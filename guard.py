"""
결정 레이어: 1차(룰) + 2차(LLM)를 합쳐 최종 판정을 낸다.

핵심 설계 = 다층 방어(defense-in-depth):
  - 룰은 빠르고 무료지만 신종·맥락형 공격을 놓친다.
  - LLM은 신종을 잡지만 느리고 비싸며 그 자체가 인젝션 표적이 된다.
  - 어느 한 레이어라도 강하게 가리키면 위로 승급(escalate)한다.
"""

from __future__ import annotations

import config
import detector
import egress
import rules

# 판정 → (이모지, 색). app.py 다크 테마와 맞춤.
DECISION_META = {
    "차단": ("🚫", "#FF5C7A"),
    "검토": ("⚠️", "#F5B14C"),
    "허용": ("✅", "#3DDC97"),
}


def evaluate(text: str, use_llm: bool = True, fail_closed: bool = False) -> dict:
    """입력을 다층으로 평가해 최종 판정을 돌려준다.

    fail_closed=False(기본): fail-open — 아무 신호도 없으면 '허용'.
    fail_closed=True: 의심스러우면 차단 원칙 — 입력을 **안전으로 확증**하지 못하면
        '허용' 대신 '검토'로 승급한다. '안전 확증'은 L2(LLM)가 실제로 돌아
        not-injection으로 분류한 경우만 인정. 즉 **L2가 없거나(키 없음) 분류 실패하면
        깨끗한 '허용'을 주지 않는다.** (대가: 정상 입력의 오탐↑ — RAG처럼 유출 비용이
        큰 곳에서 켠다. 보통 L2 키와 함께 써야 정상 트래픽이 검토로 쏠리지 않는다.)

    Returns:
        {
          "decision": "차단" | "검토" | "허용",
          "risk": int(0~100),
          "rule": <rules.scan 결과>,
          "llm": <detector.classify 결과 or None>,
          "reasons": [str ...],
          "layers": {"rule": bool, "llm": bool},
          "verified_safe": bool,   # L2가 안전으로 확증했는가(fail_closed 판단 근거)
        }
    """
    text = text or ""
    rule = rules.scan(text)

    llm = None
    if use_llm and config.has_anthropic_key():
        llm = detector.classify(text)

    llm_ok = bool(llm and llm.get("ok"))
    llm_inj = bool(llm_ok and llm.get("is_injection"))
    llm_conf = float(llm.get("confidence", 0.0)) if llm_ok else 0.0

    # 위험 점수: 두 레이어 중 큰 값 + 둘 다 가리키면 소폭 가중(상호 확증)
    llm_risk = int(round(llm_conf * 100)) if llm_inj else 0
    risk = max(rule["score"], llm_risk)
    rule_fired = rule["score"] >= rules.FLAG_THRESHOLD
    if rule_fired and llm_inj:
        risk = min(100, risk + 10)

    block = rule["score"] >= rules.BLOCK_THRESHOLD or (llm_inj and llm_conf >= 0.75)
    flag = (not block) and (
        rule_fired
        or (llm_inj and llm_conf >= 0.40)
        or rule["signals"]["zero_width"]
        or rule["signals"]["encoded"]
    )
    decision = "차단" if block else "검토" if flag else "허용"

    # 안전 확증 = L2(LLM)가 실제로 돌아 not-injection으로 분류했을 때만. (룰이 안 걸린 건
    # '아는 패턴이 없다'일 뿐 '안전 확증'이 아니다 — fail-closed의 핵심 구분.)
    verified_safe = bool(llm_ok and not llm_inj)

    reasons: list[str] = []
    for h in rule["hits"][:5]:
        reasons.append(f"[룰] {h['category']} — {h['desc']}")
    if llm_inj:
        reasons.append(
            f"[LLM] {llm.get('category', '인젝션 의심')} (확신 {llm_conf:.0%}) — {llm.get('reason', '')}"
        )
    elif llm and not llm_ok:
        reasons.append(f"[LLM] 분류 불가: {llm.get('error', '')}")

    # fail-closed: 안전으로 확증 못 한 '허용'은 '검토'로 승급(의심스러우면 통과시키지 않음)
    if fail_closed and decision == "허용" and not verified_safe:
        decision = "검토"
        reasons.append("[정책] fail-closed — 의도를 안전으로 확증하지 못해 '허용' 보류(검토)")

    if not reasons:
        reasons.append("탐지된 위험 신호 없음")

    return {
        "decision": decision,
        "risk": risk,
        "rule": rule,
        "llm": llm,
        "reasons": reasons,
        "verified_safe": verified_safe,
        "layers": {"rule": rule_fired, "llm": llm_inj},
    }


def screen_output(text: str, system_prompt: str | None = None) -> dict:
    """출력측 방어 — 모델 출력/검색 청크가 밖으로 나가기 전에 PII·시크릿·유출 채널·
    시스템 프롬프트 유출을 잡아 마스킹한다. (egress.screen 래퍼 — 입력 가드와 한 진입점)

    RAG 연동: 입력은 evaluate()로, 출력/검색 청크는 screen_output()으로 거른다.
    입력 탐지가 100%가 아니어도 여기서 실제 유출을 봉쇄한다(피해 차단).
    """
    return egress.screen(text, system_prompt=system_prompt)
