"""
출력측/콘텐츠 방어 (egress guard) — 모델 출력·검색 청크에서 PII·시크릿·유출 채널을
'데이터가 밖으로 나가기 전에' 잡아 차단·마스킹한다.

왜 필요한가 (핵심 설계):
    입력 탐지(rules/detector)는 100%가 아니다. 인젝션이 통과해 모델이 유출을 시도해도,
    egress에서 개인정보·자격증명·유출 채널을 막으면 실제 '털림'을 차단한다(피해 봉쇄).
    RAG 연동 시 ①사용자 입력 ②검색 청크 ③모델 출력 — 세 지점에 가드를 건다.

입력 가드와의 차이(정직):
    입력 가드(rules.py)는 **정밀도 우선(오탐 0%)**. egress는 출력 마스킹이라 **재현율 우선** —
    애매하면 가린다(유출보다 과도 마스킹이 덜 위험). 그래서 PII는 구조 매칭 + 검증으로 잡되,
    카드번호는 Luhn으로 오탐을 줄인다.
"""

from __future__ import annotations

import re

# ── 심각도 가중치 → risk 점수 ──────────────────────────────────
SEV = {"critical": 50, "high": 35, "medium": 20, "low": 10}

# ── PII (개인정보) ─────────────────────────────────────────────
_RRN = re.compile(r"(?<!\d)\d{6}[-\s]?[1-4]\d{6}(?!\d)")                 # 주민등록번호(구조)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_KR = re.compile(r"(?<!\d)01[016-9][-\s]?\d{3,4}[-\s]?\d{4}(?!\d)")  # 휴대폰
_PHONE_LAND = re.compile(r"(?<!\d)0(?:2|[3-6]\d)[-\s]\d{3,4}[-\s]\d{4}(?!\d)")  # 유선(구분자 필수)
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?<=\d)")                  # Luhn으로 후검증

# ── 시크릿/자격증명 ────────────────────────────────────────────
_SECRETS = [
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), "critical"),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "critical"),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("gcp_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "critical"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), "critical"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "high"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("password_kv", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_\s-]?key|token|비밀\s*번호|비번|패스워드)\b\s*[:=]\s*[\"']?([^\s\"',]{4,})", ), "high"),
]

# ── 유출 채널: 마크다운 이미지/링크·외부 URL에 데이터 실어 보내기 ──
_MD_IMG_EXFIL = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&=][^)\s]*\)")
_MD_LINK_EXFIL = re.compile(r"\[[^\]]*\]\(\s*https?://[^)\s]*[?&=][^)\s]{3,}\)")
_URL_WITH_DATA = re.compile(r"https?://[^\s)]+[?&][A-Za-z0-9_\-]+=[^\s)]{6,}")


def _luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits]
    if not (13 <= len(d) <= 19):
        return False
    s, alt = 0, False
    for x in reversed(d):
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        s += x
        alt = not alt
    return s % 10 == 0


def _add(out, typ, label, sev, m):
    out.append({"type": typ, "label": label, "severity": sev,
                "start": m.start(), "end": m.end(), "match": m.group(0)})


def find(text: str, system_prompt: str | None = None) -> list[dict]:
    """텍스트에서 PII·시크릿·유출 채널·시스템 프롬프트 유출 구간을 찾는다."""
    text = text or ""
    f: list[dict] = []

    for m in _RRN.finditer(text):
        _add(f, "pii", "주민등록번호", "critical", m)
    for m in _EMAIL.finditer(text):
        _add(f, "pii", "이메일", "medium", m)
    for m in _PHONE_KR.finditer(text):
        _add(f, "pii", "휴대폰번호", "high", m)
    for m in _PHONE_LAND.finditer(text):
        _add(f, "pii", "전화번호", "medium", m)
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if _luhn_ok(digits):
            _add(f, "pii", "신용카드번호", "critical", m)

    for typ, rx, sev in _SECRETS:
        for m in rx.finditer(text):
            _add(f, "secret", typ, sev, m)

    for m in _MD_IMG_EXFIL.finditer(text):
        _add(f, "channel", "마크다운 이미지 유출", "high", m)
    for m in _MD_LINK_EXFIL.finditer(text):
        _add(f, "channel", "마크다운 링크 유출", "medium", m)
    for m in _URL_WITH_DATA.finditer(text):
        _add(f, "channel", "URL 파라미터 유출", "medium", m)

    if system_prompt:
        for seg in _leak_segments(system_prompt, text):
            f.append({"type": "leak", "label": "시스템 프롬프트 유출", "severity": "high",
                      "start": seg[0], "end": seg[1], "match": text[seg[0]:seg[1]]})

    # 겹치는 구간 정리(긴 것 우선)
    f.sort(key=lambda d: (d["start"], -(d["end"] - d["start"])))
    dedup, last_end = [], -1
    for d in f:
        if d["start"] >= last_end:
            dedup.append(d)
            last_end = d["end"]
    return dedup


def _leak_segments(system_prompt: str, text: str, min_len: int = 24) -> list[tuple[int, int]]:
    """system_prompt의 충분히 긴 조각이 출력에 '그대로' 나타나면 유출로 본다."""
    segs = []
    for line in re.split(r"[\n.。!?]", system_prompt):
        line = line.strip()
        if len(line) >= min_len:
            i = text.find(line)
            if i != -1:
                segs.append((i, i + len(line)))
    return segs


def redact(text: str, findings: list[dict] | None = None, system_prompt: str | None = None) -> str:
    """탐지 구간을 [REDACTED:라벨]로 치환한다."""
    text = text or ""
    if findings is None:
        findings = find(text, system_prompt=system_prompt)
    out, prev = [], 0
    for d in sorted(findings, key=lambda d: d["start"]):
        if d["start"] < prev:
            continue
        out.append(text[prev:d["start"]])
        out.append(f"[REDACTED:{d['label']}]")
        prev = d["end"]
    out.append(text[prev:])
    return "".join(out)


def screen(text: str, system_prompt: str | None = None) -> dict:
    """출력/콘텐츠를 종합 스크리닝한다.

    Returns:
        {
          "leak": bool,            # 유출 위험 신호가 하나라도 있으면 True
          "risk": int(0~100),
          "findings": [...],       # find() 결과
          "redacted": str,         # 마스킹된 텍스트
          "counts": {"pii","secret","channel","leak"},
        }
    """
    findings = find(text, system_prompt=system_prompt)
    risk = min(100, sum(SEV.get(d["severity"], 10) for d in findings))
    counts = {"pii": 0, "secret": 0, "channel": 0, "leak": 0}
    for d in findings:
        counts[d["type"]] = counts.get(d["type"], 0) + 1
    return {
        "leak": bool(findings),
        "risk": risk,
        "findings": findings,
        "redacted": redact(text, findings),
        "counts": counts,
    }
