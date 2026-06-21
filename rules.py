"""
1차 방어: 룰/휴리스틱 레이어 (빠르고 무료, 오프라인 동작).

알려진 프롬프트 인젝션·탈옥 시그니처를 가중치로 매칭해 위험 점수를 낸다.
LLM 호출 없이 동작하므로 배포 데모에서 키 없이도 공격이 실제로 잡힌다.
인코딩 우회(base64)는 디코딩 후 재검사하고, 제로폭 문자 등 난독화도 신호로 잡는다.

이 레이어 '하나'로는 부족하다(신종·우회 공격을 놓침). 그래서 detector.py(LLM)와
guard.py(결정)로 다층 방어를 구성한다 — 이게 핵심 설계 의도다.
"""

from __future__ import annotations

import base64
import re

import normalize

# ── 시그니처 카테고리(한글 라벨) ───────────────────────────────
C_OVERRIDE = "지시 무시/덮어쓰기"
C_LEAK = "시스템 프롬프트 탈취"
C_ROLEPLAY = "역할극 탈옥"
C_REFUSAL = "거부 억제"
C_DELIM = "구분자 위조"
C_EXFIL = "권한 우회/유출 유도"
C_ENCODE = "인코딩/난독 우회"
C_URGENCY = "긴급·압박(사회공학)"
C_INDIRECT = "간접 주입(RAG/문서 내 지시)"

# (정규식, 카테고리, 가중치, 설명). 대소문자 무시. 한·영 동시 대응.
_RAW_SIGNATURES: list[tuple[str, str, int, str]] = [
    # 지시 무시 — 가장 전형적인 인젝션
    (r"ignore\s+(all\s+|the\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|messages?)", C_OVERRIDE, 50, "이전 지시 무시 요구"),
    (r"disregard\s+(the\s+|all\s+|everything\s+)?(that\s+was\s+|stated\s+|said\s+|written\s+)?(above|previous|prior|earlier|before|instructions?|rules?)", C_OVERRIDE, 45, "이전 지시 무효화"),
    (r"forget\s+(everything|all\s+|the\s+|your\s+)?(instructions?|rules?|guidelines?|directives?|prompts?)", C_OVERRIDE, 40, "지시 망각 요구"),
    (r"(pay\s+no\s+attention\s+to|do\s+not\s+follow|stop\s+following)\s+(the\s+)?(above|previous|earlier|prior|instructions?|rules?)", C_OVERRIDE, 45, "이전 지시 따르지 말 것 요구"),
    (r"(이\s*전|앞|위)(의|에)?\s*(지시|명령|규칙|프롬프트|내용).{0,8}(무시|잊|무효)", C_OVERRIDE, 50, "이전 지시 무시(한국어)"),
    # 삭제형 덮어쓰기: '(이전/위) 지시·프롬프트를 지우고…' — 무시 대신 '삭제' 동사. 접두(이전/위/앞)는
    # 선택적(없어도 매칭) — '프롬프트 다 지우고'처럼 접두 없는 변형도 잡는다. 명사는 지시/명령/규칙/
    # 프롬프트로 한정(대화/기록 제외 — '이전 대화 기록 삭제'는 정상 기능 문의라 오탐 위험).
    (r"(이\s*전|위|앞|기존|현재)?\s*(의|에)?\s*(지시|명령|규칙|시스템\s*프롬프트|프롬프트)\s*(을|를|들|다|싹|전부|모두)?\s*.{0,6}(지우|지워|삭제|제거|없애|날려|초기화|리셋|클리어)", C_OVERRIDE, 45, "지시/프롬프트 삭제 요구(한국어)"),
    (r"무시(하고|해)\s*(새로운|아래|다음)", C_OVERRIDE, 35, "무시하고 새 지시 따르기"),
    (r"override\s+(your|the|all|system)\s+(instructions?|rules?|settings?|prompt)", C_OVERRIDE, 45, "설정 덮어쓰기"),
    # 시스템 프롬프트 탈취
    (r"(reveal|show|print|repeat|output|display)\s+(me\s+)?(your\s+)?(system\s+prompt|initial\s+(instructions?|prompt)|the\s+(words?|text)\s+above)", C_LEAK, 45, "시스템 프롬프트 출력 요구"),
    (r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt|guidelines?)", C_LEAK, 35, "초기 지시 캐묻기"),
    (r"(시스템\s*프롬프트|초기\s*(지시|설정|프롬프트)).{0,25}(출력|보여|알려|그대로|반복|복사)", C_LEAK, 45, "시스템 프롬프트 탈취(한국어)"),
    (r"위(의)?\s*(모든\s*|전체\s*)?(내용|지시|문장|것|메시지|텍스트).{0,25}(그대로|출력|보여|반복|복사)", C_LEAK, 40, "상단 내용 그대로 출력 요구(한국어)"),
    (r"한\s*글자도\s*(빼지|빠짐없이|틀리지)", C_LEAK, 25, "원문 그대로 추출 요구"),
    (r"repeat\s+(the\s+)?(words?|everything)\s+above\s+(verbatim|exactly)?", C_LEAK, 40, "상단 내용 그대로 반복"),
    # 역할극 탈옥
    (r"\b(DAN|do\s+anything\s+now)\b", C_ROLEPLAY, 45, "DAN 탈옥 페르소나"),
    (r"(developer|god|admin|root)\s+mode", C_ROLEPLAY, 40, "특권 모드 위장"),
    (r"you\s+are\s+(now\s+)?(an?\s+)?(unrestricted|uncensored|unfiltered|jailbroken|amoral)", C_ROLEPLAY, 50, "무제한 페르소나 부여"),
    (r"(pretend|act\s+as|imagine|roleplay)\s+(you\s+(are|have)|to\s+be|that)", C_ROLEPLAY, 30, "역할극 유도"),
    (r"(너는?\s*이제|지금부터\s*너는?|당신은\s*이제).{0,18}(제한\s*없|무엇이든|검열\s*없|규칙\s*없)", C_ROLEPLAY, 50, "무제한 역할 부여(한국어)"),
    (r"(제한\s*없는|검열\s*없는|규칙\s*없는)\s*(ai|모델|챗봇|assistant)", C_ROLEPLAY, 40, "무제한 AI 요구(한국어)"),
    # 거부 억제
    (r"(do\s+not|don'?t|never)\s+(refuse|decline|warn|say\s+no|apologize)", C_REFUSAL, 30, "거부/경고 억제"),
    (r"without\s+(any\s+)?(warning|disclaimer|refusal|restriction|filter)", C_REFUSAL, 30, "경고·필터 제거 요구"),
    (r"(거부|거절|경고)\s*(하지\s*마|없이|금지)", C_REFUSAL, 30, "거부 억제(한국어)"),
    (r"no\s+matter\s+what|at\s+all\s+costs|무조건|반드시\s*해", C_REFUSAL, 15, "무조건 수행 압박"),
    # 구분자/역할 마크업 위조
    (r"</?(system|assistant|user|im_start|im_end)\s*\|?>?", C_DELIM, 40, "역할 태그 위조"),
    (r"<\|(im_start|im_end|system|endoftext)\|>", C_DELIM, 45, "특수 토큰 위조"),
    (r"(^|\n)\s*(###|\[)?\s*(system|assistant)\s*[:\]]", C_DELIM, 30, "가짜 시스템/어시스턴트 턴"),
    (r"\[/?INST\]|\[/?SYS\]", C_DELIM, 40, "명령 구분자 위조"),
    # 권한 우회/유출 유도
    (r"\b(bypass|circumvent|evade|disable)\s+(the\s+)?(filter|safety|guardrail|moderation|restriction|security)", C_EXFIL, 40, "안전장치 우회 요구"),
    (r"(우회|뚫|무력화).{0,8}(필터|안전|보안|제한|가드)", C_EXFIL, 40, "안전장치 우회(한국어)"),
    (r"\b(exfiltrate|leak|dump)\s+(the\s+)?(data|secrets?|keys?|credentials?)", C_EXFIL, 35, "데이터 유출 유도"),
    # 자격증명 탈취(영어) — reveal/send/… + password/credentials/api key 등. show/give는
    # 일반 UI 문맥('show password' 토글) 오탐 우려로 제외, 유출성 동사만 채택.
    (r"\b(reveal|send|hand|fetch|expose|leak|dump|steal|exfiltrate|give|tell|show)\s+(me\s+|us\s+)?(all\s+|the\s+|your\s+|every\s+|any\s+|stored\s+|saved\s+)*(passwords?|credentials?|api[\s_-]*keys?|secret[\s_-]*keys?|access[\s_-]*tokens?|private[\s_-]*keys?|login\s+credentials?)\b", C_EXFIL, 50, "자격증명/키 탈취 요구(영어)"),
    # 자격증명 탈취(한국어) — 두 갈래로 정밀하게:
    #  (a) 유출성 동사(가져와/넘겨/유출/탈취…): 넓은 명사(아이디/계정 포함) + 임의 간격 허용.
    (r"(아이디|비밀\s*번호|비번|패스워드|password|로그인\s*정보|인증\s*정보|자격\s*증명|계정\s*정보|크리덴셜|시크릿|액세스\s*키|api\s*키|개인\s*키).{0,12}(가져와|가져오|가져가|내놔|내놓|넘겨|빼내|빼돌|유출|훔쳐|탈취|보내라|전송해|넘겨라)", C_EXFIL, 50, "계정·비밀번호 등 자격증명 탈취(한국어)"),
    #  (b) 약한 동사(알려/보여/말해…): '비밀번호 정책 알려줘'(정상)와 구분하려고 ① 비밀 등급 명사만
    #      (아이디/계정 단독 제외) ② 사이에 조사·공백만 허용(내용어가 끼면 불매칭). '비밀번호 알려줘'는
    #      값 자체를 직접 요구 → 공격. '비밀번호 정책/방법/재설정 알려줘'는 사이 내용어로 불매칭.
    (r"(비밀\s*번호|비번|패스워드|password|인증\s*정보|자격\s*증명|크리덴셜|시크릿|액세스\s*키|api\s*키|개인\s*키|로그인\s*정보)\s*(을|를|좀|다|들|이랑|랑|와|과|는|도|만|네|의|\s)*(알려|보여|말해|불러|가르쳐|읊어|뭐야|뭐임|뭔데)", C_EXFIL, 50, "비밀번호 등 비밀정보 직접 요구(한국어)"),
    # ── 간접 주입(RAG/도구 출력 등 '데이터' 안에 심은 AI 대상 지시) ──
    # 검색결과·문서·웹페이지·이메일 본문이 LLM에 주입될 때, 그 안에 박아둔 'AI를 향한 명령'을 잡는다.
    # (이전 지시 무시/유출 시그니처는 데이터 안에 있어도 그대로 발화하므로 RAG 청크 검사에 바로 쓰인다.)
    (r"(if|when)\s+you('?re|\s+are)\s+(an?\s+)?(a\.?i\.?|ai|llm|assistant|language\s+model|chatbot)\b", C_INDIRECT, 35, "데이터 속 AI 조건부 호출(영어)"),
    (r"\b(ai|assistant|llm|chatbot)\s+(that\s+is\s+|who\s+is\s+)?reading\s+this\b", C_INDIRECT, 40, "이 글을 읽는 AI 호출(영어)"),
    (r"as\s+an?\s+(ai|language\s+model|assistant)\b[^.\n]{0,30}(you\s+(must|should|will|need|have\s+to)|ignore|reveal|send|delete|do\s+the\s+following)", C_INDIRECT, 40, "AI 사칭 지시 삽입(영어)"),
    (r"(이|본|위)\s*(문서|글|문장|텍스트|내용|페이지|메일|이메일|리뷰|댓글|기사)[^.\n]{0,12}(읽는|보는|처리|요약)[^.\n]{0,8}(ai|인공지능|모델|어시스턴트|봇|에이전트)", C_INDIRECT, 40, "이 문서를 읽는 AI 대상 지시(한국어)"),
    (r"(ai|인공지능|모델|어시스턴트|챗봇|에이전트)\s*(에게|한테|야|님|는|은)[^.\n]{0,20}(무시하|복종|유출|탈취|넘겨|전송해|삭제해|실행해|따르라)", C_INDIRECT, 40, "AI 호명 후 명령 삽입(한국어)"),
    # ── 유출 채널: 마크다운 이미지/링크·외부 URL로 데이터 빼돌리기(RAG 데이터 탈출) ──
    (r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&=][^)\s]*\)", C_EXFIL, 40, "마크다운 이미지 URL로 데이터 유출 시도"),
    (r"\b(send|post|upload|exfiltrate|forward|leak)\b[^.\n]{0,40}\bto\b\s+https?://", C_EXFIL, 40, "외부 URL로 전송/유출 지시(영어)"),
    # ── 다국어 인젝션(일본어·중국어) — L1 다국어 확장 ──
    (r"(以前|これまで|上記|先程|前)\s*の?\s*(指示|命令|ルール|プロンプト|指図)[^。\n]{0,8}(無視|忘れ|破棄)", C_OVERRIDE, 50, "이전 지시 무시(일본어)"),
    (r"(システムプロンプト|初期指示|最初の指示)[^。\n]{0,12}(表示|教え|出力|見せ|繰り返)", C_LEAK, 45, "시스템 프롬프트 탈취(일본어)"),
    (r"(パスワード|認証情報|資格情報|アカウント情報)[^。\n]{0,10}(教え|見せ|渡し|送っ|出力)", C_EXFIL, 50, "자격증명 탈취(일본어)"),
    (r"忽略[^。\n]{0,6}(之前|上述|先前|以上|前面)[^。\n]{0,4}(指令|指示|提示|规则|命令)", C_OVERRIDE, 50, "이전 지시 무시(중국어)"),
    (r"(显示|输出|告诉我|重复|泄露)[^。\n]{0,8}(系统提示|系统提示词|初始指令|系统指令)", C_LEAK, 45, "시스템 프롬프트 탈취(중국어)"),
    (r"(密码|账号|账户|凭据|密钥|令牌)[^。\n]{0,6}(告诉|给我|发给|泄露|发送)", C_EXFIL, 50, "자격증명 탈취(중국어)"),
    # 긴급/압박(보조 신호 — 단독으론 약하게)
    (r"\b(urgent|immediately|right\s+now|asap)\b|긴급|당장|즉시", C_URGENCY, 10, "긴급성 압박"),
]

_SIGNATURES = [
    (re.compile(pat, re.IGNORECASE), cat, w, desc) for pat, cat, w, desc in _RAW_SIGNATURES
]

# 제로폭/보이지 않는 문자(난독화에 자주 쓰임)
_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿­]")
# base64로 의심되는 긴 토큰
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# 점수 → 레벨 임계값
FLAG_THRESHOLD = 20
BLOCK_THRESHOLD = 50


def _snippet(text: str, m: re.Match) -> str:
    s = max(0, m.start() - 12)
    e = min(len(text), m.end() + 12)
    frag = text[s:e].replace("\n", " ").strip()
    return ("…" if s > 0 else "") + frag + ("…" if e < len(text) else "")


def _decode_b64_candidates(text: str) -> list[str]:
    """base64로 보이는 토큰을 디코딩해 사람이 읽을 수 있는 문자열만 돌려준다."""
    out = []
    for m in _B64.finditer(text):
        token = m.group(0)
        if len(token) < 20:
            continue
        try:
            pad = token + "=" * (-len(token) % 4)
            dec = base64.b64decode(pad, validate=False)
            txt = dec.decode("utf-8", errors="strict")
        except Exception:
            continue
        printable = sum(c.isprintable() or c.isspace() for c in txt)
        if txt and printable / max(1, len(txt)) > 0.85 and len(txt) >= 6:
            out.append(txt)
    return out


def scan(text: str) -> dict:
    """입력 텍스트를 룰 레이어로 검사한다.

    Returns:
        {
          "score": int(0~100),
          "level": "안전" | "의심" | "위험",
          "hits": [{"category","weight","desc","snippet"} ...],
          "signals": {"zero_width": bool, "encoded": bool, "length": int},
        }
    """
    text = text or ""
    hits: list[dict] = []
    seen_cat_desc = set()

    def add(category, weight, desc, snippet):
        key = (category, desc)
        if key in seen_cat_desc:
            return
        seen_cat_desc.add(key)
        hits.append({"category": category, "weight": weight, "desc": desc, "snippet": snippet})

    # 1) 평문 시그니처
    for rx, cat, w, desc in _SIGNATURES:
        m = rx.search(text)
        if m:
            add(cat, w, desc, _snippet(text, m))

    # 2) 역난독화: 정규화·리트스피크·공백복원·인코딩 디코드 뷰에서 시그니처 재검사
    #    (평문에서 이미 잡힌 시그니처는 건너뛰어 이중 가산을 막는다)
    raw_keys = set(seen_cat_desc)
    deobf_added: set = set()
    encoded = False
    views = normalize.deobfuscated_views(text)
    for rx, cat, w, desc in _SIGNATURES:
        if cat not in (C_OVERRIDE, C_LEAK, C_ROLEPLAY, C_EXFIL, C_REFUSAL, C_INDIRECT):
            continue
        if (cat, desc) in raw_keys or (cat, desc) in deobf_added:
            continue
        for label, view in views:
            if rx.search(view):
                encoded = True
                deobf_added.add((cat, desc))
                add(cat, w, f"{desc} (난독 우회: {label})",
                    view[:48] + ("…" if len(view) > 48 else ""))
                break

    # 3) 제로폭/보이지 않는 문자(그 자체로 난독화 시도 신호)
    zero_width = bool(_ZERO_WIDTH.search(text))
    if zero_width:
        add(C_ENCODE, 25, "보이지 않는 제로폭 문자(난독화)", "(zero-width chars)")

    score = min(100, sum(h["weight"] for h in hits))
    level = "위험" if score >= BLOCK_THRESHOLD else "의심" if score >= FLAG_THRESHOLD else "안전"

    # 위험도순 정렬
    hits.sort(key=lambda h: -h["weight"])
    return {
        "score": score,
        "level": level,
        "hits": hits,
        "signals": {"zero_width": zero_width, "encoded": encoded, "length": len(text)},
    }


def _try_decode(token: str) -> str | None:
    """base64 토큰을 사람이 읽을 수 있는 문자열로 디코딩(아니면 None)."""
    if len(token) < 20:
        return None
    try:
        pad = token + "=" * (-len(token) % 4)
        txt = base64.b64decode(pad, validate=False).decode("utf-8", errors="strict")
    except Exception:
        return None
    if not txt or len(txt) < 6:
        return None
    printable = sum(c.isprintable() or c.isspace() for c in txt)
    return txt if printable / max(1, len(txt)) > 0.85 else None


def _decoded_is_attack(dec: str) -> bool:
    return any(
        cat in (C_OVERRIDE, C_LEAK, C_ROLEPLAY, C_EXFIL) and rx.search(dec)
        for rx, cat, _w, _d in _SIGNATURES
    )


def detect_spans(text: str) -> list[dict]:
    """탐지된 악성 '구간'을 원문 문자 오프셋으로 돌려준다(인라인 하이라이트용).

    겹치는 구간은 병합하고, 그 구간 색은 가장 높은 가중치 시그니처의 카테고리를 따른다.
    Returns: [{"start": int, "end": int, "category": str, "weight": int} ...] (start 오름차순)
    """
    text = text or ""
    raw: list[tuple[int, int, str, int]] = []

    for rx, cat, w, _desc in _SIGNATURES:
        for m in rx.finditer(text):
            if m.end() > m.start():
                raw.append((m.start(), m.end(), cat, w))

    # base64로 숨긴 공격: 원문에서 그 토큰 위치를 하이라이트
    for m in _B64.finditer(text):
        dec = _try_decode(m.group(0))
        if dec and _decoded_is_attack(dec):
            raw.append((m.start(), m.end(), C_ENCODE, 60))

    # 제로폭 문자 각각도 구간으로
    for m in _ZERO_WIDTH.finditer(text):
        raw.append((m.start(), m.end(), C_ENCODE, 25))

    if not raw:
        return []

    raw.sort()
    merged: list[list] = []
    for s, e, cat, w in raw:
        if merged and s <= merged[-1][1]:
            if w > merged[-1][3]:
                merged[-1][2], merged[-1][3] = cat, w
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e, cat, w])
    return [{"start": s, "end": e, "category": c, "weight": w} for s, e, c, w in merged]
