"""
입력 정규화 / 역난독화 — 시그니처 매칭 '전에' 변형 공격을 평문으로 되돌린다.

룰 레이어가 리트스피크·글자 띄우기·제로폭·동형문자·인코딩(base64/hex/ROT13/URL) 같은
'난독화' 우회에 뚫리는 걸 막기 위한 모듈. 원문을 여러 방식으로 역난독화한 '뷰'를 만들어,
rules.scan이 원문 + 이 뷰들 모두에 시그니처를 돌리게 한다.

한계(정직): 이건 '난독화'만 되돌린다. **다른 언어(일본어 등)나 의미 패러프레이즈는
못 막는다** — 그건 번역/의미의 문제라 2차 LLM 레이어나 시그니처 확장이 필요하다.
"""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from urllib.parse import unquote

# 보이지 않는/제어 문자(제로폭·방향제어·소프트하이픈 등) → 제거
_INVISIBLE = re.compile(
    "[​‌‍⁠﻿­᠎‎‏"
    "‪‫‬‭‮⁡⁢⁣⁤]"
)

# 동형문자(혼동문자) → 라틴. 공격에 흔한 키릴/그리스 위주.
_HOMOGLYPH = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ո": "n", "𝗶": "i",
    "ο": "o", "ι": "i", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "ѵ": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
}

# 리트스피크 → 알파벳
_LEET = str.maketrans(
    {"1": "i", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t",
     "@": "a", "$": "s", "8": "b", "!": "i", "|": "l", "€": "e"}
)

# 단어 '안'의 단일문자+단일공백 분산만 합침(2칸 이상 공백 = 단어 경계로 보존)
_DESPACE_RUN = re.compile(r"(?:(?<=\s)|^)((?:[^\W_] ){2,}[^\W_])(?=\s|$)")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def _printable(s: str) -> bool:
    if not s or len(s) < 6:
        return False
    ok = sum(c.isprintable() or c.isspace() for c in s)
    return ok / len(s) > 0.85


def strip_invisible(s: str) -> str:
    return _INVISIBLE.sub("", s)


def fold_homoglyph(s: str) -> str:
    return "".join(_HOMOGLYPH.get(c, c) for c in s)


def despace(s: str) -> str:
    """'i g n o r e   a l l' → 'ignore all'. 2칸 이상 공백을 단어 경계로 보존한다."""
    out = []
    for part in re.split(r"\s{2,}", s):
        out.append(_DESPACE_RUN.sub(lambda m: m.group(1).replace(" ", ""), part))
    return " ".join(out)


def _decoded(text: str) -> list[str]:
    """base64 / hex / ROT13 / URL 디코드한 사람이 읽을 수 있는 문자열들."""
    out: list[str] = []

    def add(s: str):
        if s and s != text and _printable(s) and s not in out:
            out.append(s)

    for m in _B64.finditer(text):
        tok = m.group(0)
        try:
            add(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8"))
        except Exception:
            pass
    for m in _HEX.finditer(text):
        try:
            add(bytes.fromhex(m.group(0)).decode("utf-8"))
        except Exception:
            pass
    try:
        add(codecs.decode(text, "rot_13"))
    except Exception:
        pass
    try:
        add(unquote(text))
    except Exception:
        pass
    return out


def canonical(text: str) -> str:
    """NFKC + 보이지 않는 문자 제거 + 동형문자 폴딩 (기본 정규화 1패스)."""
    return fold_homoglyph(strip_invisible(unicodedata.normalize("NFKC", text or "")))


def deobfuscated_views(text: str) -> list[tuple[str, str]]:
    """원문을 제외한 역난독화 후보를 (방법라벨, 텍스트)로 반환(중복 제거)."""
    text = text or ""
    base = canonical(text)
    pairs: list[tuple[str, str]] = []
    seen: set[str] = {text}

    def add(label: str, s: str):
        if s and s not in seen:
            seen.add(s)
            pairs.append((label, s))

    add("정규화(유니코드/동형문자/제로폭)", base)
    add("공백분산 복원", despace(base))
    add("리트스피크 복원", base.translate(_LEET))
    add("공백+리트 복원", despace(base).translate(_LEET))
    for d in _decoded(text):
        add("인코딩 디코드", d)
        # 디코드 결과도 한 번 더 역난독화
        db = canonical(d)
        add("디코드+정규화", db)
        add("디코드+리트", db.translate(_LEET))
    return pairs
