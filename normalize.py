"""
입력 정규화와 복원: 시그니처 매칭 '전에' 변형 공격을 평문으로 되돌린다.

룰 레이어가 리트스피크, 글자 띄우기, 숨은 문자, 동형문자, 인코딩(base64, hex, ROT13, URL 등) 같은
'난독화' 우회에 뚫리는 걸 막기 위한 모듈이다. 입구는 하나다. prepare()로 기본 글을 만들고
views()로 복원한 글 목록을 만든다. rules.py는 이 목록에 시그니처를 건다.

복원은 앞 단계의 결과 위에 겹쳐서 쌓는다. 그래야 유사 문자와 띄어쓰기를 함께 쓴 글도 풀린다.
뷰 수는 정해져 있고 디코드 결과는 한 덩어리로 합친다. 토큰 수만큼 뷰가 늘면 검사 시간이 입력에 끌려간다.

한계(정직): 이건 '난독화'만 되돌린다. 다른 언어나 의미 패러프레이즈는 못 막는다.
그건 번역과 의미의 문제라 2차 LLM 레이어나 뒤 단계 방어의 몫이다.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from typing import NamedTuple
from urllib.parse import unquote

# 범주 Cf가 아닌데 화면에 안 보이는 글자: 채움 문자, 결합용 빈 글자, 몽골 변이 선택자, 점자 빈칸
_FILLER = set("͏ᅟᅠ឴឵᠋᠌᠍᠏⠀ㅤﾠ")
# 형식 문자, 제어 문자, 외톨이 서로게이트, 사용자 영역, 미지정 글자
_HIDDEN_CATEGORIES = {"Cf", "Cc", "Cs", "Co", "Cn"}
# 제어 문자지만 공백으로 쓰는 것
_LAYOUT = set("\t\n\r\x0b\x0c\x1c\x1d\x1e\x1f\x85")


def _is_hidden(c: str) -> bool:
    if c in _LAYOUT:
        return False
    # 새 그림 문자는 파이썬의 유니코드 표보다 먼저 나와 미지정(Cn)으로 보인다
    if "\U0001f000" <= c <= "\U0001faff":
        return False
    # 변이 선택자는 범주가 Mn이라 범위로 본다
    return c in _FILLER or unicodedata.category(c) in _HIDDEN_CATEGORIES or "︀" <= c <= "️" or "\U000e0100" <= c <= "\U000e01ef"


def hidden_chars(text: str) -> set[str]:
    """글에 든 숨은 문자들. 파일 맨 앞의 BOM은 편집기가 붙인 것이라 뺀다."""
    return {c for c in set(text.removeprefix("﻿")) if _is_hidden(c)}


def strip_invisible(s: str) -> str:
    return s.translate({ord(c): None for c in set(s) if _is_hidden(c)})


# 호환 자모로 풀어 쓴 글을 음절로 잇는다. 'ㅇㅣㅈㅓㄴ' -> '이전'
_LEAD = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"
_VOWEL = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
_TAIL = "ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ"
_JAMO_RUN = re.compile(r"[ㄱ-ㅣ](?: ?[ㄱ-ㅣ]){1,4096}")


def _syllables(run: str) -> str:
    t, out, i = run.replace(" ", ""), [], 0
    while i < len(t):
        if t[i] in _LEAD and t[i + 1:i + 2] and t[i + 1] in _VOWEL:
            tail, after = t[i + 2:i + 3], t[i + 3:i + 4]
            has_tail = bool(tail) and tail in _TAIL and not (after and after in _VOWEL)
            out.append(chr(0xAC00 + _LEAD.index(t[i]) * 588 + _VOWEL.index(t[i + 1]) * 28 + (_TAIL.index(tail) + 1 if has_tail else 0)))
            i += 3 if has_tail else 2
        else:
            out.append(t[i])
            i += 1
    return "".join(out)


def join_jamo(s: str) -> str:
    return _JAMO_RUN.sub(lambda m: _syllables(m.group(0)), s)


_RUN = re.compile(r"\s{3,}")  # 공백 한 종류만 보는 반복이라 되돌아갈 일이 없다


def squeeze(s: str) -> str:
    """빈 줄을 없애고 공백 덩어리를 2칸으로 줄인다. 정규식 시간이 공백 길이에 끌려가지 않게 하는 첫 단계다.

    2칸은 남긴다. despace()가 그것을 단어 경계로 쓴다.
    """
    return "\n".join(line for line in (_RUN.sub("  ", raw.strip()) for raw in s.splitlines()) if line)


def prepare(text: str) -> str:
    """기본 글을 만든다: 숨은 문자 제거, 자모 잇기, NFKC, 공백 줄이기. 모든 뷰가 여기서 시작한다."""
    return squeeze(unicodedata.normalize("NFKC", join_jamo(strip_invisible(text or ""))))


# 동형문자(혼동문자) → 라틴. 키릴, 그리스, 소형 대문자 위주. 한자는 난독화에 쓰기 쉬운 낱말만
_HOMOGLYPH = str.maketrans({
    # 키릴 소문자, 대문자
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ո": "n", "һ": "h", "ӏ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ѕ": "S", "Ј": "J",
    # 그리스 소문자, 대문자
    "ο": "o", "ι": "i", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "ѵ": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
    # 소형 대문자와 점 없는 i, 수학 글자
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f", "ɢ": "g",
    "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n",
    "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ʏ": "y", "ᴢ": "z", "ı": "i", "𝗶": "i",
    # 한자로 바꿔 쓴 지시, 무시
    "指": "지", "示": "시", "無": "무", "視": "시",
})


def fold_homoglyph(s: str) -> str:
    return s.translate(_HOMOGLYPH)


def canonical(text: str) -> str:
    """NFKC + 보이지 않는 문자 제거 + 동형문자 폴딩. 공백은 그대로 둔다."""
    return fold_homoglyph(strip_invisible(unicodedata.normalize("NFKC", text or "")))


# 표 구분자: 막대, 탭, 상자 그리기 글자. HTML 태그는 글자 사이에 끼워 시그니처를 깨는 데 쓰인다.
# 역할 태그는 지우지 않는다. 유사 문자로 쓴 <ѕystem>은 여기서야 <system>이 된다
_TABLE = re.compile("[|¦\t─-╿]{1,4096}")
_TAG = re.compile(r"</?(?!\s{0,3}/?\s{0,3}(?:system|assistant|user|developer|human|im_start|im_end)\b)[a-z][^<>\n]{0,60}>", re.IGNORECASE)


def strip_layout(s: str) -> str:
    return _TABLE.sub(" ", _TAG.sub("", s))


def columns(s: str) -> str:
    """표를 세로로 읽는다. 공격 문장을 행마다 한 조각씩 나눠 넣은 글을 잡는다."""
    rows = [[c.strip() for c in re.split(r"[|\t]", line.strip().strip("|"))] for line in s.split("\n") if len(re.findall(r"[|\t]", line)) >= 2]
    if len(rows) < 2:
        return ""
    cols: dict[int, list[str]] = {}
    for row in rows:
        for i, cell in enumerate(row):
            cols.setdefault(i, []).append(cell)
    return " ".join(" ".join(cols[i]) for i in sorted(cols))


# 단어 '안'의 단일문자+단일공백 분산만 합침(2칸 이상 공백 = 단어 경계로 보존)
_DESPACE_RUN = re.compile(r"(?:(?<=\s)|^)((?:[^\W_] ){2,400}[^\W_])(?=\s|$)")


def despace(s: str) -> str:
    """'i g n o r e   a l l' → 'ignore all'. 2칸 이상 공백을 단어 경계로 보존한다."""
    out = []
    for part in re.split(r"\s{2,}", s):
        out.append(_DESPACE_RUN.sub(lambda m: m.group(1).replace(" ", ""), part))
    return " ".join(out)


# 리트스피크 → 알파벳. 숫자만 있는 낱말과 m2 같은 두 글자 낱말은 그대로 둔다 (뷰만 늘어난다)
_LEET = str.maketrans(
    {"1": "i", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t",
     "@": "a", "$": "s", "8": "b", "!": "i", "€": "e"}
)
_TOKEN = re.compile(r"[A-Za-z0-9@$!€_]{1,256}")


def unleet(s: str) -> str:
    return _TOKEN.sub(lambda m: m.group(0).translate(_LEET) if len(m.group(0)) >= 3 and any(c.isalpha() for c in m.group(0)) else m.group(0), s)


# 막대를 l로 쓴 리트스피크. 표 구분자와 겹쳐서 글자에 붙은 것만 본다. 'a||', 'fi|ter'
_PIPE_L = re.compile(r"(?<=[A-Za-z0-9])\|{1,2}(?=[A-Za-z0-9\s]|$)")


def unleet_pipe(s: str) -> str:
    return _PIPE_L.sub(lambda m: "l" * len(m.group(0)), s)


# 글자 사이에 낀 문장 부호. '지.시', '앞-선', '프*롬'. 뒤가 띄어쓰기면 문장 끝이라 남긴다
_MARK = re.compile("(?<=[가-힣a-zA-Z0-9])[.\\-_·・•∙⋅ᆞ*~^'`\",‐-―]{1,3}(?=[가-힣a-zA-Z])")


def strip_marks(s: str) -> str:
    return _MARK.sub("", s)


# CJK(한글, 한자, 가나) 글자 '사이'에만 낀 공백. '비 밀 번 호'식 띄어쓰기 난독화 복원용.
# 한쪽이라도 비CJK(라틴/숫자)면 손대지 않아 일반 문장의 단어 경계는 보존된다.
_CJK = "가-힣ᄀ-ᇿ㄰-㆏一-鿿぀-ヿㇰ-ㇿ"
_CJK_SPACE = re.compile(rf"(?<=[{_CJK}])[ \t　]{{1,8}}(?=[{_CJK}])")


def collapse_cjk_spaces(s: str) -> str:
    """'비 밀 번 호' → '비밀번호'. CJK 글자 사이의 공백만 제거(라틴/숫자 경계는 보존).

    한국어는 본래 단어를 띄어 쓰므로 일반 문장도 일부 붙지만('다음 주'→'다음주'),
    이 함수의 결과는 시그니처 '재검사용 뷰'로만 쓰여 원문 가독성에는 영향이 없다.
    despace()가 못 잡는 '부분 띄어쓰기'(예: '이 전 프롬프트')를 보완한다.
    """
    return _CJK_SPACE.sub("", s or "")


# 줄바꿈이 끼어든 영어 단어. 'ig\nnore', 'instruc-\ntions'. 낱말이 맞는지는 몰라 뷰로만 쓴다
_WRAPPED = re.compile(r"(?<=[A-Za-z_])-?\n(?=[A-Za-z_])")
# base64 토큰. 표준과 URL 안전 글자를 다 받고, 한 칸씩 띄운 조각은 붙여서도 푼다
_B64 = re.compile(r"[A-Za-z0-9+/_-]{4,4096}={0,2}(?:[ \n][A-Za-z0-9+/_-]{4,4096}={0,2}){0,256}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}[ :-]?){8,4096}")
_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_LATIN = re.compile(r"[A-Za-z][A-Za-z ]{5,4096}")
_DECODED_CAP = 50_000


def _unbase64(token: str) -> str:
    """깨진 바이트가 있어도 읽히는 부분은 살린다. 끝에 1바이트 덧붙이는 것만으로 디코드가 꺼지면 안 된다."""
    s = token.rstrip("=").replace("-", "+").replace("_", "/")
    s = s[: len(s) - (len(s) % 4 == 1)]
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return ""


def _decode_once(s: str) -> str:
    """base64, 16진수, ROT13, URL, HTML 엔터티, 이스케이프를 푼 글을 한 덩어리로 돌려준다.

    사람이 읽을 만한 글인지는 따로 재지 않는다. 그 비율은 쓰레기 바이트를 섞으면 꺼진다.
    """
    parts: list[str] = []
    for m in _B64.finditer(s):
        tokens = m.group(0).split()
        if len(tokens) > 1:
            parts.append(_unbase64("".join(tokens)))
        parts += [_unbase64(t) for t in tokens if len(t) >= 16]
    for m in _HEX.finditer(s):
        parts.append(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", m.group(0))).decode("utf-8", "ignore"))
    latin = _LATIN.findall(s)
    if latin:
        parts.append(codecs.encode(" ".join(latin), "rot_13"))
    plain = _ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), s) if "\\" in s else s
    plain = html.unescape(plain) if "&" in plain else plain
    plain = unquote(plain, errors="ignore") if "%" in plain else plain
    if plain != s:
        parts.append(plain)
    return "\n".join(p for p in parts if len(p) >= 6)


def decoded(base: str) -> list[str]:
    """두 겹까지 푼다. 한 겹마다 prepare를 거치므로 푼 글의 숨은 문자와 전각 글자도 지워진다."""
    out: list[str] = []
    cur = base
    for _ in range(2):
        cur = prepare(_decode_once(cur)[:_DECODED_CAP])[:_DECODED_CAP]
        if not cur:
            break
        out.append(cur)
    return out


class View(NamedTuple):
    label: str
    text: str
    short: str  # 한글이 없는 규칙이 보는 글. 한글 덩어리를 한 글자로 줄였다


HANGUL = re.compile(r"[가-힣]{1,4096}")


def _one_line(s: str) -> str:
    return s.replace("\n", " ")


def _stacked(lines: str) -> str:
    """유사 문자와 표를 지운 글 위에 글자 띄우기, 리트스피크, 문장 부호, 한글 띄어쓰기 복원을 겹친다."""
    return collapse_cjk_spaces(strip_marks(unleet(despace(_one_line(lines)))))


def views(base: str) -> list[View]:
    """prepare()를 거친 글에서 뷰 목록을 만든다. 첫 뷰는 기본 글이고, 뷰 수는 정해져 있다.

    전부 겹친 글 하나를 기본으로 본다. 단계마다 뷰를 두면 긴 글에서 시간만 몇 배로 든다.
    겹친 글은 줄을 합친 글이기도 하다. 공격 문장을 줄바꿈으로 쪼개도 여기서 이어진다.
    """
    lines = strip_layout(fold_homoglyph(base))
    pairs = [
        ("정규화", base),
        ("유사 문자와 표 구분자", lines),
        ("겹쳐 복원(공백, 리트, 문장 부호, CJK 공백분산)", _stacked(lines)),
    ]
    piped = unleet_pipe(base)
    if piped != base:
        pairs.append(("리트스피크 복원(막대)", unleet(despace(_one_line(fold_homoglyph(piped))))))
    wrapped = _WRAPPED.sub("", lines)
    if wrapped != lines:
        pairs.append(("줄바꿈 낀 단어", unleet(_one_line(wrapped))))
    pairs.append(("표 세로 읽기", strip_layout(columns(base))))
    for layer in decoded(base):
        pairs += [("인코딩 디코드", layer), ("디코드 뒤 복원", _stacked(strip_layout(fold_homoglyph(layer))))]
    # 줄바꿈만 다른 글은 규칙이 똑같이 본다
    seen: set[str] = set()
    out = []
    for label, text in pairs:
        key = _one_line(text)
        if key and key not in seen:
            seen.add(key)
            out.append(View(label, text, HANGUL.sub("가", text)))
    return out


def deobfuscated_views(text: str) -> list[tuple[str, str]]:
    """원문을 제외한 역난독화 후보를 (방법라벨, 텍스트)로 반환(중복 제거)."""
    text = text or ""
    return [(v.label, v.text) for v in views(prepare(text)) if v.text != text]
