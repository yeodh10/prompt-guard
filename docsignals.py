"""
문서 모드 전용 신호: RAG 청크, 웹페이지, 메일, 공문서처럼 믿을 수 없는 글에서만 본다.

사람이 챗봇에 치는 말은 rules.py가 본다. 여기서는 글 안에 심어 둔, 글을 읽는 쪽을 조종하려는 문장을 본다.
가중치 50 이상은 하나만 맞아도 막는 확실한 신호고, 그보다 낮으면 사람이 보도록 검토로 넘기는 넓은 신호다.

막는 것: 프롬프트를 지칭한 명령, 호출하는 쪽이 넘긴 출력 형식의 필드 이름, 역할 표시 위조,
기계를 불러 결과를 바꾸라는 지시, 앞의 지시를 따르지 말라는 글, 숨긴 글.
검토로 넘기는 것: 프롬프트 같은 낱말만 나옴, 기계를 부르지만 내용이 평범함, 문서를 읽는 쪽에게 하는 말.
교육 공고에 '프롬프트'가 나오고, 민원 안내에 '바랍니다'가 나온다. 낱말 하나로 막으면 오탐만 는다.

공격 문장을 줄바꿈이나 표 칸으로 쪼개도 이어서 본다. normalize.views()의 겹친 글이 줄을 합친 글이고,
규칙의 건너뛰기([^.。!?]{0,40})도 줄바꿈을 넘는다. 모든 반복은 횟수를 묶었다.
"""

from __future__ import annotations

import functools
import re
import time
import unicodedata

import normalize

C_DOCUMENT = "문서 속 지시"
BLOCK_WEIGHT = 50
MAX_FIELDS = 64

# 글을 읽는 기계를 뜻하는 말. 앞뒤가 영어 글자면 메일(mail), 태국(thai)의 일부다
READER = r"(?:(?<![a-z])ai(?![a-z])|a\.i\.|인공\s{0,2}지능|챗\s{0,2}봇|언어\s{0,2}모델|판독\s{0,2}(?:기|엔진|모델|프로그램|시스템)|ocr(?:\s{0,2}엔진)?|llm|gpt|claude|클로드|어시스턴트|assistant|추출기|파서|분류기|자동\s{0,2}(?:처리|추출|분석)\s{0,2}(?:기|도구|시스템|프로그램|모델))"
# 사람이나 물건일 수도 있는 말까지 넓힌 것. '로봇', '건설기계'는 글을 읽는 기계가 아니다
READER_WIDE = rf"(?:{READER}|모델|에이전트|agent|(?<!로)봇|(?<!건설)기계)"
CALL = r"\s{0,2}(?:은|는|께|에게|님|들|,|:)"
# 명령형 끝말. '바랍니다'가 있어 혼자서는 신호가 못 된다. 앞의 글자 검사는 시간을 줄인다
ORDER = r"(?=[하해어아시세주바요할따pms])(?:하라|해라|어라|아라|시오|세요|주시기|주길|바랍니다|바람|요망|할\s{0,2}것|따를\s{0,2}것|please|must|should)"
WRITE = r"(?:표시|기록|분류|입력|적어|적으|적는|적습|추출|반환|출력|포함|제외|삭제|추가|등록|넣|처리|mark|record|flag|classify|return|output|include|exclude|delete|add)"
# '지시 문서', '지시 문건'은 공사 감독에서 흔하다
PROMPT = r"(?:프롬프트|시스템\s{0,2}메시지|시스템\s{0,2}지시|system\s{0,2}prompt|system\s{0,2}(?:message|instruction)s?|지시\s{0,2}문(?![서건])|명령\s{0,2}문(?![서건]))"
SPILL = r"(?:출력|적어|적으|옮겨|복사|공개|알려|보여|인용|반복|되풀이|무시|따르|따라|지우|지워|삭제|바꾸|바꿔|덮어)"
# '이 문서를 처리하는'까지. '읽어 보시고', '읽으신 분'은 사람에게 하는 말이다
READS = r"(?:이|본|해당)\s{0,2}(?:문서|글|문장|고시|공고|페이지|메일|이메일|기사|리뷰|댓글)\s{0,2}(?:를|을)\s{0,2}(?:읽(?!어\s{0,2}보시|으시|으신)|처리|분석|요약|추출|판독)"
PREV = r"(?:위|앞|앞선|이전|상기|종전)"

# (정규식, 가중치, 설명)
SIGNATURES: list[tuple[str, int, str]] = [
    # 프롬프트를 지칭한 명령
    (rf"(?:{PROMPT}|prompt)\s{{0,2}}(?:(?:전문|원문|내용|전체|문구)\s{{0,2}}(?:을|를|은|는|도|만)?|을|를|은|는|도|만)[^.。!?]{{0,30}}{SPILL}[^.。!?]{{0,12}}{ORDER}", 60, "프롬프트를 지칭한 명령"),
    (PROMPT, 30, "모델을 가리키는 말"),
    # 역할 표시 위조. rules.py의 위조 규칙에 더해 문서를 감싼 구분자와 표시 붙은 턴을 본다
    (r"<\|[^|\n]{1,30}\|>|<\s{0,2}/?\s{0,2}instructions?\s{0,2}>", 60, "역할 표시 위조"),
    (r"<<<[^<>\n]{0,30}(?:원문|문서|자료|고시|공고|untrusted|input|document)[^<>\n]{0,30}>>>|</\s{0,2}(?:documents?|context|retrieved|search_results?|untrusted[a-z_]{0,12})\s{0,2}>", 60, "문서 구분자 위조"),
    (r"(?:[#*※\[•>]|(?:^|\s)[가-힣0-9]{1,2}[.)])[ \t]{0,3}\*{0,2}(?:system|assistant|developer)[ \t]{0,3}\*{0,2}[ \t]{0,3}[:\]]", 60, "표시 붙은 가짜 턴"),
    (r"(?m)^[ \t]{0,3}(?:user|human|사용자)[ \t]{0,3}:[^\n]{0,300}\n[ \t]{0,3}(?:assistant|model|ai|bot|어시스턴트|모델)[ \t]{0,3}:", 60, "대화 턴 위조"),
    (r"(?m)^[ \t]{0,3}(?:시스템|어시스턴트)[ \t]{0,3}:", 20, "가짜 턴 의심(한국어)"),
    # 숨긴 글과 유출 통로
    (r"<!--|<script|display\s{0,2}:\s{0,2}none|visibility\s{0,2}:\s{0,2}hidden|font-size\s{0,2}:\s{0,2}0(?![.\d])", 60, "숨긴 글"),
    (r"!\[[^\]\n]{0,80}\]\(\s{0,2}https?://[^)\s?&=]{0,300}[?&=]", 55, "그림 주소로 나가는 유출 통로"),
    (r"<img\s|!\[[^\]\n]{0,80}\]\(\s{0,2}http", 30, "글에 박힌 그림 주소"),
    # 읽는 쪽에게 하는 지시
    (rf"{READER}{CALL}[^.。!?]{{0,40}}{WRITE}[^.。!?]{{0,12}}{ORDER}", 55, "문서를 읽는 기계에게 하는 지시"),
    (rf"{READS}\S{{0,8}}\s{{0,2}}(?:자동\s{{0,2}})?(?:(?<![a-z])ai(?![a-z])|인공\s{{0,2}}지능|모델|프로그램|시스템|도구|엔진|판독기|기계|봇|에이전트)[^.。!?]{{0,60}}{ORDER}", 55, "문서를 읽는 기계에게 하는 지시"),
    (r"note\s{1,2}(?:to|for)\s{1,2}(?:the\s{1,2}|any\s{1,2}|all\s{1,2}){0,2}(?:reader\s{1,2})?(?:ai|assistants?|models?|llms?|parsers?|agents?|bots?)(?![a-z])", 55, "문서를 읽는 기계에게 하는 지시"),
    (rf"{READER_WIDE}{CALL}[^.。!?]{{0,40}}{ORDER}", 30, "기계를 부르는 말"),
    (rf"{READS}[^.。!?]{{0,60}}{ORDER}", 30, "문서를 읽는 쪽에게 하는 말"),
    (r"(?:when|while|before)\s{1,2}(?:you\s{1,2}(?:are\s{1,2})?)?(?:summariz|process|read|analyz|extract|index)\w{0,6}\s{1,2}this\s{1,2}(?:document|text|page|notice|email|message|file|article)", 30, "문서를 읽는 쪽에게 하는 말"),
    # 지시 바꾸기
    (r"(?:새|새로운|다음|아래)\s{0,2}(?:지시|지침|명령|임무|역할)\s{0,2}(?:사항)?\s{0,2}[:\-]|(?:새|새로운)\s{0,2}규칙\s{0,2}[:\-]|new\s{1,2}(?:system\s{1,2})?instructions?\s{0,2}:", 55, "새 지시를 내리는 글"),
    (rf"{PREV}\S{{0,3}}\s{{0,2}}(?:모든\s{{0,2}})?(?:내용|지시|지침|규칙|안내|설명)\S{{0,3}}\s{{0,2}}(?:는|은|을|를)?\s{{0,2}}(?:참고\s{{0,2}}하지|따르지|고려\s{{0,2}}하지|신경\s{{0,2}}쓰지|상관\s{{0,2}}하지)\s{{0,2}}(?:마|말|않아도)", 55, "앞의 지시를 따르지 말라는 글"),
    (rf"{PREV}\S{{0,3}}\s{{0,2}}(?:지시|명령|규칙)\s{{0,2}}(?:을|를|들|다|싹|전부|모두)?\s{{0,2}}.{{0,6}}(?:지우|지워|삭제|제거|없애|날려|초기화|리셋|클리어)", 30, "앞의 지시를 지우라는 글"),
    (r"새\s{0,2}기준\s{0,2}:", 30, "새 기준을 내리는 글"),
]


def _compile(pat: str) -> re.Pattern:
    return re.compile(unicodedata.normalize("NFKC", pat), re.IGNORECASE | re.DOTALL)


_COMPILED = [(_compile(pat), w, desc, not normalize.HANGUL.search(pat)) for pat, w, desc in SIGNATURES]


def _field_pattern(name: str) -> str | None:
    """필드 이름 하나를 정규식으로. 낱말 사이 구분자가 달라도(record_type, record-type, recordType) 같은 이름이다.

    낱말 하나짜리 이름은 평범한 글에도 나오므로(summary) 필드처럼 쓴 곳만 본다: 따옴표 키, 한글 조사가 바로 붙은 곳.
    """
    parts = re.findall(r"[A-Za-z][a-z]*|[0-9]+|[가-힣]+", name)
    if not parts or len("".join(parts)) < 3:
        return None
    joined = r"[\s_-]{0,3}".join(re.escape(p) for p in parts)
    if len(parts) > 1:
        return rf"(?<![a-z0-9_]){joined}(?![a-z0-9_])"
    return rf"[\"']{joined}[\"']\s{{0,2}}:|(?<![a-z0-9_]){joined}(?:에는|에|은|는|을|를|칸|란)"


@functools.lru_cache(maxsize=32)
def _field_rules(names: tuple[str, ...]) -> list[tuple[re.Pattern, int, str, bool]]:
    found = [p for p in (_field_pattern(n) for n in names) if p]
    if not found:
        return []
    return [(_compile("|".join(found)), 60, "출력 형식의 필드 이름", False)]


def field_rules(schema_fields) -> list[tuple[re.Pattern, int, str, bool]]:
    if not schema_fields:
        return []
    names = (schema_fields,) if isinstance(schema_fields, str) else tuple(schema_fields)
    if len(names) > MAX_FIELDS:
        raise ValueError(f"schema_fields는 {MAX_FIELDS}개까지만 받는다")
    return _field_rules(names)


def scan(views: list[normalize.View], deadline: float, schema_fields=None) -> list[dict]:
    """맞은 신호 목록. 시간 상한을 넘기면 거기까지 찾은 것을 돌려준다. 시간 판단은 부른 쪽이 한다.

    같은 설명은 가중치가 높은 쪽 하나만 남긴다. 호출한 쪽은 restored로 복원 글에서 맞았는지 안다.
    """
    best: dict[str, dict] = {}
    for rx, w, desc, no_hangul in _COMPILED + field_rules(schema_fields):
        if w <= best.get(desc, {"weight": 0})["weight"]:
            continue
        for n, (label, view, short) in enumerate(views):
            if time.thread_time() > deadline:
                return list(best.values())
            m = rx.search(short if no_hangul else view)
            if m:
                m = rx.search(view) or m
                s, e = max(0, m.start() - 12), min(len(view), m.end() + 12)
                best[desc] = {"category": C_DOCUMENT, "weight": w, "rule": desc, "restored": n > 0,
                              "desc": f"{desc} (난독 우회: {label})" if n else desc,
                              "snippet": view[s:e].replace("\n", " ").strip()}
                break
    return list(best.values())
