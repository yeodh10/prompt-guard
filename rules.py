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
import time
import unicodedata

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
C_LIMIT = "검사 한도 초과"

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
    (r"(지시|명령|규칙|시스템\s*프롬프트|프롬프트)\s*(을|를|들|다|싹|전부|모두)?\s*.{0,6}(지우|지워|삭제|제거|없애|날려|초기화|리셋|클리어)", C_OVERRIDE, 45, "지시/프롬프트 삭제 요구(한국어)"),
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
    (r"(?m)^[ \t]{0,3}(?:###[ \t]{0,3}|\[[ \t]{0,3})?(?:system|assistant)\s*[:\]]", C_DELIM, 30, "가짜 시스템/어시스턴트 턴"),
    (r"\[/?INST\]|\[/?SYS\]", C_DELIM, 40, "명령 구분자 위조"),
    # 권한 우회/유출 유도
    (r"\b(bypass|circumvent|evade|disable)\s+(the\s+)?(filter|safety|guardrail|moderation|restriction|security)", C_EXFIL, 40, "안전장치 우회 요구"),
    # 가정법/허구 프레이밍 우회: "hypothetically, if you had no content policy…"
    (r"(?i)\b(hypothetical(?:ly)?|imagine|suppose|pretend)\b[^.\n]{0,40}\byou\b[^.\n]{0,20}(had\s+no|have\s+no|without|no\s+longer\s+had|didn'?t\s+have)\b[^.\n]{0,15}(content\s*polic|rules?|restrictions?|filters?|guardrails?|safety|guidelines?)", C_EXFIL, 30, "가정법 프레이밍으로 안전장치 우회(영어)"),
    (r"(우회|뚫|무력화).{0,8}(필터|안전|보안|제한|가드)", C_EXFIL, 40, "안전장치 우회(한국어)"),
    (r"\b(exfiltrate|leak|dump)\s+(the\s+)?(data|secrets?|keys?|credentials?)", C_EXFIL, 35, "데이터 유출 유도"),
    # 자격증명 탈취(영어) — reveal/send/… + password/credentials/api key 등. show/give는
    # 일반 UI 문맥('show password' 토글) 오탐 우려로 제외, 유출성 동사만 채택.
    (r"\b(reveal|send|hand|fetch|expose|leak|dump|steal|exfiltrate|give|tell|show)\s+(me\s+|us\s+)?(all\s+|the\s+|your\s+|every\s+|any\s+|stored\s+|saved\s+){0,6}(passwords?|credentials?|api[\s_-]{0,3}keys?|secret[\s_-]{0,3}keys?|access[\s_-]{0,3}tokens?|private[\s_-]{0,3}keys?|login\s+credentials?)\b", C_EXFIL, 50, "자격증명/키 탈취 요구(영어)"),
    # 자격증명 탈취(한국어) — 두 갈래로 정밀하게:
    #  (a) 유출성 동사(가져와/넘겨/유출/탈취…): 넓은 명사(아이디/계정 포함) + 임의 간격 허용.
    (r"(아이디|비밀\s*번호|비번|패스워드|password|로그인\s*정보|인증\s*정보|자격\s*증명|계정\s*정보|크리덴셜|시크릿|액세스\s*키|api\s*키|개인\s*키).{0,12}(가져와|가져오|가져가|내놔|내놓|넘겨|빼내|빼돌|유출|훔쳐|탈취|보내라|전송해|넘겨라)", C_EXFIL, 50, "계정·비밀번호 등 자격증명 탈취(한국어)"),
    #  (b) 약한 동사(알려/보여/말해…): '비밀번호 정책 알려줘'(정상)와 구분하려고 ① 비밀 등급 명사만
    #      (아이디/계정 단독 제외) ② 사이에 조사·공백만 허용(내용어가 끼면 불매칭). '비밀번호 알려줘'는
    #      값 자체를 직접 요구 → 공격. '비밀번호 정책/방법/재설정 알려줘'는 사이 내용어로 불매칭.
    (r"(비밀\s*번호|비번|패스워드|password|인증\s*정보|자격\s*증명|크리덴셜|시크릿|액세스\s*키|api\s*키|개인\s*키|로그인\s*정보)(?:을|를|좀|다|들|이랑|랑|와|과|는|도|만|네|의|\s){0,8}(알려|보여|말해|불러|가르쳐|읊어|뭐야|뭐임|뭔데)", C_EXFIL, 50, "비밀번호 등 비밀정보 직접 요구(한국어)"),
    # ── 간접 주입(RAG/도구 출력 등 '데이터' 안에 심은 AI 대상 지시) ──
    # 검색결과·문서·웹페이지·이메일 본문이 LLM에 주입될 때, 그 안에 박아둔 'AI를 향한 명령'을 잡는다.
    # (이전 지시 무시/유출 시그니처는 데이터 안에 있어도 그대로 발화하므로 RAG 청크 검사에 바로 쓰인다.)
    (r"(if|when)\s+you('?re|\s+are)\s+(an?\s+)?(a\.?i\.?|ai|llm|assistant|language\s+model|chatbot)\b", C_INDIRECT, 35, "데이터 속 AI 조건부 호출(영어)"),
    (r"\b(ai|assistant|llm|chatbot)\s+(that\s+is\s+|who\s+is\s+)?reading\s+this\b", C_INDIRECT, 40, "이 글을 읽는 AI 호출(영어)"),
    (r"as\s+an?\s+(ai|language\s+model|assistant)\b[^.\n]{0,30}(you\s+(must|should|will|need|have\s+to)|ignore|reveal|send|delete|do\s+the\s+following)", C_INDIRECT, 40, "AI 사칭 지시 삽입(영어)"),
    (r"(이|본|위)\s*(문서|글|문장|텍스트|내용|페이지|메일|이메일|리뷰|댓글|기사)[^.\n]{0,12}(읽는|보는|처리|요약)[^.\n]{0,8}(ai|인공지능|모델|어시스턴트|봇|에이전트)", C_INDIRECT, 40, "이 문서를 읽는 AI 대상 지시(한국어)"),
    (r"(ai|인공지능|모델|어시스턴트|챗봇|에이전트)\s*(에게|한테|야|님|는|은)[^.\n]{0,20}(무시하|복종|유출|탈취|넘겨|전송해|삭제해|실행해|따르라)", C_INDIRECT, 40, "AI 호명 후 명령 삽입(한국어)"),
    # ── 유출 채널: 마크다운 이미지/링크·외부 URL로 데이터 빼돌리기(RAG 데이터 탈출) ──
    (r"!\[[^\]\n]{0,80}\]\(\s*https?://[^)\s?&=]{0,300}[?&=][^)\s]{0,300}\)", C_EXFIL, 40, "마크다운 이미지 URL로 데이터 유출 시도"),
    (r"\b(send|post|upload|exfiltrate|forward|leak)\b[^.\n]{0,40}\bto\b\s+https?://", C_EXFIL, 40, "외부 URL로 전송/유출 지시(영어)"),
    # ── 다국어 인젝션(일본어·중국어) — L1 다국어 확장 ──
    (r"(以前|これまで|上記|先程|前)\s*の?\s*(指示|命令|ルール|プロンプト|指図)[^。\n]{0,8}(無視|忘れ|破棄)", C_OVERRIDE, 50, "이전 지시 무시(일본어)"),
    (r"(システムプロンプト|初期指示|最初の指示)[^。\n]{0,12}(表示|教え|出力|見せ|繰り返)", C_LEAK, 45, "시스템 프롬프트 탈취(일본어)"),
    (r"(パスワード|認証情報|資格情報|アカウント情報)[^。\n]{0,10}(教え|見せ|渡し|送っ|出力)", C_EXFIL, 50, "자격증명 탈취(일본어)"),
    (r"忽略[^。\n]{0,6}(之前|上述|先前|以上|前面)[^。\n]{0,4}(指令|指示|提示|规则|命令)", C_OVERRIDE, 50, "이전 지시 무시(중국어)"),
    (r"(显示|输出|告诉我|重复|泄露)[^。\n]{0,8}(系统提示|系统提示词|初始指令|系统指令)", C_LEAK, 45, "시스템 프롬프트 탈취(중국어)"),
    (r"(密码|账号|账户|凭据|密钥|令牌)[^。\n]{0,6}(告诉|给我|发给|泄露|发送)", C_EXFIL, 50, "자격증명 탈취(중국어)"),

    # ── 데이터베이스/대량 데이터 유출 (한/영) — '사용자 DB 다 가져와'류 ──
    (r"(데이터\s*베이스|디비|사용자\s*데이터|회원\s*정보|고객\s*정보|개인\s*정보|사용자\s*정보|전체\s*데이터|모든\s*데이터|db)[^.\n]{0,12}(가져와|가져가|넘겨|빼내|빼돌|유출|탈취|내놔|덤프|보내라|전송해|다\s*줘)", C_EXFIL, 50, "사용자 데이터/DB 유출(한국어)"),
    (r"(?i)\b(dump|exfiltrate|leak|steal|extract|download|send|give|fetch|scrape)\b[^.\n]{0,20}(the\s+|entire\s+|all\s+|whole\s+|user\s+|customer\s+|our\s+){0,4}(database|databases|user\s+data|customer\s+data|user\s+records|user\s+table|records|pii)\b", C_EXFIL, 45, "사용자 데이터/DB 유출(영어)"),
    # 탈옥(jailbreak) 자체를 키워드로
    (r"(?i)\bjail\s*break(ing|s)?\b|탈옥", C_ROLEPLAY, 40, "탈옥(jailbreak) 명시"),

    # ── 다국어 인젝션(주요 언어) — 각 언어: 지시무시 / 시스템프롬프트 탈취 / 자격증명·DB 유출 ──
    # 스페인어(ES)
    (r"(?i)(ignora|olvida|descarta|desatiende)\w{0,8}\s+(todas\s+)?(las\s+)?(instrucciones|reglas|[óo]rdenes)\s+(anteriores|previas)", C_OVERRIDE, 50, "이전 지시 무시(스페인어)"),
    (r"(?i)(revela|muestra|imprime|repite|ens[eé][ñn]a)\w{0,8}\s+(tu\s+|el\s+|las\s+)?(prompt\s+del\s+sistema|instrucciones\s+iniciales|system\s+prompt|indicaciones\s+del\s+sistema)", C_LEAK, 45, "시스템 프롬프트 탈취(스페인어)"),
    (r"(?i)(dame|env[ií]a\w{0,8}|revela|filtra|mu[eé]strame|comparte)\s+(la\s+|las\s+|el\s+|todas?\s+)?(contrase[ñn]as?|credenciales|clave|base\s+de\s+datos|datos\s+de\s+usuarios?)", C_EXFIL, 50, "자격증명/DB 유출(스페인어)"),
    # 프랑스어(FR)
    (r"(?i)(ignore[rz]?|oublie[rz]?|n[ée]glige[rz]?)\s+(toutes\s+)?(les\s+)?(instructions|r[èe]gles|consignes)\s+(pr[ée]c[ée]dentes|ant[ée]rieures)", C_OVERRIDE, 50, "이전 지시 무시(프랑스어)"),
    (r"(?i)(r[ée]v[èe]le[rz]?|montre[rz]?|affiche[rz]?)\s+(-?moi\s+)?(ton\s+|le\s+|tes\s+)?(prompt\s+syst[èe]me|instructions\s+initiales|invite\s+syst[èe]me)", C_LEAK, 45, "시스템 프롬프트 탈취(프랑스어)"),
    (r"(?i)(donne[rz]?-?moi|envoie[rz]?|r[ée]v[èe]le[rz]?|divulgue[rz]?)\s+(le\s+|la\s+|les\s+|tous?\s+)?(mots?\s+de\s+passe|identifiants|base\s+de\s+donn[ée]es|donn[ée]es\s+(des\s+)?utilisateurs)", C_EXFIL, 50, "자격증명/DB 유출(프랑스어)"),
    # 독일어(DE)
    (r"(?i)(ignoriere|vergiss|missachte)\s+(alle\s+)?(vorherigen|bisherigen|obigen)\s+(anweisungen|regeln|befehle)", C_OVERRIDE, 50, "이전 지시 무시(독일어)"),
    (r"(?i)(zeige?|verrate|gib\s+aus|wiederhole)\s+(mir\s+)?(deinen?\s+)?(system[-\s]?prompt|systemanweisung(en)?|urspr[üu]nglichen\s+anweisungen)", C_LEAK, 45, "시스템 프롬프트 탈취(독일어)"),
    (r"(?i)(gib\s+mir|sende|zeige?|verrate|leake)\s+(?:(?:alle|die|das|den|dein|deine|meine?|mir)\s+){0,2}(passw[öo]rter|passwort|zugangsdaten|anmeldedaten|datenbank|benutzerdaten)", C_EXFIL, 50, "자격증명/DB 유출(독일어)"),
    # 포르투갈어(PT)
    (r"(?i)(ignore|esque[çc]a|desconsidere)\s+(todas\s+)?(as\s+)?(instru[çc][õo]es|regras|ordens)\s+(anteriores|pr[ée]vias)", C_OVERRIDE, 50, "이전 지시 무시(포르투갈어)"),
    (r"(?i)(revele|mostre|imprima|repita)\s+(seu\s+|o\s+|as\s+)?(prompt\s+do\s+sistema|instru[çc][õo]es\s+iniciais)", C_LEAK, 45, "시스템 프롬프트 탈취(포르투갈어)"),
    (r"(?i)(me\s+d[êe]|envie|revele|vaze|mostre)\s+(as\s+|todas?\s+|a\s+|o\s+)?(senhas?|credenciais|banco\s+de\s+dados|dados\s+dos?\s+usu[áa]rios)", C_EXFIL, 50, "자격증명/DB 유출(포르투갈어)"),
    # 인도네시아어(ID)
    (r"(?i)(abaikan|lupakan)\s+(semua\s+)?(instruksi|aturan|perintah)\s+(sebelumnya|di\s+atas)", C_OVERRIDE, 50, "이전 지시 무시(인니어)"),
    (r"(?i)(beri(kan)?|kirim|tunjukkan|bocorkan)\s+(saya\s+)?(semua\s+)?(kata\s+sandi|password|kredensial|basis\s+data|data\s+pengguna)", C_EXFIL, 50, "자격증명/DB 유출(인니어)"),
    # 러시아어(RU)
    (r"(игнорируй|забудь|отмени|проигнорируй)\s+(все\s+)?(предыдущие|прошлые|вышеуказанные)\s+(инструкции|правила|указания)", C_OVERRIDE, 50, "이전 지시 무시(러시아어)"),
    (r"(покажи|раскрой|выведи|повтори)\s+(свой\s+|мне\s+)?(системный\s+промпт|системную\s+подсказку|исходные\s+инструкции)", C_LEAK, 45, "시스템 프롬프트 탈취(러시아어)"),
    (r"(дай|отправь|покажи|слей|раскрой)\s+(мне\s+)?(все\s+)?(парол\w{1,8}|учетные\s+данные|базу\s+данных|данные\s+пользователей)", C_EXFIL, 50, "자격증명/DB 유출(러시아어)"),
    # 아랍어(AR) — 근사치(형태 변화 많음)
    (r"(تجاهل|انسى|تخط[ىي]?)\s+(كل\s+)?(التعليمات|القواعد|الأوامر)", C_OVERRIDE, 50, "이전 지시 무시(아랍어)"),
    (r"(أعطني|أرسل|اكشف|سرب|أظهر)\s+(كل\s+)?(كلم[ةا]ت?\s+المرور|بيانات\s+الاعتماد|قاعدة\s+البيانات|بيانات\s+المستخدم)", C_EXFIL, 50, "자격증명/DB 유출(아랍어)"),
    # 힌디어(HI) — 근사치
    (r"(पिछले|सभी|ऊपर).{0,6}(निर्देश|नियम|आदेश).{0,6}(अनदेखा|भूल|नज़रअंदाज़|अनदेखी)", C_OVERRIDE, 50, "이전 지시 무시(힌디어)"),
    (r"(पासवर्ड|यूज़र\s*डेटा|डेटाबेस|क्रेडेंशियल|उपयोगकर्ता\s*डेटा).{0,10}(दे\s*दो|बताओ|भेजो|दिखाओ|लीक)", C_EXFIL, 50, "자격증명/DB 유출(힌디어)"),
    # 긴급/압박(보조 신호 — 단독으론 약하게)
    (r"\b(urgent|immediately|right\s+now|asap)\b|긴급|당장|즉시", C_URGENCY, 10, "긴급성 압박"),
]



def _tight(pat: str) -> str:
    """공백 반복에 상한을 건다. 검사하는 글은 공백 덩어리를 2칸으로 줄여 두어 3이면 넉넉하다."""
    return pat.replace(r"\s+", r"\s{1,3}").replace(r"\s*", r"\s{0,3}")


# 어떤 규칙에도 무제한 반복이 없다. tests/test_redos.py가 컴파일된 정규식을 뜯어 확인한다.
# 끝의 참거짓은 규칙에 한글이 없는가다. 그런 규칙은 한글 덩어리를 줄인 글을 봐서 긴 한글 글에서 빠르다.
# 입력은 NFKC를 거쳐 오므로 규칙도 같은 형태로 맞춘다
_SIGNATURES = [
    (re.compile(unicodedata.normalize("NFKC", _tight(pat)), re.IGNORECASE), cat, w, desc, not normalize.HANGUL.search(pat))
    for pat, cat, w, desc in _RAW_SIGNATURES
]

# base64로 의심되는 긴 토큰
_B64 = re.compile(r"[A-Za-z0-9+/]{16,4096}={0,2}")

# 점수 → 레벨 임계값
FLAG_THRESHOLD = 20
BLOCK_THRESHOLD = 50

# 입력 길이 상한. 넘으면 읽지 않고 막는다
MAX_INPUT = 20_000
# 검사 시간 상한(CPU 초). 넘기면 끝까지 못 본 글이므로 막는다. 벽시계로 재면 PC가 바쁠 때 판정이 달라진다.
# 규칙은 반복 횟수를 묶어 여기까지 갈 일이 드물다
TIME_LIMIT = 1.2


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


def _stopped(text: str, desc: str, signal: str) -> dict:
    """끝까지 보지 못한 글의 결과. 안전을 확인하지 못했으므로 막는다."""
    signals = {"zero_width": False, "encoded": False, "length": len(text), "oversize": False, "timed_out": False}
    signals[signal] = True
    hit = {"category": C_LIMIT, "weight": 100, "rule": desc, "desc": desc, "snippet": ""}
    return {"score": 100, "level": "위험", "hits": [hit], "signals": signals}


def scan(text: str) -> dict:
    """입력 텍스트를 룰 레이어로 검사한다.

    normalize.views()가 만든 뷰 목록에 시그니처를 건다. 첫 뷰(기본 글)에서 맞으면 평문 적중,
    그 뒤 뷰에서 맞으면 난독 우회로 본다. 규칙 하나는 한 번만 센다.
    길이 상한을 넘은 글과 시간 상한 안에 다 보지 못한 글은 막는다. signals의 oversize, timed_out으로 구분한다.

    Returns:
        {
          "score": int(0~100),
          "level": "안전" | "의심" | "위험",
          "hits": [{"category","weight","desc","rule","snippet"} ...],
          "signals": {"zero_width": bool, "encoded": bool, "length": int, "oversize": bool, "timed_out": bool},
        }
    """
    text = text or ""
    base = normalize.prepare(text) if len(text) <= MAX_INPUT else None
    # NFKC로 18배까지 늘어나는 글자가 있어 늘어난 길이도 잰다
    if base is None or len(base) > MAX_INPUT:
        return _stopped(text, f"입력이 {MAX_INPUT}자를 넘는다", "oversize")
    deadline = time.thread_time() + TIME_LIMIT
    views = normalize.views(base)
    hits: list[dict] = []
    encoded = False

    for rx, cat, w, desc, no_hangul in _SIGNATURES:
        # '해당 장소'가 붙으면 '당장'이 되듯, 낱말 하나짜리 약한 신호는 복원 글에서 보지 않는다
        for n, (label, view, short) in enumerate(views[:1] if cat == C_URGENCY else views):
            if time.thread_time() > deadline:
                return _stopped(text, "검사가 시간 안에 끝나지 않았다", "timed_out")
            m = rx.search(short if no_hangul else view)
            if m:
                m = rx.search(view) or m
                encoded = encoded or n > 0
                hits.append({"category": cat, "weight": w, "rule": desc, "snippet": _snippet(m.string, m),
                             "desc": f"{desc} (난독 우회: {label})" if n else desc})
                break

    # 숨은 문자는 그 자체로 난독화 시도 신호다
    hidden = bool(normalize.hidden_chars(text))
    if hidden:
        hits.append({"category": C_ENCODE, "weight": 25, "rule": "숨은 문자", "desc": "보이지 않는 제로폭 문자(난독화)",
                     "snippet": "(zero-width chars)"})

    score = min(100, sum(h["weight"] for h in hits))
    level = "위험" if score >= BLOCK_THRESHOLD else "의심" if score >= FLAG_THRESHOLD else "안전"

    # 위험도순 정렬
    hits.sort(key=lambda h: -h["weight"])
    return {
        "score": score,
        "level": level,
        "hits": hits,
        "signals": {"zero_width": hidden, "encoded": encoded, "length": len(text), "oversize": False, "timed_out": False},
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
        for rx, cat, _w, _d, _h in _SIGNATURES
    )


def detect_spans(text: str) -> list[dict]:
    """탐지된 악성 '구간'을 원문 문자 오프셋으로 돌려준다(인라인 하이라이트용).

    겹치는 구간은 병합하고, 그 구간 색은 가장 높은 가중치 시그니처의 카테고리를 따른다.
    글이 길면 앞부분만 보고, 시간 상한에 닿으면 찾은 데까지 돌려준다. 하이라이트는 판정에 쓰지 않는다.
    Returns: [{"start": int, "end": int, "category": str, "weight": int} ...] (start 오름차순)
    """
    text = (text or "")[:MAX_INPUT]
    raw: list[tuple[int, int, str, int]] = []
    deadline = time.thread_time() + TIME_LIMIT

    for rx, cat, w, _desc, _h in _SIGNATURES:
        if time.thread_time() > deadline:
            break
        for m in rx.finditer(text):
            if m.end() > m.start():
                raw.append((m.start(), m.end(), cat, w))

    # base64로 숨긴 공격: 원문에서 그 토큰 위치를 하이라이트
    for m in _B64.finditer(text):
        if time.thread_time() > deadline:
            break
        dec = _try_decode(m.group(0))
        if dec and _decoded_is_attack(dec):
            raw.append((m.start(), m.end(), C_ENCODE, 60))

    # 숨은 문자 각각도 구간으로
    hidden = normalize.hidden_chars(text)
    if hidden:
        for m in re.finditer("[" + re.escape("".join(hidden)) + "]", text):
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
