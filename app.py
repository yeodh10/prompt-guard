"""
프롬프트 인젝션 가드 — SOC 콘솔 (Streamlit).

생성형 AI 보안관제센터(SOC) 콘솔 컨셉의 입력 방어 데모.
다층 방어(룰 + LLM)로 사용자 입력의 인젝션·탈옥 시도를 실시간 탐지·차단한다.
룰 레이어는 Anthropic 키 없이도 동작하므로, 배포 데모에서 공격이 실제로 막히는 장면을 보여 준다.

UI 컨셉 = "soc-console" (+ 심사 graft 병합):
  - 모노스페이스 터미널 감성, 상태 LED, 회전 레이더 로고, 좌→우 스캔 스윕
  - 인터셉션 레일: 입력 → ①룰 게이트 → ②LLM 게이트 → LLM 도달 / 차단 (어디서 막혔나)
  - 위협 미터: SVG 원형 게이지 + 임계 틱(FLAG/BLOCK 상수 연동) 세그먼트 미터 + 차단 시 BLOCKED 고무도장
  - 라이브 스캔 로그: guard.evaluate 결과를 0.16s 간격으로 한 줄씩 순차 점등(실제 hits/signals/llm 값에서만 분기)
  - 원문 인라인 증거: rules.detect_spans()로 악성 구간을 원문 위 <mark>로 번호 배지와 함께 하이라이트
  - SIEM 탐지 이벤트 그리드: 모든 hit + LLM 판정을 TIME·SEV·SIG·분류·근거·점수 행으로 (인라인 번호와 cross-ref)

표시되는 모든 숫자·구간·로그 한 줄은 실제 룰/LLM 판정에서 나온다(가짜 텍스트·하드코딩 수치 없음).

실행:  streamlit run app.py
"""

from __future__ import annotations

import html
import math
import time

import streamlit as st

import config
import guard
import rules
import samples

config.reload_runtime_keys()

st.set_page_config(page_title="프롬프트 인젝션 가드 · SOC", page_icon="🛰️",
                   layout="wide", initial_sidebar_state="expanded")


# ════════════════════════════════════════════════════════════════════
#  Streamlit markdown 안전 래퍼 (전역 몽키패치 없이 호출 단위로)
# ════════════════════════════════════════════════════════════════════
#  Streamlit은 st.markdown 문자열을 markdown→HTML로 먼저 변환한다. 이때 4칸 이상
#  들여쓴 줄은 '코드 블록'으로 escape돼 <태그>가 글자로 보인다. 우리 템플릿은 가독성을
#  위해 들여쓰기되어 있으므로, HTML을 넘기기 전에 각 줄 앞 공백을 제거(구조 들여쓰기
#  평탄화)한다. 사용자 페이로드의 진짜 줄바꿈은 미리 <br>로 바꿔 두므로 안전하다.
#  (firewall-gate의 통찰을 채택하되, 전역 st.markdown 몽키패치는 의도적으로 쓰지 않는다.)
def md(body: str) -> None:
    flat = "".join(line.lstrip() for line in body.splitlines())
    st.markdown(flat, unsafe_allow_html=True)


def esc(x) -> str:
    """동적 텍스트는 전부 이스케이프(인젝션 입력을 그대로 렌더하므로 필수)."""
    return html.escape(str(x if x is not None else ""))


def esc1(x) -> str:
    """한 줄용 이스케이프: 모든 공백(줄바꿈 포함)을 단일 공백으로 접는다.
    LLM이 돌려준 자유 텍스트(reason 등)가 줄바꿈을 포함해도 한 줄 레이아웃을 지킨다."""
    return html.escape(" ".join(str(x if x is not None else "").split()))


def esc_br(x) -> str:
    """이스케이프 후 줄바꿈을 <br>로 바꾼다(원문 다중 행 보존용).
    중요: md()가 템플릿 들여쓰기를 평탄화할 때 페이로드의 \\n이 행으로 쪼개져 선행 공백이
    먹히는 것을 방지한다. 행 내부 공백은 .body{white-space:pre-wrap}이 그대로 보존한다."""
    return html.escape(str(x if x is not None else "")).replace("\n", "<br>")


# ── 카테고리 → 단축코드/색(SIEM 시그니처 ID 느낌) ──────────────────
#    rules.detect_spans / hits의 category(한글 라벨)를 키로 사용한다.
#    DECISION_META가 판정 색의 단일 소스이듯, 여기 색이 블립·마크·시그·그리드의 단일 소스.
CAT_META = {
    rules.C_OVERRIDE: ("INJ-OVR", "#FF5C7A"),   # 지시 무시/덮어쓰기
    rules.C_LEAK:     ("INJ-LEAK", "#FF7A45"),  # 시스템 프롬프트 탈취
    rules.C_ROLEPLAY: ("JBK-ROLE", "#C77DFF"),  # 역할극 탈옥
    rules.C_REFUSAL:  ("EVN-RFS", "#F5B14C"),   # 거부 억제
    rules.C_DELIM:    ("SPF-DLM", "#5AA2FF"),   # 구분자 위조
    rules.C_EXFIL:    ("EXF-BYP", "#FF5C7A"),   # 권한 우회/유출
    rules.C_ENCODE:   ("OBF-ENC", "#3DDC97"),   # 인코딩/난독 우회
    rules.C_URGENCY:  ("SOC-URG", "#9AA3B2"),   # 긴급·압박
}
_DEFAULT_CAT = ("SIG-GEN", "#9AA3B2")

# 시그니처 종수는 항상 라이브로 — 하드코딩 금지('정직한 카운트' 원칙).
SIG_DB_COUNT = len(rules._SIGNATURES)


def cat_code(category: str) -> str:
    return CAT_META.get(category, _DEFAULT_CAT)[0]


def cat_color(category: str) -> str:
    return CAT_META.get(category, _DEFAULT_CAT)[1]


# ════════════════════════════════════════════════════════════════════
#  글로벌 스타일(SOC 콘솔 테마)
# ════════════════════════════════════════════════════════════════════
md(
    """
    <style>
      @import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css');
      :root{
        --bg:#06070A; --panel:#0C0E14; --panel-2:#0F1219; --panel-3:#11151D;
        --line:rgba(120,160,220,.12); --line-2:rgba(120,160,220,.22);
        --text:#E8EDF5; --muted:#8893A6; --faint:#5A6474;
        --grn:#3DDC97; --blu:#5AA2FF; --cyn:#36D4E0; --red:#FF5C7A; --org:#FF7A45;
        --amb:#F5B14C; --vio:#C77DFF;
        --mono:ui-monospace,'SFMono-Regular','Cascadia Code',Consolas,'Liberation Mono',monospace;
      }
      html, body, [class*="css"], .stMarkdown, .stApp{
        font-family:'Pretendard',-apple-system,BlinkMacSystemFont,sans-serif;
        -webkit-font-smoothing:antialiased;
      }
      .stApp{
        background:
          radial-gradient(1200px 600px at 78% -260px, rgba(90,162,255,.10), transparent 60%),
          radial-gradient(900px 520px at 0% 0%, rgba(54,212,224,.06), transparent 55%),
          linear-gradient(180deg, #07080C 0%, var(--bg) 100%);
      }
      /* 미세 그리드 라인(관제 화면 느낌) */
      .stApp:before{
        content:""; position:fixed; inset:0; z-index:0; pointer-events:none;
        background-image:
          linear-gradient(rgba(120,160,220,.035) 1px, transparent 1px),
          linear-gradient(90deg, rgba(120,160,220,.035) 1px, transparent 1px);
        background-size:42px 42px; mask-image:linear-gradient(180deg, transparent, #000 8%, #000 92%, transparent);
      }
      .block-container{ padding-top:1.4rem; padding-bottom:4rem; max-width:1180px; position:relative; z-index:1; }
      #MainMenu, footer, header[data-testid="stHeader"]{ display:none; }

      @keyframes rise{ from{opacity:0; transform:translateY(10px);} to{opacity:1; transform:none;} }
      @keyframes blink{ 0%,100%{opacity:1;} 50%{opacity:.25;} }
      @keyframes sweep{ 0%{transform:translateX(-100%);} 100%{transform:translateX(320%);} }
      @keyframes logline{ from{opacity:0; transform:translateX(-6px);} to{opacity:1; transform:none;} }
      @keyframes meterfill{ from{width:0;} }
      @keyframes pulsering{ 0%{box-shadow:0 0 0 0 currentColor;} 70%{box-shadow:0 0 0 7px transparent;} 100%{box-shadow:0 0 0 0 transparent;} }
      @keyframes radar{ to{ transform:rotate(360deg); } }
      @keyframes gaugein{ from{ stroke-dashoffset:var(--circ); } }
      @keyframes markin{ from{ opacity:0; transform:translateY(2px);} to{ opacity:1; transform:none;} }
      @keyframes pktflow{ 0%{left:-8%;} 100%{left:108%;} }
      @keyframes stampslam{
        0%{ opacity:0; transform:translate(-50%,-50%) scale(2.6) rotate(-20deg); }
        55%{ opacity:1; transform:translate(-50%,-50%) scale(.86) rotate(-11deg); }
        72%{ transform:translate(-50%,-50%) scale(1.06) rotate(-11deg); }
        100%{ opacity:1; transform:translate(-50%,-50%) scale(1) rotate(-11deg); }
      }

      /* ── 콘솔 상단 바 ── */
      .topbar{ display:flex; align-items:center; gap:14px; flex-wrap:wrap; padding:11px 16px; border-radius:12px;
        border:1px solid var(--line); background:linear-gradient(180deg, rgba(255,255,255,.035), rgba(255,255,255,.008));
        font-family:var(--mono); animation:rise .4s ease both; box-shadow:0 14px 40px rgba(0,0,0,.45); }
      .topbar .brand{ display:flex; align-items:center; gap:10px; font-weight:800; letter-spacing:.04em;
        color:var(--text); font-size:14px; font-family:'Pretendard',sans-serif; }
      .topbar .logo{ width:30px; height:30px; border-radius:8px; position:relative; overflow:hidden;
        background:radial-gradient(circle at 50% 50%, rgba(61,220,151,.18), rgba(8,10,14,.9));
        border:1px solid var(--line-2); flex-shrink:0; }
      .topbar .logo:before{ content:""; position:absolute; inset:3px; border-radius:50%;
        border:1px solid rgba(61,220,151,.35); }
      .topbar .logo:after{ content:""; position:absolute; left:50%; top:50%; width:48%; height:1.5px;
        background:linear-gradient(90deg, var(--grn), transparent); transform-origin:left center;
        animation:radar 2.6s linear infinite; }
      .topbar .sub{ color:var(--faint); font-size:11px; letter-spacing:.12em; text-transform:uppercase;
        font-family:'Pretendard',sans-serif; font-weight:700; }
      .topbar .spacer{ flex:1; }
      .stat{ display:flex; align-items:center; gap:7px; font-size:11.5px; color:var(--muted);
        padding:4px 10px; border-radius:7px; border:1px solid var(--line); background:rgba(255,255,255,.018); }
      .stat b{ color:var(--text); font-weight:700; }
      .led{ width:8px; height:8px; border-radius:50%; display:inline-block; }
      .led.on{ background:var(--grn); color:var(--grn); animation:pulsering 2s infinite; }
      .led.warn{ background:var(--amb); color:var(--amb); animation:blink 1.6s infinite; }
      .led.off{ background:var(--faint); }
      .led.live{ background:var(--red); color:var(--red); animation:blink 1.1s infinite; }

      /* ── 섹션 라벨 ── */
      .seclabel{ display:flex; align-items:center; gap:9px; margin:20px 2px 9px; font-family:var(--mono);
        font-size:11px; letter-spacing:.18em; text-transform:uppercase; color:var(--faint); }
      .seclabel:before{ content:""; width:5px; height:5px; border-radius:1px; background:var(--blu);
        box-shadow:0 0 8px var(--blu); }
      .seclabel .ln{ flex:1; height:1px; background:linear-gradient(90deg,var(--line),transparent); }

      /* ── 인터셉션 레일(어디서 막혔나) ── */
      .rail{ position:relative; display:flex; align-items:center; gap:0; flex-wrap:nowrap;
        padding:14px 14px 16px; border-radius:14px; overflow:hidden;
        border:1px solid var(--line); background:var(--panel-2); animation:rise .35s ease both;
        box-shadow:0 14px 40px rgba(0,0,0,.45); }
      .rail .node{ position:relative; z-index:2; flex:0 0 auto; min-width:96px; text-align:center;
        border:1px solid var(--line-2); border-radius:12px; padding:11px 9px; background:var(--panel-3); }
      .rail .node .ic{ font-size:17px; line-height:1; }
      .rail .node .nm{ font-size:11.5px; font-weight:800; color:var(--text); margin-top:5px; }
      .rail .node .sb{ font-family:var(--mono); font-size:9px; color:var(--faint); margin-top:2px;
        white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:120px; }
      .rail .node.ep{ border-style:dashed; }
      .rail .node.pass{ border-color:rgba(61,220,151,.5); box-shadow:inset 0 0 18px rgba(61,220,151,.12); }
      .rail .node.block{ border-color:rgba(255,92,122,.55); box-shadow:inset 0 0 18px rgba(255,92,122,.14); }
      .rail .node.standby{ opacity:.72; border-style:dashed; }
      .rail .node .badge{ position:absolute; top:-9px; left:50%; transform:translateX(-50%);
        font-family:var(--mono); font-size:9px; font-weight:800; letter-spacing:.04em; padding:2px 7px;
        border-radius:6px; white-space:nowrap; border:1px solid currentColor; background:var(--panel); }
      .rail .seg{ position:relative; flex:1 1 auto; height:4px; min-width:26px; margin:0 -1px;
        border-radius:4px; background:rgba(120,150,200,.14); overflow:visible; }
      .rail .seg .fill{ position:absolute; inset:0; border-radius:4px; background:var(--sc,var(--blu)); opacity:.5; }
      .rail .seg.dead .fill{ background:rgba(255,92,122,.22); }
      .rail .seg .pkt{ position:absolute; top:50%; width:13px; height:13px; margin-top:-6.5px; border-radius:50%;
        background:var(--sc,var(--blu)); box-shadow:0 0 12px var(--sc,var(--blu)); animation:pktflow 1.5s linear infinite; }
      .rail .seg.dead .pkt{ display:none; }
      .rail .seg .cap{ position:absolute; top:-19px; left:50%; transform:translateX(-50%);
        font-family:var(--mono); font-size:8.5px; color:var(--faint); white-space:nowrap; }

      /* ── 위협 미터(헤드라인) — 게이지 + 세그먼트 ── */
      .threatwrap{ position:relative; padding:18px 20px; border-radius:14px; overflow:hidden;
        border:1px solid var(--line); background:var(--panel); animation:rise .35s ease both;
        box-shadow:0 16px 46px rgba(0,0,0,.5); }
      .threatwrap .scan{ position:absolute; top:0; left:0; width:34%; height:100%;
        background:linear-gradient(90deg, transparent, rgba(90,162,255,.12), transparent);
        animation:sweep 2.4s ease-in-out infinite; pointer-events:none; }
      .threatgrid{ position:relative; display:grid; grid-template-columns:170px 1fr; gap:20px; align-items:center; }
      .gauge{ display:flex; flex-direction:column; align-items:center; position:relative; }
      .gauge .lvl{ font-family:var(--mono); font-size:10.5px; letter-spacing:.14em; color:var(--muted);
        margin-top:6px; text-transform:uppercase; }
      .stamp{ position:absolute; top:50%; left:50%; z-index:6; text-align:center; pointer-events:none;
        font-family:var(--mono); font-weight:900; letter-spacing:.05em; padding:8px 16px; border-radius:9px;
        border:3px solid var(--red); color:var(--red); background:rgba(255,92,122,.07);
        text-shadow:0 0 12px rgba(255,92,122,.5); box-shadow:0 0 0 3px rgba(255,92,122,.10),0 0 30px rgba(255,92,122,.25);
        animation:stampslam .55s cubic-bezier(.2,1.3,.4,1) both; white-space:nowrap; }
      .stamp .big{ font-size:19px; display:block; line-height:1; }
      .stamp .sm{ font-size:8.5px; display:block; margin-top:3px; opacity:.85; letter-spacing:.1em; }
      .verdict{ font-family:'Pretendard',sans-serif; font-weight:800; font-size:24px; line-height:1.1;
        display:flex; align-items:center; gap:10px; }
      .verdict .band{ font-family:var(--mono); font-size:11px; font-weight:700; padding:2px 9px; border-radius:6px;
        border:1px solid currentColor; letter-spacing:.06em; margin-left:4px; }
      .meter{ margin-top:14px; height:18px; border-radius:6px; position:relative; overflow:hidden;
        background:repeating-linear-gradient(90deg, rgba(255,255,255,.05) 0 2px, transparent 2px 4%);
        border:1px solid var(--line-2); }
      .meter .fill{ height:100%; border-radius:5px; animation:meterfill 1s cubic-bezier(.2,.8,.2,1) both;
        box-shadow:0 0 18px currentColor; position:relative; }
      .meter .thr{ position:absolute; top:-3px; bottom:-3px; width:2px; z-index:3; }
      .meter .thr.flag{ background:var(--amb); box-shadow:0 0 8px var(--amb); }
      .meter .thr.block{ background:var(--red); box-shadow:0 0 8px var(--red); }
      .meter .thr .tl{ position:absolute; top:-15px; left:50%; transform:translateX(-50%);
        font-family:var(--mono); font-size:8px; white-space:nowrap; letter-spacing:.04em; }
      .meter .needle{ position:absolute; top:-4px; bottom:-4px; width:2px; background:#fff;
        box-shadow:0 0 10px #fff; z-index:4; }
      .mscale{ display:flex; justify-content:space-between; font-family:var(--mono); font-size:10px;
        color:var(--faint); margin-top:16px; letter-spacing:.06em; }
      .laychips{ display:flex; gap:8px; margin-top:13px; }
      .laychip{ flex:1; display:flex; align-items:center; justify-content:center; gap:7px; font-family:var(--mono);
        font-size:10.5px; padding:6px 4px; border-radius:8px; border:1px solid var(--line-2);
        background:var(--panel-3); color:var(--muted); }
      .laychip .d{ width:7px; height:7px; border-radius:50%; }

      /* ── 라이브 로그 콘솔 ── */
      .console{ border:1px solid var(--line); border-radius:13px; background:linear-gradient(180deg,#090B11,#070A0F);
        overflow:hidden; animation:rise .35s ease both; box-shadow:0 16px 46px rgba(0,0,0,.5); }
      .console .bar{ display:flex; align-items:center; gap:7px; padding:9px 13px; border-bottom:1px solid var(--line);
        background:rgba(255,255,255,.02); font-family:var(--mono); font-size:11px; color:var(--faint); }
      .console .dot{ width:10px; height:10px; border-radius:50%; }
      .console .ttl{ margin-left:8px; letter-spacing:.06em; }
      .console .live{ margin-left:auto; display:flex; align-items:center; gap:6px; color:var(--red);
        letter-spacing:.14em; font-weight:700; }
      .logbody{ padding:12px 15px 15px; font-family:var(--mono); font-size:12.5px; line-height:1.85;
        max-height:340px; overflow-y:auto; }
      .logline{ display:flex; gap:10px; white-space:pre-wrap; animation:logline .25s ease both; }
      .logline .ts{ color:var(--faint); flex-shrink:0; }
      .logline .mk{ flex-shrink:0; width:14px; text-align:center; }
      .logline.ok   .mk{ color:var(--grn); }
      .logline.hit  .mk{ color:var(--red); }
      .logline.warn .mk{ color:var(--amb); }
      .logline.info .mk{ color:var(--blu); }
      .logline.dim{ color:var(--faint); }
      .logline .tx{ color:var(--muted); }
      .logline.hit  .tx{ color:#FFD9E0; }
      .logline.ok   .tx b{ color:var(--grn); }
      .logline.hit  .tx b{ color:var(--red); }
      .cursor{ display:inline-block; width:8px; height:14px; background:var(--grn); vertical-align:middle;
        animation:blink 1s steps(1) infinite; margin-left:2px; }

      /* ── 원문 인라인 하이라이트(증거) ── */
      .evidence{ border:1px solid var(--line); border-radius:13px; background:var(--panel);
        overflow:hidden; animation:rise .35s ease both; }
      .evidence .bar{ display:flex; align-items:center; gap:8px; padding:9px 14px; border-bottom:1px solid var(--line);
        font-family:var(--mono); font-size:11px; color:var(--faint); letter-spacing:.06em; }
      .evidence .body{ padding:18px 17px 15px; font-family:var(--mono); font-size:13px; line-height:2.2;
        color:var(--text); white-space:pre-wrap; word-break:break-word; max-height:260px; overflow-y:auto;
        counter-reset:mk; }
      mark.ev{ padding:2px 4px; border-radius:5px; color:#fff; font-weight:600; position:relative;
        background:var(--mc,rgba(255,92,122,.16)); border-bottom:2px solid var(--mcb,currentColor); cursor:help;
        animation:markin .4s ease both; }
      mark.ev:after{ counter-increment:mk; content:counter(mk); position:absolute; top:-8px; right:-7px;
        min-width:15px; height:15px; padding:0 2px; font-family:var(--mono); font-size:9px; font-weight:700;
        line-height:15px; text-align:center; color:#06070A; background:var(--mcb); border-radius:50%;
        box-shadow:0 0 0 2px var(--panel); }
      mark.ev .tip{ font-family:var(--mono); font-size:10px; vertical-align:super; opacity:.85;
        margin-left:3px; letter-spacing:.04em; }
      mark.ev.zw{ background:repeating-linear-gradient(45deg, rgba(61,220,151,.35) 0 4px, transparent 4px 8px);
        outline:1px dashed var(--grn); }
      .evnone{ color:var(--faint); font-style:italic; }

      /* ── 레이어 파이프라인 ── */
      .stage{ border:1px solid var(--line); border-radius:12px; background:var(--panel);
        padding:14px 16px; animation:rise .35s ease both; position:relative; overflow:hidden; margin-bottom:11px; }
      .stage .top{ display:flex; align-items:center; gap:10px; }
      .stage .ix{ font-family:var(--mono); font-size:11px; color:var(--faint); }
      .stage .nm{ font-weight:800; font-size:14px; color:var(--text); }
      .stage .badge{ margin-left:auto; font-family:var(--mono); font-size:10.5px; font-weight:700;
        padding:3px 9px; border-radius:6px; letter-spacing:.08em; border:1px solid currentColor; }
      .stage .desc{ font-size:12px; color:var(--muted); margin-top:8px; line-height:1.55; }
      .hitrow{ display:flex; gap:8px; align-items:baseline; font-family:var(--mono); font-size:11.5px;
        padding:6px 0; border-top:1px dashed var(--line); }
      .hitrow .sid{ flex-shrink:0; font-weight:700; padding:1px 6px; border-radius:5px;
        border:1px solid currentColor; }
      .hitrow .dsc{ color:var(--muted); flex:1; }
      .hitrow .wt{ color:var(--faint); flex-shrink:0; }
      .chip{ display:inline-block; font-family:var(--mono); font-size:10.5px; font-weight:700;
        padding:2px 8px; margin:3px 4px 0 0; border-radius:6px; color:var(--vio);
        background:rgba(199,125,255,.08); border:1px solid rgba(199,125,255,.25); }
      .progbar{ height:4px; border-radius:3px; background:rgba(255,255,255,.05); margin-top:11px; overflow:hidden; }
      .progbar > i{ display:block; height:100%; border-radius:3px; }

      /* ── 탐지 이벤트 그리드(SIEM) ── */
      .grid{ width:100%; border-collapse:collapse; font-family:var(--mono); font-size:11.5px;
        border:1px solid var(--line); border-radius:12px; overflow:hidden; }
      .grid thead th{ text-align:left; padding:9px 12px; color:var(--faint); font-weight:700;
        letter-spacing:.1em; text-transform:uppercase; font-size:10px; background:rgba(255,255,255,.025);
        border-bottom:1px solid var(--line); }
      .grid tbody td{ padding:9px 12px; border-bottom:1px solid var(--line); color:var(--muted); vertical-align:top; }
      .grid tbody tr:last-child td{ border-bottom:none; }
      .grid tbody tr:hover td{ background:rgba(90,162,255,.04); }
      .gnum{ display:inline-block; min-width:16px; height:16px; line-height:16px; text-align:center; border-radius:50%;
        font-size:9px; font-weight:700; color:#06070A; }
      .sev{ font-weight:800; padding:1px 7px; border-radius:5px; border:1px solid currentColor; white-space:nowrap; }
      .grid .ev{ color:var(--faint); }
      .grid .sigc{ font-weight:700; }

      /* ── 사이드바 ── */
      section[data-testid="stSidebar"]{ background:linear-gradient(180deg,#080A0F,#06070A);
        border-right:1px solid var(--line); }
      section[data-testid="stSidebar"] .blk{ font-family:var(--mono); font-size:10px; letter-spacing:.16em;
        text-transform:uppercase; color:var(--faint); margin:6px 0 8px; }
      .stButton > button{ border-radius:9px; border:1px solid var(--line); background:rgba(255,255,255,.02);
        color:var(--text); font-weight:600; font-size:13px; text-align:left; transition:.14s; }
      .stButton > button:hover{ border-color:var(--line-2); background:rgba(90,162,255,.06); }
      .runbtn .stButton > button{ background:linear-gradient(180deg, rgba(61,220,151,.18), rgba(61,220,151,.05));
        border-color:rgba(61,220,151,.45); color:#CFFCEA; font-weight:800; text-align:center;
        font-family:var(--mono); letter-spacing:.05em; }
      .runbtn .stButton > button:hover{ border-color:var(--grn); box-shadow:0 0 24px rgba(61,220,151,.25); }

      /* 입력 영역을 터미널처럼 */
      .stTextArea textarea{ font-family:var(--mono) !important; font-size:13px !important;
        background:#080A0F !important; border:1px solid var(--line) !important; color:#CDE7FF !important;
        border-radius:11px !important; }
      .stTextArea textarea:focus{ border-color:var(--line-2) !important;
        box-shadow:0 0 0 1px rgba(90,162,255,.25) !important; }

      .ix-prompt{ font-family:var(--mono); font-size:11px; color:var(--faint); margin:6px 2px 4px;
        display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
      .ix-prompt b{ color:var(--grn); }

      .note{ font-family:var(--mono); font-size:11.5px; color:var(--muted); line-height:1.7;
        border:1px solid var(--line); border-left:2px solid var(--blu); border-radius:0 9px 9px 0;
        padding:12px 14px; background:rgba(90,162,255,.03); }
      .foot{ text-align:center; color:var(--faint); font-family:var(--mono); font-size:11px;
        margin-top:30px; letter-spacing:.06em; }

      div[data-testid="stExpander"]{ border:1px solid var(--line) !important; border-radius:12px !important;
        background:rgba(255,255,255,.015) !important; }

      /* ── 좁은 화면 반응형(graft: firewall-gate) ── */
      @media (max-width:680px){
        .threatgrid{ grid-template-columns:1fr; }
        .grid thead th:nth-child(5), .grid tbody td:nth-child(5){ display:none; }
        .topbar .sub{ display:none; }
      }
    </style>
    """
)


# ════════════════════════════════════════════════════════════════════
#  세션 상태 + 샘플 콜백 (기존 app.py 패턴 유지)
# ════════════════════════════════════════════════════════════════════
if "text" not in st.session_state:
    st.session_state.text = samples.ATTACKS[0]["text"]
if "auto" not in st.session_state:
    st.session_state.auto = True


def load_sample(t: str):
    st.session_state.text = t
    st.session_state.auto = True


HAS_KEY = config.has_anthropic_key()


# ════════════════════════════════════════════════════════════════════
#  사이드바: 관제 설정 + 샘플 주입
# ════════════════════════════════════════════════════════════════════
with st.sidebar:
    md('<div class="blk">▌ENGINE CONTROL</div>')
    use_llm = st.toggle("LLM 분석 레이어 (2차)", value=True,
                        help="Anthropic 키가 있을 때만 동작. 룰 레이어(1차)는 항상 켜짐.")
    md(
        f'<div class="ix-prompt"><span class="led {"on" if HAS_KEY else "warn"}"></span>'
        f'Anthropic 키: <b style="color:{"var(--grn)" if HAS_KEY else "var(--amb)"}">'
        f'{"CONNECTED" if HAS_KEY else "STANDBY"}</b></div>'
    )
    if not HAS_KEY:
        st.caption("키가 없어도 룰 레이어가 단독으로 공격을 차단합니다.")

    md('<div class="blk" style="margin-top:18px">▌ATTACK SAMPLES · 위협 주입</div>')
    st.caption("클릭하면 입력에 주입하고 즉시 스캔합니다.")
    for s in samples.ATTACKS:
        st.button("🔴 " + s["title"], key="atk_" + s["id"], use_container_width=True,
                  on_click=load_sample, args=(s["text"],), help=s.get("technique", ""))

    md('<div class="blk" style="margin-top:16px">▌BENIGN BASELINE · 정상 트래픽</div>')
    st.caption("오탐(false positive) 회피 확인용.")
    for s in samples.BENIGN:
        st.button("🟢 " + s["title"], key="bn_" + s["id"], use_container_width=True,
                  on_click=load_sample, args=(s["text"],))


# ════════════════════════════════════════════════════════════════════
#  상단 콘솔 바
# ════════════════════════════════════════════════════════════════════
clock = time.strftime("%H:%M:%S")
key_led = "on" if HAS_KEY else "warn"
key_txt = "ONLINE" if HAS_KEY else "STANDBY"
md(
    f"""
    <div class="topbar">
      <div class="logo"></div>
      <div>
        <div class="brand">PROMPT&nbsp;INJECTION&nbsp;GUARD</div>
        <div class="sub">GENAI THREAT DETECTION CONSOLE · 다층 방어</div>
      </div>
      <div class="spacer"></div>
      <div class="stat"><span class="led on"></span>ENGINE&nbsp;<b>ACTIVE</b></div>
      <div class="stat">SIG-DB&nbsp;<b>{SIG_DB_COUNT}</b></div>
      <div class="stat"><span class="led {key_led}"></span>LLM&nbsp;<b>{key_txt}</b></div>
      <div class="stat">⏱ <b>{clock}</b> KST</div>
    </div>
    """
)


# ════════════════════════════════════════════════════════════════════
#  입력(터미널 프롬프트 스타일)
# ════════════════════════════════════════════════════════════════════
md(
    '<div class="ix-prompt"><b>guard@soc</b> ~ <span style="color:var(--muted)">'
    '검사할 입력 스트림을 붙여넣고 스캔을 실행하세요</span> <span class="cursor"></span></div>'
)
text = st.text_area("검사할 입력", key="text", height=130,
                    label_visibility="collapsed",
                    placeholder="LLM에 전달될 사용자 입력(payload)을 여기에…")

md('<div class="runbtn">')
run = st.button("▶  THREAT SCAN — 검사 실행", type="primary", use_container_width=True)
md('</div>')

should_eval = run or st.session_state.auto
st.session_state.auto = False


# ════════════════════════════════════════════════════════════════════
#  인터셉션 레일 빌더 (firewall-gate graft: 어디서 막혔나)
# ════════════════════════════════════════════════════════════════════
def build_rail(result: dict, used_llm_layer: bool) -> str:
    """입력 → ①룰 게이트 → ②LLM 게이트 → LLM 도달/차단 흐름.
    게이트 상태는 guard layers/score/llm 분기와 1:1 — 백엔드 로직을 충실히 증거화."""
    rule = result["rule"]
    llm = result["llm"]
    decision = result["decision"]
    _emoji, dcolor = guard.DECISION_META[decision]

    rule_fired = result["layers"]["rule"]
    rule_block = rule["score"] >= rules.BLOCK_THRESHOLD
    llm_inj = result["layers"]["llm"]

    # 게이트 ① 룰
    if rule_block:
        g1 = ("block", "BLOCKED", "🚫", "룰 게이트", f"score {rule['score']}")
    elif rule_fired:
        g1 = ("block", "FLAGGED", "⚠️", "룰 게이트", f"score {rule['score']}")
    else:
        g1 = ("pass", "PASS", "✅", "룰 게이트", f"score {rule['score']}")
    g1_stops = rule_block

    # 게이트 ② LLM (firewall-gate의 명시적 6분기)
    if g1_stops:
        g2 = ("standby", "SKIP", "⏭️", "LLM 게이트", "1차 차단 생략")
    elif not (used_llm_layer and HAS_KEY):
        g2 = ("standby", "STANDBY", "🌙", "LLM 게이트", "키 없음 · 대기")
    elif llm and not llm.get("ok"):
        g2 = ("standby", "DEGRADED", "⚠️", "LLM 게이트", "분류 불가 · 폴백")
    elif llm_inj:
        conf = float(llm.get("confidence", 0.0))
        g2 = ("block", "BLOCKED", "🚫", "LLM 게이트", f"인젝션 {conf:.0%}")
    elif llm and llm.get("ok"):
        g2 = ("pass", "PASS", "✅", "LLM 게이트", "정상 판정")
    else:
        g2 = ("standby", "STANDBY", "🌙", "LLM 게이트", "비활성")
    g2_stops = (g2[0] == "block")

    # 세그먼트 색/생사
    def seg(state, color, cap):
        dead = "dead" if state == "dead" else ""
        return (f'<div class="seg {dead}" style="--sc:{color}">'
                f'<div class="cap">{esc(cap)}</div><div class="fill"></div><div class="pkt"></div></div>')

    segA = ("live", "var(--blu)", "패킷 진입")
    if g1_stops:
        segB = ("dead", "var(--red)", "차단됨")
    else:
        segB = ("live", "var(--blu)" if not rule_fired else "var(--amb)", "검사 통과")
    if g1_stops or g2_stops:
        segC = ("dead", "var(--red)", "차단됨")
    elif g2[0] == "standby":
        segC = ("live", "var(--blu)" if not rule_fired else "var(--amb)", "룰 단독 통과")
    else:
        segC = ("live", "var(--grn)", "전달 승인")

    # 종착 노드
    if decision == "차단":
        dest = ("block", "DROPPED", "🧱", "LLM 보호됨", "패킷 폐기")
    elif decision == "검토":
        dest = ("pass", "FLAGGED", "🔎", "LLM 도달", "플래그 전달")
    else:
        dest = ("pass", "DELIVERED", "🤖", "LLM 도달", "정상 전달")

    def node(state, badge, ic, nm, sb, ep=False):
        cls = "node" + (" ep" if ep else "") + " " + state
        col = {"pass": "var(--grn)", "block": "var(--red)", "standby": "var(--faint)"}.get(state, "var(--faint)")
        return (f'<div class="{cls}"><div class="badge" style="color:{col}">{esc(badge)}</div>'
                f'<div class="ic">{ic}</div><div class="nm">{esc(nm)}</div>'
                f'<div class="sb">{esc(sb)}</div></div>')

    in_node = node("pass", "INGEST", "📥", "입력 패킷", f'{rule["signals"]["length"]} chars', ep=True)
    return (
        '<div class="rail">'
        f'{in_node}{seg(*segA)}'
        f'{node(*g1)}{seg(*segB)}'
        f'{node(*g2)}{seg(*segC)}'
        f'{node(*dest, ep=True)}'
        '</div>'
    )


# ════════════════════════════════════════════════════════════════════
#  위협 미터 헤드라인 (SVG 원형 게이지 + 세그먼트 미터 + BLOCKED 도장)
# ════════════════════════════════════════════════════════════════════
def build_threat_meter(result: dict) -> str:
    decision = result["decision"]
    emoji, color = guard.DECISION_META[decision]
    risk = max(0, min(100, int(result["risk"])))
    level = result["rule"]["level"]

    band = ("CRITICAL" if risk >= rules.BLOCK_THRESHOLD
            else "ELEVATED" if risk >= rules.FLAG_THRESHOLD else "NOMINAL")

    # SVG 원형 게이지 (radar-scanner graft)
    circ = 2 * math.pi * 78
    off = circ * (1 - risk / 100.0)
    gauge = (
        f'<svg width="150" height="150" viewBox="0 0 200 200" style="--circ:{circ:.1f}">'
        '<defs><filter id="gl"><feGaussianBlur stdDeviation="3" result="b"/>'
        '<feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>'
        '<circle cx="100" cy="100" r="78" fill="none" stroke="rgba(120,160,220,.12)" stroke-width="12"/>'
        f'<circle cx="100" cy="100" r="78" fill="none" stroke="{color}" stroke-width="12" '
        f'stroke-linecap="round" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{off:.1f}" '
        f'transform="rotate(-90 100 100)" filter="url(#gl)" '
        'style="animation:gaugein .9s cubic-bezier(.2,.8,.2,1) both"/>'
        f'<text x="100" y="92" text-anchor="middle" fill="{color}" '
        'style="font-family:var(--mono);font-size:46px;font-weight:800">'
        f'{risk}</text>'
        '<text x="100" y="118" text-anchor="middle" fill="var(--faint)" '
        'style="font-family:var(--mono);font-size:11px;letter-spacing:.18em">/ 100 RISK</text>'
        '</svg>'
    )

    # 차단 시 고무도장 (firewall-gate graft)
    stamp = ""
    if decision == "차단":
        stamp = ('<div class="stamp"><span class="big">⛔ BLOCKED</span>'
                 '<span class="sm">PROMPT INJECTION · DROPPED</span></div>')

    # 세그먼트 미터 + 임계 틱(상수 연동) + 바늘
    flag_pct = rules.FLAG_THRESHOLD
    block_pct = rules.BLOCK_THRESHOLD
    rule_on = result["layers"]["rule"]
    llm_on = result["layers"]["llm"]
    lay = (
        f'<div class="laychip"><span class="d" style="background:'
        f'{"var(--red)" if rule_on else "var(--faint)"}"></span>RULE {"●" if rule_on else "○"}</div>'
        f'<div class="laychip"><span class="d" style="background:'
        f'{"var(--red)" if llm_on else "var(--faint)"}"></span>LLM {"●" if llm_on else "○"}</div>'
    )

    return (
        f'<div class="threatwrap" style="border-color:{color}55">'
        '<div class="scan"></div>'
        '<div class="threatgrid">'
        f'<div class="gauge">{gauge}{stamp}<div class="lvl">위협 등급 · {esc(level)}</div></div>'
        '<div>'
        f'<div class="verdict" style="color:{color}">{emoji} {esc(decision)}'
        f'<span class="band">{band}</span></div>'
        '<div class="meter">'
        f'<div class="fill" style="width:{risk}%; background:linear-gradient(90deg,{color}88,{color}); color:{color}"></div>'
        f'<div class="thr flag" style="left:{flag_pct}%"><span class="tl" style="color:var(--amb)">FLAG {flag_pct}</span></div>'
        f'<div class="thr block" style="left:{block_pct}%"><span class="tl" style="color:var(--red)">BLOCK {block_pct}</span></div>'
        f'<div class="needle" style="left:{risk}%"></div>'
        '</div>'
        '<div class="mscale"><span>0 · 허용</span><span>임계 틱 = 백엔드 상수</span><span>100</span></div>'
        f'<div class="laychips">{lay}</div>'
        '</div></div></div>'
    )


# ════════════════════════════════════════════════════════════════════
#  라이브 스캔 로그 빌더 (soc-console 핵심: 단계별 순차 점등)
# ════════════════════════════════════════════════════════════════════
def build_scan_log(result: dict, used_llm_layer: bool) -> str:
    """실제 결과(result)를 바탕으로 SOC 스캔 로그 라인들을 만든다.
    각 라인은 CSS animation-delay(0.16s 간격)로 순차 등장 — 분기·문구는 100% 실제 값에서 갈린다."""
    rule = result["rule"]
    sig = rule["signals"]
    lines: list[tuple[str, str, str]] = []  # (level, mark, body_html)

    def L(level, mark, body):
        lines.append((level, mark, body))

    L("info", "▶", f"입력 스트림 수신 — {esc(sig['length'])} chars · 정규화/디코드 파이프라인 가동")
    L("info", "▶", f"룰 시그니처 <b>{SIG_DB_COUNT}</b>종 대조 (한·영 정규식, 대소문자 무시)…")

    hits = rule["hits"]
    plain_hits = [h for h in hits if h["category"] != rules.C_ENCODE]
    if plain_hits:
        for h in plain_hits:
            code = cat_code(h["category"])
            L("hit", "✗", f"시그니처 매칭 <b>{esc(code)}</b> · {esc(h['category'])} "
                           f"— {esc(h['desc'])} <span class='ts'>(가중치 +{esc(h['weight'])})</span>")
    else:
        L("ok", "✓", "평문 시그니처 매칭 없음")

    # base64 디코드 단계
    L("info", "▶", "의심 토큰 base64 디코드 시도 (printable ratio &gt; 0.85)…")
    if sig["encoded"]:
        b64_hits = [h for h in hits if h["category"] == rules.C_ENCODE and "base64" in h["desc"]]
        if b64_hits:
            L("hit", "✗", f"<b>OBF-ENC</b> · 디코드 결과에서 공격 패턴 확인 — {esc(b64_hits[0]['desc'])}")
        else:
            L("hit", "✗", "<b>OBF-ENC</b> · base64 페이로드에서 공격 패턴 확인")
    else:
        L("ok", "✓", "인코딩 우회 페이로드 없음")

    # 제로폭/난독
    if sig["zero_width"]:
        L("hit", "✗", "<b>OBF-ENC</b> · 제로폭(보이지 않는) 문자 검출 — 난독화 시도")
    else:
        L("ok", "✓", "제로폭/난독 문자 미검출")

    # 룰 스코어
    lvl = rule["level"]
    L("warn" if lvl != "안전" else "ok",
      "Σ", f"룰 레이어 위험 점수 집계 = <b>{esc(rule['score'])}/100</b> · 레벨 [{esc(lvl)}] "
           f"(FLAG≥{rules.FLAG_THRESHOLD} / BLOCK≥{rules.BLOCK_THRESHOLD})")

    # LLM 레이어
    llm = result["llm"]
    if llm and llm.get("ok"):
        if llm.get("is_injection"):
            L("hit", "✗", f"LLM 의미 분석 — <b>인젝션 의심</b> · {esc(llm.get('category') or '미상')} "
                           f"(확신 {float(llm['confidence']):.0%})")
        else:
            L("ok", "✓", f"LLM 의미 분석 — 정상 판정 (확신 {float(llm['confidence']):.0%})")
    elif llm and not llm.get("ok"):
        L("warn", "!", f"LLM 레이어 오류 — {esc1(llm.get('error', ''))} · 룰 레이어로 폴백")
    elif used_llm_layer:
        L("dim", "○", "LLM 레이어 비활성 (키 STANDBY) — 룰 레이어 단독 가동")
    else:
        L("dim", "○", "LLM 레이어 OFF (토글 해제) — 룰 레이어 단독 가동")

    # 최종 판정
    decision = result["decision"]
    _emoji, color = guard.DECISION_META[decision]
    dmark = "✗" if decision == "차단" else "!" if decision == "검토" else "✓"
    dlevel = "hit" if decision == "차단" else "warn" if decision == "검토" else "ok"
    L(dlevel, dmark, f"<b style='color:{color}'>최종 판정 · {esc(decision)}</b> "
                     f"— 위험도 {esc(result['risk'])}/100 · 결정 레이어 승급 규칙 적용")

    # 라인 → HTML (순차 등장 애니메이션). 타임스탬프는 의사 시퀀스(연출용 라벨).
    out = []
    base = time.strftime("%H:%M:%S")
    for i, (level, mark, body) in enumerate(lines):
        delay = round(i * 0.16, 2)
        out.append(
            f'<div class="logline {level}" style="animation-delay:{delay}s">'
            f'<span class="ts">[{base}.{i:02d}]</span>'
            f'<span class="mk">{mark}</span><span class="tx">{body}</span></div>'
        )
    last_delay = round(len(lines) * 0.16, 2)
    out.append(
        f'<div class="logline dim" style="animation-delay:{last_delay}s">'
        f'<span class="ts">[{base}.{len(lines):02d}]</span>'
        f'<span class="mk" style="color:var(--grn)">$</span>'
        f'<span class="tx">scan complete<span class="cursor"></span></span></div>'
    )
    return "".join(out)


# ════════════════════════════════════════════════════════════════════
#  원문 인라인 하이라이트(증거) — forensic-highlight 클램핑 방어 이식
# ════════════════════════════════════════════════════════════════════
def build_evidence_html(text: str, spans: list[dict]) -> str:
    """rules.detect_spans()로 원문 위 악성 구간을 인라인 하이라이트한다.
    detect_spans는 정렬·병합된 구간을 주지만, 어떤 엣지 입력에도 안전하도록 클램핑/겹침 방어."""
    if not text:
        return '<div class="evnone">입력 없음</div>'
    if not spans:
        return ('<div class="evnone">탐지된 악성 구간 없음 — 원문에 매칭되는 위험 시그니처가 '
                '없습니다 (정상 트래픽).</div>')
    spans = sorted(spans, key=lambda sp: (sp["start"], sp["end"]))
    out = []
    cur = 0
    n = len(text)
    for sp in spans:
        s = max(0, min(n, int(sp["start"])))
        e = max(0, min(n, int(sp["end"])))
        if e <= cur or s >= n:
            continue
        s = max(s, cur)
        if e <= s:
            continue
        if s > cur:
            out.append(esc_br(text[cur:s]))
        cat = sp["category"]
        code = cat_code(cat)
        color = cat_color(cat)
        frag = text[s:e]
        is_zw = (cat == rules.C_ENCODE and frag.strip() == "")
        cls = "ev zw" if is_zw else "ev"
        shown = esc_br(frag) if frag.strip() else "⟨제로폭⟩"
        out.append(
            f'<mark class="{cls}" style="--mc:{color}22;--mcb:{color}" '
            f'title="{esc(cat)} · {esc(code)} · weight {esc(sp["weight"])}">'
            f'{shown}<span class="tip">{esc(code)}</span></mark>'
        )
        cur = e
    if cur < n:
        out.append(esc_br(text[cur:]))
    return "".join(out)


# ════════════════════════════════════════════════════════════════════
#  메인 출력
# ════════════════════════════════════════════════════════════════════
if should_eval and text.strip():
    result = guard.evaluate(text, use_llm=use_llm)
    decision = result["decision"]
    emoji, color = guard.DECISION_META[decision]
    risk = int(result["risk"])
    rule = result["rule"]
    llm = result["llm"]
    spans = rules.detect_spans(text)   # 한 번만 계산해 재사용

    # 0) 인터셉션 레일 — 어디서 막혔나 -----------------------------
    md('<div class="seclabel">INTERCEPTION RAIL · 패킷 흐름 (어디서 막혔나)<span class="ln"></span></div>')
    md(build_rail(result, used_llm_layer=use_llm))

    # 1) 위협 미터 헤드라인 (게이지 + 세그먼트 + 도장) -------------
    md('<div class="seclabel">THREAT METER · 위협 지수<span class="ln"></span></div>')
    md(build_threat_meter(result))

    # 2) 라이브 스캔 로그 ------------------------------------------
    md('<div class="seclabel">LIVE SCAN LOG · 실시간 탐지 파이프라인<span class="ln"></span></div>')
    log_html = build_scan_log(result, used_llm_layer=use_llm)
    md(
        f"""
        <div class="console">
          <div class="bar">
            <span class="dot" style="background:#FF5F56"></span>
            <span class="dot" style="background:#FFBD2E"></span>
            <span class="dot" style="background:#27C93F"></span>
            <span class="ttl">guard-engine — /var/log/injection-scan.log</span>
            <span class="live"><span class="led live"></span>LIVE</span>
          </div>
          <div class="logbody">{log_html}</div>
        </div>
        """
    )

    # 3) 원문 증거 하이라이트 + 레이어 파이프라인 (2단) -------------
    colL, colR = st.columns([1.25, 1], gap="medium")

    with colL:
        md('<div class="seclabel">PAYLOAD EVIDENCE · 원문 내 악성 구간<span class="ln"></span></div>')
        ev_html = build_evidence_html(text, spans)
        span_n = len(spans)
        md(
            f"""
            <div class="evidence">
              <div class="bar">⌖ inline detection · 하이라이트 구간 <b style="color:var(--text)">{span_n}</b>개
                · 번호=아래 SIEM 행과 동일 · 색상=카테고리</div>
              <div class="body">{ev_html}</div>
            </div>
            """
        )

    with colR:
        md('<div class="seclabel">DEFENSE PIPELINE · 레이어<span class="ln"></span></div>')

        # STAGE 1 — 룰
        fired = result["layers"]["rule"]
        s1_color = ("var(--red)" if rule["score"] >= rules.BLOCK_THRESHOLD
                    else "var(--amb)" if fired else "var(--grn)")
        s1_txt = ("BLOCK" if rule["score"] >= rules.BLOCK_THRESHOLD
                  else "FLAG" if fired else "PASS")
        rows = ""
        for h in rule["hits"][:4]:
            code = cat_code(h["category"])
            col = cat_color(h["category"])
            rows += (f'<div class="hitrow"><span class="sid" style="color:{col}">{esc(code)}</span>'
                     f'<span class="dsc">{esc(h["desc"])}</span>'
                     f'<span class="wt">+{esc(h["weight"])}</span></div>')
        if not rows:
            rows = '<div class="desc">매칭된 룰 시그니처 없음 — 정상 패턴.</div>'
        sig = rule["signals"]
        flags = []
        if sig["encoded"]:
            flags.append("base64 디코드 우회")
        if sig["zero_width"]:
            flags.append("제로폭 난독화")
        flag_html = (f'<div class="desc" style="color:var(--org)">⚑ {esc(" · ".join(flags))}</div>'
                     if flags else "")
        s1_w = min(100, rule["score"])
        md(
            f"""
            <div class="stage" style="border-color:{s1_color}44">
              <div class="top"><span class="ix">L1</span><span class="nm">룰 / 시그니처 레이어</span>
                <span class="badge" style="color:{s1_color}">{s1_txt} · {esc(rule['score'])}</span></div>
              <div class="desc">오프라인·무료. 알려진 인젝션·인코딩 우회를 정규식으로 즉시 차단.</div>
              {rows}{flag_html}
              <div class="progbar"><i style="width:{s1_w}%; background:{s1_color}"></i></div>
            </div>
            """
        )

        # STAGE 2 — LLM (명시적 분기)
        if llm and llm.get("ok"):
            inj = llm["is_injection"]
            s2_color = "var(--red)" if inj else "var(--grn)"
            s2_badge = "INJECTION" if inj else "CLEAN"
            techs = "".join(f'<span class="chip">{esc1(t)}</span>' for t in llm.get("techniques", []))
            body = (f'<div class="desc" style="color:{s2_color}">'
                    f'{esc1(llm.get("category") or ("인젝션 의심" if inj else "정상"))} '
                    f'· 확신 {float(llm["confidence"]):.0%}</div>'
                    f'<div class="desc">{esc1(llm.get("reason", ""))}</div>{techs}')
            s2_w = int(round(float(llm["confidence"]) * 100))
            prog = f'<div class="progbar"><i style="width:{s2_w}%; background:{s2_color}"></i></div>'
        elif llm and not llm.get("ok"):
            s2_color, s2_badge = "var(--amb)", "DEGRADED"
            body = f'<div class="desc" style="color:var(--amb)">분류 불가: {esc1(llm.get("error", ""))} · 룰로 폴백</div>'
            prog = ""
        else:
            s2_color, s2_badge = "var(--faint)", "STANDBY"
            why = ("토글 해제됨." if (HAS_KEY and not use_llm) else "Anthropic 키 미연결.")
            body = (f'<div class="desc">{esc(why)} 대기 중 — 키 연결 + 토글 ON 시, 룰이 놓치는 '
                    '신종·맥락형 공격을 의미 기반으로 포착합니다.</div>')
            prog = ""
        md(
            f"""
            <div class="stage" style="border-color:{s2_color}44">
              <div class="top"><span class="ix">L2</span><span class="nm">LLM / 의미 분석 레이어</span>
                <span class="badge" style="color:{s2_color}">{s2_badge}</span></div>
              {body}{prog}
            </div>
            """
        )

    # 4) 탐지 이벤트 그리드(SIEM) — 인라인 번호와 cross-ref ---------
    md('<div class="seclabel">DETECTION EVENTS · 탐지 이벤트 로그<span class="ln"></span></div>')

    ev_rows = ""
    base = time.strftime("%H:%M:%S")
    # 인라인 <mark> 번호는 '구간 순서(=start 오름차순)'로 매겨진다. 같은 번호로 묶기 위해
    # category→번호 매핑을 spans 순서로 만든다(한 카테고리가 여러 번이면 첫 번호 사용).
    cat_to_num: dict[str, int] = {}
    for i, sp in enumerate(spans, 1):
        cat_to_num.setdefault(sp["category"], i)

    seq = 0
    for h in rule["hits"]:
        code = cat_code(h["category"])
        col = cat_color(h["category"])
        w = h["weight"]
        sev_txt = ("CRIT" if w >= rules.BLOCK_THRESHOLD else "HIGH" if w >= 35 else
                   "MED" if w >= 20 else "LOW")
        sev_col = ("var(--red)" if w >= rules.BLOCK_THRESHOLD else "var(--org)" if w >= 35 else
                   "var(--amb)" if w >= 20 else "var(--faint)")
        snip = esc1(h.get("snippet") or "—")
        num = cat_to_num.get(h["category"])
        num_badge = (f'<span class="gnum" style="background:{col}">{num}</span> '
                     if num is not None else "")
        ev_rows += (
            f'<tr><td>{base}.{seq:02d}</td>'
            f'<td><span class="sev" style="color:{sev_col}">{sev_txt}</span></td>'
            f'<td class="sigc" style="color:{col}">{num_badge}{esc(code)}</td>'
            f'<td style="color:var(--text)">{esc(h["category"])}</td>'
            f'<td><span class="ev">{snip}</span></td>'
            f'<td style="color:var(--text)">+{esc(w)}</td></tr>'
        )
        seq += 1
    if llm and llm.get("ok") and llm.get("is_injection"):
        conf = float(llm["confidence"])
        sev_col = "var(--red)" if conf >= 0.75 else "var(--org)"
        ev_rows += (
            f'<tr><td>{base}.{seq:02d}</td>'
            f'<td><span class="sev" style="color:{sev_col}">LLM</span></td>'
            f'<td class="sigc" style="color:var(--vio)">SEM-LLM</td>'
            f'<td style="color:var(--text)">{esc(llm.get("category") or "인젝션 의심")}</td>'
            f'<td><span class="ev">{esc1(llm.get("reason", ""))[:80]}</span></td>'
            f'<td style="color:var(--text)">{conf:.0%}</td></tr>'
        )
        seq += 1
    if not ev_rows:
        ev_rows = ('<tr><td colspan="6" style="color:var(--faint);text-align:center;padding:18px">'
                   '탐지 이벤트 없음 — 위험 신호가 발견되지 않았습니다 (정상 트래픽).</td></tr>')

    md(
        f"""
        <table class="grid">
          <thead><tr>
            <th>TIME</th><th>SEV</th><th>SIG&nbsp;ID</th><th>CATEGORY · 분류</th>
            <th>EVIDENCE · 근거</th><th>SCORE</th>
          </tr></thead>
          <tbody>{ev_rows}</tbody>
        </table>
        """
    )

    # 5) 결정 레이어 종합 근거 -------------------------------------
    reasons_html = "".join(
        f'<div class="logline info" style="animation:none"><span class="mk">›</span>'
        f'<span class="tx">{esc1(r)}</span></div>'
        for r in result["reasons"]
    )
    md(
        f"""
        <div class="seclabel">DECISION RATIONALE · 결정 레이어 근거<span class="ln"></span></div>
        <div class="console"><div class="logbody" style="max-height:none">{reasons_html}</div></div>
        """
    )

elif should_eval:
    md(
        '<div class="note">⌀ 입력 스트림이 비어 있습니다. 왼쪽 <b>ATTACK SAMPLES</b> 패널에서 '
        '위협을 주입하거나, 직접 payload를 붙여넣고 <b>THREAT SCAN</b>을 실행하세요.</div>'
    )


# ════════════════════════════════════════════════════════════════════
#  다층 방어 설명(접이식)
# ════════════════════════════════════════════════════════════════════
with st.expander("◆ 왜 ‘다층 방어(Defense-in-Depth)’인가?"):
    st.markdown(
        "- **L1 · 룰 레이어**: 빠르고 무료·오프라인. 알려진 공격·인코딩(base64) 우회를 즉시 차단하지만 "
        "신종·맥락형 공격은 놓칠 수 있습니다.\n"
        "- **L2 · LLM 레이어**: 신종·우회 공격을 의미 기반으로 잡지만 느리고 비용이 들며, "
        "**분류기 자신이 인젝션 표적**이 됩니다. 그래서 입력을 ‘데이터’로만 다루도록 방어적으로 프롬프트합니다.\n"
        "- **결정 레이어**: 두 레이어 중 하나라도 강하게 가리키면 위로 승급(escalate). "
        "한 겹이 뚫려도 다른 겹이 받칩니다 — 이게 다층 방어의 핵심입니다.\n\n"
        f"> 현재 엔진: 룰 시그니처 {SIG_DB_COUNT}종 · 임계값 FLAG≥{rules.FLAG_THRESHOLD} / "
        f"BLOCK≥{rules.BLOCK_THRESHOLD} · base64 디코드 재검사 · 제로폭 난독화 탐지."
    )

md(
    '<div class="foot">PROMPT INJECTION GUARD · RULE + CLAUDE 다층 방어 ENGINE · '
    'GENAI SECURITY 포트폴리오 데모</div>'
)
