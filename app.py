"""
프롬프트 인젝션 가드 — LLM 입력 방어 데모 (Streamlit).

다층 방어(룰 + LLM)로 사용자 입력의 인젝션·탈옥 시도를 탐지·차단한다.
룰 레이어는 키 없이도 동작하므로 배포 데모에서 공격이 실제로 막히는 장면을 보여 준다.

실행:  streamlit run app.py
"""

from __future__ import annotations

import html

import streamlit as st

import config
import guard
import rules
import samples

config.reload_runtime_keys()

st.set_page_config(page_title="프롬프트 인젝션 가드", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

st.markdown(
    """
    <style>
      @import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/static/pretendard.min.css');
      :root{
        --bg:#08090C; --surface:#121419; --surface-2:#15181F;
        --line:rgba(255,255,255,.07); --line-2:rgba(255,255,255,.13);
        --text:#F4F6FA; --muted:#9AA3B2; --faint:#646C78;
        --accent:#3DDC97; --accent-2:#5AA2FF; --danger:#FF5C7A; --warn:#F5B14C;
        --radius:18px;
      }
      html, body, [class*="css"], .stMarkdown, .stApp{
        font-family:'Pretendard',-apple-system,BlinkMacSystemFont,sans-serif;
        -webkit-font-smoothing:antialiased;
      }
      .stApp{
        background:
          radial-gradient(1100px 560px at 50% -240px, rgba(90,162,255,.10), transparent 60%),
          radial-gradient(820px 460px at 100% -40px, rgba(61,220,151,.06), transparent 55%),
          var(--bg);
      }
      .block-container{ padding-top:2.4rem; padding-bottom:5rem; max-width:1060px; }
      #MainMenu, footer, header[data-testid="stHeader"]{ display:none; }
      @keyframes rise{ from{opacity:0; transform:translateY(14px);} to{opacity:1; transform:none;} }

      .hero{ margin:2px 0 22px; padding:36px 40px 30px; border-radius:24px; border:1px solid var(--line);
        background:linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.012));
        box-shadow:0 22px 64px rgba(0,0,0,.5); animation:rise .5s ease both; }
      .hero h1{ margin:0 0 8px; font-size:31px; font-weight:800; letter-spacing:-.02em; color:var(--text); }
      .hero p{ margin:0; font-size:15px; line-height:1.6; color:var(--muted); max-width:740px; }
      .hero .eyebrow{ display:inline-block; margin-bottom:12px; padding:5px 12px; border-radius:999px;
        font-size:12px; font-weight:700; color:var(--accent-2);
        background:rgba(90,162,255,.10); border:1px solid rgba(90,162,255,.25); }

      .verdict{ padding:22px 24px; border-radius:var(--radius); border:1px solid var(--line);
        background:var(--surface); margin:4px 0 14px; animation:rise .4s ease both; }
      .verdict .badge{ font-size:24px; font-weight:800; }
      .gauge{ height:12px; border-radius:8px; background:var(--surface-2); overflow:hidden; margin:12px 0 4px; }
      .gauge > span{ display:block; height:100%; border-radius:8px; }
      .lab{ font-size:12px; color:var(--faint); }

      .panel{ padding:16px 18px; border-radius:var(--radius); border:1px solid var(--line);
        background:var(--surface); height:100%; }
      .panel h4{ margin:0 0 10px; font-size:14px; color:var(--text); font-weight:800; }
      .hit{ font-size:13px; line-height:1.5; color:var(--text); padding:8px 11px; margin-bottom:7px;
        border-radius:10px; background:var(--surface-2); border:1px solid var(--line); }
      .hit .cat{ font-weight:700; color:var(--danger); }
      .hit .snip{ font-family:ui-monospace,Consolas,monospace; font-size:11.5px; color:var(--faint); }
      .chip{ display:inline-block; font-size:11.5px; font-weight:700; padding:3px 9px; margin:2px 4px 2px 0;
        border-radius:8px; color:var(--accent-2); background:rgba(90,162,255,.10); border:1px solid rgba(90,162,255,.22); }
      .muted{ font-size:12.5px; color:var(--faint); font-style:italic; }
      .reason{ font-size:13px; line-height:1.55; color:var(--muted); padding:3px 0; }
    </style>
    """,
    unsafe_allow_html=True,
)


def esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


if "text" not in st.session_state:
    st.session_state.text = samples.ATTACKS[0]["text"]
if "auto" not in st.session_state:
    st.session_state.auto = True


def load_sample(t: str):
    st.session_state.text = t
    st.session_state.auto = True


# ── 사이드바 ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ 설정")
    use_llm = st.toggle("LLM 레이어(2차) 사용", value=True,
                        help="Anthropic 키가 있을 때만 동작. 룰 레이어(1차)는 항상 켜짐.")
    key_state = "있음 ✅" if config.has_anthropic_key() else "없음 — 룰 레이어만"
    st.caption(f"Anthropic 키: {key_state}")

    st.markdown("---")
    st.markdown("### 🧪 공격 샘플")
    st.caption("클릭하면 입력에 넣고 즉시 검사합니다.")
    for s in samples.ATTACKS:
        st.button("🔴 " + s["title"], key="atk_" + s["id"], use_container_width=True,
                  on_click=load_sample, args=(s["text"],))
    st.markdown("### 🟢 정상 샘플")
    for s in samples.BENIGN:
        st.button("🟢 " + s["title"], key="bn_" + s["id"], use_container_width=True,
                  on_click=load_sample, args=(s["text"],))


# ── 헤더 ───────────────────────────────────────────────────────
st.markdown(
    """
    <div class="hero">
      <span class="eyebrow">GENAI SECURITY · 다층 방어 데모</span>
      <h1>🛡️ 프롬프트 인젝션 가드</h1>
      <p>LLM에 들어오는 사용자 입력에서 <b>인젝션·탈옥</b> 시도를 탐지·차단합니다.
      <b>룰 레이어</b>(빠르고 무료, 알려진 공격·인코딩 우회)와 <b>LLM 레이어</b>(신종·맥락형 공격)를
      겹친 <b>다층 방어</b> — 한 겹으로는 막을 수 없기 때문입니다.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

text = st.text_area("검사할 입력", key="text", height=140,
                    label_visibility="collapsed", placeholder="LLM에 전달될 사용자 입력을 붙여넣으세요…")
run = st.button("🛡️ 검사하기", type="primary")

should_eval = run or st.session_state.auto
st.session_state.auto = False

if should_eval and text.strip():
    result = guard.evaluate(text, use_llm=use_llm)
    emoji, color = guard.DECISION_META[result["decision"]]
    risk = result["risk"]

    # 판정 + 위험 게이지
    st.markdown(
        f"""
        <div class="verdict" style="border-color:{color}66">
          <span class="badge" style="color:{color}">{emoji} {esc(result['decision'])}</span>
          <span class="lab" style="margin-left:10px">위험도 {risk}/100 ·
            룰 {'●' if result['layers']['rule'] else '○'} / LLM {'●' if result['layers']['llm'] else '○'}</span>
          <div class="gauge"><span style="width:{risk}%; background:{color}"></span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    # 1차: 룰 레이어
    with col1:
        rule = result["rule"]
        hits_html = ""
        for h in rule["hits"]:
            snip = f'<div class="snip">{esc(h["snippet"])}</div>' if h.get("snippet") else ""
            hits_html += (f'<div class="hit"><span class="cat">{esc(h["category"])}</span> '
                          f'· {esc(h["desc"])} <span class="lab">(+{h["weight"]})</span>{snip}</div>')
        if not hits_html:
            hits_html = '<div class="muted">탐지된 룰 시그니처 없음</div>'
        sig = rule["signals"]
        extra = []
        if sig["encoded"]:
            extra.append("base64 인코딩 우회 감지")
        if sig["zero_width"]:
            extra.append("제로폭 문자(난독화) 감지")
        extra_html = (f'<div class="reason">⚑ {esc(" · ".join(extra))}</div>' if extra else "")
        st.markdown(
            f'<div class="panel"><h4>1차 · 룰 레이어 (점수 {rule["score"]})</h4>{hits_html}{extra_html}</div>',
            unsafe_allow_html=True,
        )
    # 2차: LLM 레이어
    with col2:
        llm = result["llm"]
        if llm and llm.get("ok"):
            inj = llm["is_injection"]
            head = "인젝션 의심" if inj else "정상 판정"
            hc = "var(--danger)" if inj else "var(--accent)"
            techs = "".join(f'<span class="chip">{esc(t)}</span>' for t in llm.get("techniques", []))
            body = (f'<div class="hit"><span style="color:{hc};font-weight:700">{esc(llm.get("category") or head)}</span> '
                    f'<span class="lab">(확신 {llm["confidence"]:.0%})</span>'
                    f'<div class="reason">{esc(llm.get("reason",""))}</div>{techs}</div>')
        elif llm and not llm.get("ok"):
            body = f'<div class="muted">분류 불가: {esc(llm.get("error",""))}</div>'
        else:
            body = ('<div class="muted">LLM 레이어 비활성. Anthropic 키를 넣고 토글을 켜면 '
                    '룰이 놓치는 신종·맥락형 공격까지 잡습니다.</div>')
        st.markdown(f'<div class="panel"><h4>2차 · LLM 레이어</h4>{body}</div>', unsafe_allow_html=True)

    # 종합 근거
    reasons_html = "".join(f'<div class="reason">• {esc(r)}</div>' for r in result["reasons"])
    st.markdown(f'<div class="panel" style="margin-top:14px"><h4>판정 근거</h4>{reasons_html}</div>',
                unsafe_allow_html=True)

elif should_eval:
    st.info("검사할 입력을 넣어 주세요. (왼쪽 샘플 버튼을 눌러도 됩니다)")

with st.expander("ℹ️ 왜 ‘다층 방어’인가?"):
    st.markdown(
        "- **룰 레이어(1차)**: 빠르고 무료, 오프라인. 알려진 공격·인코딩(base64) 우회를 즉시 차단하지만 "
        "신종·맥락형 공격은 놓칠 수 있습니다.\n"
        "- **LLM 레이어(2차)**: 신종·우회 공격을 의미 기반으로 잡지만 느리고 비용이 들며, "
        "**분류기 자신이 인젝션 표적**이 됩니다. 그래서 입력을 ‘데이터’로만 다루도록 방어적으로 프롬프트합니다.\n"
        "- **결정 레이어**: 두 레이어 중 하나라도 강하게 가리키면 위로 승급(escalate). "
        "한 겹이 뚫려도 다른 겹이 받칩니다 — 이게 다층 방어의 핵심입니다."
    )

st.markdown(
    '<p style="text-align:center;color:#646C78;font-size:12px;margin-top:26px">'
    '프롬프트 인젝션 가드 · 룰 + Claude 다층 방어 · 포트폴리오 데모</p>',
    unsafe_allow_html=True,
)
