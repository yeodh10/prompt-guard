"""
환경설정 로더. .env / Streamlit secrets / 기본값을 한 곳에서 관리한다.
(형제 프로젝트 cve-radar·security-sales-agent의 config 패턴을 따른다.)
"""

import os
import sys

from dotenv import load_dotenv

load_dotenv()

# Windows 콘솔 한글 깨짐 방지
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def _from_secrets(name: str):
    """Streamlit Cloud 배포 시 st.secrets에서 값을 읽는다(로컬 CLI에는 영향 없음)."""
    try:
        import streamlit as st

        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        return None
    return None


def _get(name: str, default: str = "") -> str:
    """우선순위: 환경변수(.env) → Streamlit secrets → 기본값."""
    value = os.getenv(name)
    if not value:
        value = _from_secrets(name)
    return (value if value is not None else default).strip()


ANTHROPIC_API_KEY = _get("ANTHROPIC_API_KEY", "")
# 분류기는 빠르고 저렴한 모델이 적합하다. 기본은 형제 프로젝트와 맞춰 두되 .env로 교체 가능.
# (예: ANTHROPIC_MODEL=claude-haiku-4-5 로 더 빠르고 싸게)
ANTHROPIC_MODEL = _get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

ANTHROPIC_MAX_RETRIES = int(os.getenv("ANTHROPIC_MAX_RETRIES", "3"))
ANTHROPIC_TIMEOUT = float(os.getenv("ANTHROPIC_TIMEOUT", "30"))


def _is_placeholder(value: str) -> bool:
    return (not value) or ("여기에" in value) or ("YOUR_" in value)


def has_anthropic_key() -> bool:
    return not _is_placeholder(ANTHROPIC_API_KEY)


def require_anthropic_key() -> str:
    if not has_anthropic_key():
        raise RuntimeError(
            "ANTHROPIC_API_KEY가 설정되지 않았습니다. .env에 실제 키를 입력해 주세요.\n"
            "발급: https://console.anthropic.com"
        )
    return ANTHROPIC_API_KEY


def make_anthropic_client():
    from anthropic import Anthropic

    return Anthropic(
        api_key=require_anthropic_key(),
        max_retries=ANTHROPIC_MAX_RETRIES,
        timeout=ANTHROPIC_TIMEOUT,
    )


def reload_runtime_keys() -> None:
    """배포(Streamlit Secrets) 환경에서 런타임에 키를 다시 읽어 전역을 최신화."""
    global ANTHROPIC_API_KEY, ANTHROPIC_MODEL
    ANTHROPIC_API_KEY = _get("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = _get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
