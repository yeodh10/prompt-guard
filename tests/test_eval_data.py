"""블라인드 묶음 자료와 측정 함수를 잠근다. 키와 네트워크가 필요 없다."""

import re

import eval_dataset
import evaluate
import guard


def test_batch_sizes():
    sizes = {name: len(eval_dataset.blind_lines(f)) for name, f, _ in eval_dataset.BLIND_BATCHES}
    assert sizes == {"1차 공격": 92, "1차 정상": 82, "2차 공격": 80, "2차 정상": 80}


def test_lines_keep_line_breaks():
    lines = eval_dataset.blind_lines("attacks1.txt")
    assert any("\n" in line for line in lines) and not any("\\n" in line for line in lines)


def test_no_phone_numbers_in_public_data():
    phone = re.compile(r"0\d{1,2}-\d{3,4}-\d{4}")
    files = [f for _, f, _ in eval_dataset.BLIND_BATCHES] + ["carriers.txt"]
    for name in files:
        assert not phone.search((eval_dataset.DATA_DIR / name).read_text(encoding="utf-8")), name


def test_carriers_are_plain_documents():
    bodies = eval_dataset.carriers()
    assert len(bodies) == 5
    for body in bodies:
        assert guard.evaluate(body, use_llm=False, document=True)["decision"] == "허용"


def test_inject_puts_line_in_the_middle_between_lines():
    bodies = ["첫 줄\n둘째 줄\n셋째 줄\n넷째 줄"]
    text = eval_dataset.inject("시험 문장", 0, bodies)
    lines = text.split("\n")
    assert "시험 문장" in lines and lines[0] == "첫 줄" and lines[-1] == "넷째 줄"


def test_run_blind_counts_with_fake_guard():
    calls = []

    def fake(text, use_llm=False, document=False):
        assert document is True
        calls.append(use_llm)
        return {"decision": "허용", "reasons": [], "llm": {"ok": True} if use_llm else None}

    rows = evaluate.run_blind(use_llm=True, max_calls=3, workers=1, evaluate_fn=fake)
    assert sum(calls) == 3
    assert sum(r["llm"] == "상한 초과" for r in rows) == len(rows) - 3
    assert "1차 공격" in evaluate.format_blind(rows)


def test_run_blind_skips_llm_when_rule_blocks():
    def fake(text, use_llm=False, document=False):
        assert not use_llm, "규칙이 막은 글을 LLM에 다시 묻지 않는다"
        return {"decision": "차단", "reasons": [], "llm": None}

    rows = evaluate.run_blind(use_llm=True, max_calls=10, workers=1, evaluate_fn=fake)
    assert all(r["llm"] == "안 씀" for r in rows)
