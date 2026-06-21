"""
evaluate 하니스 + 데이터셋 단위 테스트 (키·네트워크 불필요).

채점 함수는 순수 로직이라 합성 rows로 검증하고, run()은 가짜 evaluate_fn을 주입해 확인한다.
실행: python -m pytest tests/test_evaluate.py -q  (또는 python tests/test_evaluate.py)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evaluate
import eval_dataset


# ── 채점 ──────────────────────────────────────────────────────
def test_score_perfect():
    rows = [
        {"label": "attack", "technique": "t", "decision": "차단"},
        {"label": "benign", "technique": "t", "decision": "허용"},
    ]
    m = evaluate.score(rows, "strict")
    assert m["recall"] == 1.0 and m["fpr"] == 0.0
    assert m["tp"] == 1 and m["tn"] == 1 and m["fp"] == 0 and m["fn"] == 0


def test_score_lenient_vs_strict():
    # '검토'는 lenient에선 탐지, strict에선 미탐
    rows = [{"label": "attack", "technique": "t", "decision": "검토"}]
    assert evaluate.score(rows, "lenient")["recall"] == 1.0
    assert evaluate.score(rows, "strict")["recall"] == 0.0


def test_score_false_positive():
    rows = [{"label": "benign", "technique": "t", "decision": "차단"}]
    m = evaluate.score(rows, "strict")
    assert m["fp"] == 1 and m["fpr"] == 1.0 and m["precision"] == 0.0


def test_score_counts_and_f1():
    rows = [
        {"label": "attack", "technique": "a", "decision": "차단"},   # TP
        {"label": "attack", "technique": "a", "decision": "허용"},   # FN
        {"label": "benign", "technique": "b", "decision": "허용"},   # TN
        {"label": "benign", "technique": "b", "decision": "차단"},   # FP
    ]
    m = evaluate.score(rows, "strict")
    assert (m["tp"], m["fn"], m["tn"], m["fp"]) == (1, 1, 1, 1)
    assert abs(m["recall"] - 0.5) < 1e-9
    assert abs(m["precision"] - 0.5) < 1e-9
    assert abs(m["f1"] - 0.5) < 1e-9


def test_recall_by_technique():
    rows = [
        {"label": "attack", "technique": "인코딩", "decision": "차단"},
        {"label": "attack", "technique": "인코딩", "decision": "허용"},
        {"label": "attack", "technique": "역할극", "decision": "검토"},
        {"label": "benign", "technique": "x", "decision": "허용"},  # 무시(공격 아님)
    ]
    by = evaluate.recall_by_technique(rows, "lenient")
    assert by["인코딩"] == (1, 2)
    assert by["역할극"] == (1, 1)
    assert "x" not in by


# ── run() — 가짜 evaluate_fn 주입 ─────────────────────────────
def test_run_with_fake_fn():
    # '공격' 텍스트면 차단, 아니면 허용으로 답하는 가짜 평가기
    def fake(text, use_llm=False):
        return {"decision": "차단" if "ATTACK" in text else "허용", "risk": 0}

    ds = [
        {"id": "a1", "label": "attack", "technique": "t", "text": "ATTACK here"},
        {"id": "b1", "label": "benign", "technique": "t", "text": "hello"},
    ]
    rows = evaluate.run(ds, use_llm=False, evaluate_fn=fake)
    assert rows[0]["decision"] == "차단" and rows[1]["decision"] == "허용"
    m = evaluate.score(rows, "strict")
    assert m["recall"] == 1.0 and m["fpr"] == 0.0


# ── 데이터셋 위생 ─────────────────────────────────────────────
def test_dataset_wellformed():
    items = eval_dataset.all_labeled()
    ids = [it["id"] for it in items]
    assert len(ids) == len(set(ids)), "id 중복 없음"
    for it in items:
        assert it["label"] in ("attack", "benign")
        assert it["technique"] and it["text"].strip()
    labels = {it["label"] for it in items}
    assert {"attack", "benign"} <= labels
    n_atk = sum(1 for it in items if it["label"] == "attack")
    n_bn = sum(1 for it in items if it["label"] == "benign")
    assert n_atk >= 15 and n_bn >= 10  # 측정에 의미 있는 최소 규모


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    p = 0
    for fn in fns:
        try:
            fn(); print("PASS", fn.__name__); p += 1
        except Exception:
            print("FAIL", fn.__name__); traceback.print_exc()
    print(f"\n{p}/{len(fns)} passed")
