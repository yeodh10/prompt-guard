"""
평가 하니스 — 룰 단독 / 룰+LLM 의 탐지 성능(재현율·오탐률 등)을 측정한다.

- 룰 레이어는 **키 없이** 측정 가능.
- LLM 레이어 실측은 ANTHROPIC_API_KEY가 있어야 한다(없으면 자동으로 룰 단독만 측정).

판정→정오 기준:
  positive(=공격으로 판정)을 두 가지로 본다.
  - lenient: 차단 또는 검토 → '잡음'으로 인정 (탐지 관점)
  - strict : 차단만 → '잡음'으로 인정 (실제 차단 관점)

실행:
  python evaluate.py            # 룰 단독 측정(키 불필요)
  python evaluate.py --llm      # 룰+LLM 측정(키 필요)
  python evaluate.py --json     # 지표를 JSON으로도 출력
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict

import eval_dataset

_POSITIVE_STRICT = {"차단"}
_POSITIVE_LENIENT = {"차단", "검토"}


def _is_positive(decision: str, mode: str) -> bool:
    return decision in (_POSITIVE_STRICT if mode == "strict" else _POSITIVE_LENIENT)


def score(rows: list[dict], mode: str = "lenient") -> dict:
    """rows: [{"label","technique","decision"}] → 지표 dict.

    positive='공격으로 판정'. 공격을 positive로 맞히면 TP, 정상을 positive로 보면 FP(오탐).
    """
    tp = fp = tn = fn = 0
    for r in rows:
        pred_pos = _is_positive(r["decision"], mode)
        actual_pos = r["label"] == "attack"
        if actual_pos and pred_pos:
            tp += 1
        elif actual_pos and not pred_pos:
            fn += 1
        elif (not actual_pos) and pred_pos:
            fp += 1
        else:
            tn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0       # 공격 탐지율
    fpr = fp / (fp + tn) if (fp + tn) else 0.0          # 정상 오탐률
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    acc = (tp + tn) / len(rows) if rows else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "recall": recall, "fpr": fpr, "precision": precision, "f1": f1, "accuracy": acc,
        "n_attack": tp + fn, "n_benign": fp + tn,
    }


def recall_by_technique(rows: list[dict], mode: str = "lenient") -> dict:
    """공격 항목만 대상으로 기법별 (탐지수, 전체수)."""
    agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["label"] != "attack":
            continue
        agg[r["technique"]][1] += 1
        if _is_positive(r["decision"], mode):
            agg[r["technique"]][0] += 1
    return {t: (c, n) for t, (c, n) in agg.items()}


def run(dataset: list[dict], use_llm: bool = False, evaluate_fn=None) -> list[dict]:
    """데이터셋 각 항목을 guard로 평가해 rows를 만든다.

    evaluate_fn 주입 가능(테스트용). 기본은 guard.evaluate.
    """
    if evaluate_fn is None:
        import guard
        evaluate_fn = guard.evaluate
    rows = []
    for item in dataset:
        res = evaluate_fn(item["text"], use_llm=use_llm)
        rows.append({
            "id": item["id"], "label": item["label"], "technique": item["technique"],
            "decision": res["decision"], "risk": res.get("risk", 0),
        })
    return rows


def format_report(rows: list[dict], layer_label: str, mode: str = "lenient") -> tuple[str, dict]:
    m = score(rows, mode)
    L = [f"\n=== {layer_label} · {mode} ==="]
    L.append(f"공격 {m['n_attack']}건 · 정상 {m['n_benign']}건")
    L.append(f"탐지율(recall) {m['recall']:.0%}  |  오탐률(FPR) {m['fpr']:.0%}  |  "
             f"정밀도 {m['precision']:.0%}  |  F1 {m['f1']:.2f}  |  정확도 {m['accuracy']:.0%}")
    L.append(f"TP {m['tp']} · FN {m['fn']}(놓친 공격) · FP {m['fp']}(오탐) · TN {m['tn']}")
    L.append("기법별 탐지율:")
    for t, (c, n) in sorted(recall_by_technique(rows, mode).items()):
        L.append(f"  - {t}: {c}/{n}")
    missed = [r["id"] for r in rows if r["label"] == "attack" and not _is_positive(r["decision"], mode)]
    fps = [r["id"] for r in rows if r["label"] == "benign" and _is_positive(r["decision"], mode)]
    if missed:
        L.append("놓친 공격: " + ", ".join(missed))
    if fps:
        L.append("오탐(정상→공격판정): " + ", ".join(fps))
    return "\n".join(L), m


def main() -> None:
    ap = argparse.ArgumentParser(description="prompt-guard 탐지 성능 평가")
    ap.add_argument("--llm", action="store_true", help="LLM 레이어 포함(키 필요)")
    ap.add_argument("--json", action="store_true", help="지표를 JSON으로도 출력")
    args = ap.parse_args()

    import config
    dataset = eval_dataset.all_labeled()

    use_llm = args.llm
    if use_llm and not config.has_anthropic_key():
        print("⚠️  ANTHROPIC_API_KEY가 없어 LLM 레이어를 건너뜁니다(룰 단독만 측정).")
        use_llm = False

    layer_label = "룰+LLM" if use_llm else "룰 단독"
    rows = run(dataset, use_llm=use_llm)

    rep_len, m_len = format_report(rows, layer_label, "lenient")
    rep_str, m_str = format_report(rows, layer_label, "strict")
    print(rep_len)
    print(rep_str)

    if not use_llm:
        print("\nℹ️  LLM 레이어 실측: 키를 설정하고 `python evaluate.py --llm` 으로 측정하세요.")

    if args.json:
        print("\n" + json.dumps(
            {"layer": layer_label, "lenient": m_len, "strict": m_str, "rows": rows},
            ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
