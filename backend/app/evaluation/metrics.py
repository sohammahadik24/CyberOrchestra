"""Deterministic metric primitives used by the evaluation framework."""

from enum import Enum
from typing import Iterable, List, Optional, Sequence, Set

from pydantic import BaseModel, ConfigDict


class MetricStatus(str, Enum):
    CALCULATED = "calculated"
    NO_GROUND_TRUTH = "no_ground_truth"
    NO_PREDICTIONS = "no_predictions"
    NOT_APPLICABLE = "not_applicable"


class MetricResult(BaseModel):
    """Calculated metric, distinct from the dataset's ground-truth labels."""

    value: Optional[float]
    numerator: int
    denominator: int
    status: MetricStatus
    definition: str

    model_config = ConfigDict(extra="forbid")


def ratio_metric(numerator: int, denominator: int, definition: str) -> MetricResult:
    if denominator <= 0:
        return MetricResult(
            value=None, numerator=0, denominator=0,
            status=MetricStatus.NO_GROUND_TRUTH, definition=definition,
        )
    return MetricResult(
        value=numerator / denominator,
        numerator=numerator,
        denominator=denominator,
        status=MetricStatus.CALCULATED,
        definition=definition,
    )


def accuracy_metric(expected: Sequence, predicted: Sequence, definition: str) -> MetricResult:
    if not expected:
        return ratio_metric(0, 0, definition)
    correct = sum(1 for truth, guess in zip(expected, predicted) if guess is not None and truth == guess)
    return ratio_metric(correct, len(expected), definition)


def exact_set_metric(expected: Sequence[Set[str]], predicted: Sequence[Optional[Set[str]]], definition: str) -> MetricResult:
    if not expected:
        return ratio_metric(0, 0, definition)
    correct = sum(1 for truth, guess in zip(expected, predicted) if guess is not None and truth == guess)
    return ratio_metric(correct, len(expected), definition)


def binary_classification_metrics(expected_positive: Sequence[bool], predicted_positive: Sequence[Optional[bool]]):
    """Return precision, recall and F1; missing/invalid predictions count as negative."""
    tp = fp = fn = 0
    for truth, prediction in zip(expected_positive, predicted_positive):
        prediction = bool(prediction) if prediction is not None else False
        if prediction and truth:
            tp += 1
        elif prediction and not truth:
            fp += 1
        elif truth and not prediction:
            fn += 1
    precision = ratio_metric(tp, tp + fp, "TP / (TP + FP)")
    recall = ratio_metric(tp, tp + fn, "TP / (TP + FN)")
    f1_denominator = 2 * tp + fp + fn
    f1 = ratio_metric(2 * tp, f1_denominator, "2*TP / (2*TP + FP + FN)")
    return precision, recall, f1


def grounding_metric(cited: Sequence[str], valid_evidence_ids: Set[str]) -> MetricResult:
    valid = sum(1 for evidence_id in cited if evidence_id in valid_evidence_ids)
    return ratio_metric(valid, len(cited), "Supplied evidence citations / all evidence citations")


def not_applicable_metric(definition: str) -> MetricResult:
    return MetricResult(value=None, numerator=0, denominator=0, status=MetricStatus.NOT_APPLICABLE, definition=definition)
