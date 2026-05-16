"""Pure-stdlib arithmetic helpers replacing numpy in security detectors."""
import math


def _mean(xs) -> float:
    return sum(xs) / len(xs)


def _std(xs) -> float:
    m = _mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs))


def _norm(v) -> float:
    return math.sqrt(sum(x * x for x in v))


def _dot(a, b) -> float:
    return sum(x * y for x, y in zip(a, b))
