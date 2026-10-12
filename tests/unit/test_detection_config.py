"""Validated settings for the failed-login rule."""

from dataclasses import replace
from datetime import timedelta

import pytest

from threatlens.config import DetectionConfig


def test_defaults() -> None:
    config = DetectionConfig()
    assert config.lookback == timedelta(minutes=10)
    assert (config.medium_threshold, config.medium_window) == (5, timedelta(minutes=2))
    assert (config.high_threshold, config.high_window) == (10, timedelta(minutes=5))
    assert config.cooldown == timedelta(minutes=10)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lookback", timedelta(0)),
        ("lookback", timedelta(hours=25)),
        ("medium_window", timedelta(seconds=-1)),
        ("high_window", timedelta(minutes=1)),
        ("high_window", timedelta(hours=25)),
        ("cooldown", timedelta(minutes=4)),
        ("medium_threshold", 0),
        ("medium_threshold", True),
        ("high_threshold", 5),
    ],
)
def test_inconsistent_settings_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        replace(DetectionConfig(), **{field: value})  # type: ignore[arg-type]


def test_maximum_lookback_and_custom_thresholds_are_valid() -> None:
    config = DetectionConfig(
        lookback=timedelta(hours=24), medium_threshold=3, high_threshold=6
    )
    assert config.medium_threshold == 3
