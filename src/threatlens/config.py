"""Bounded, validated settings for the v0.1 detection rule."""

from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    lookback: timedelta = timedelta(minutes=10)
    medium_threshold: int = 5
    medium_window: timedelta = timedelta(minutes=2)
    high_threshold: int = 10
    high_window: timedelta = timedelta(minutes=5)
    cooldown: timedelta = timedelta(minutes=10)

    def __post_init__(self) -> None:
        for name in ("lookback", "medium_window", "high_window", "cooldown"):
            value = getattr(self, name)
            if not isinstance(value, timedelta) or not timedelta(
                0
            ) < value <= timedelta(hours=24):
                raise ValueError(f"{name} must be positive and no longer than 24 hours")
        for name in ("medium_threshold", "high_threshold"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.high_threshold <= self.medium_threshold:
            raise ValueError("high_threshold must be greater than medium_threshold")
        if self.high_window < self.medium_window:
            raise ValueError("high_window must not be shorter than medium_window")
        if self.cooldown < self.high_window:
            raise ValueError("cooldown must not be shorter than high_window")
