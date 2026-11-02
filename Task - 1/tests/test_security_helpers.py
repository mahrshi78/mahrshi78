"""Focused tests for security hardening helpers."""

from collections import Counter

import pytest

from packet_analyzer import (
    DEFAULT_CAPTURE_DURATION,
    DEFAULT_PACKET_LIMIT,
    MAX_DISPLAY_TEXT,
    OTHER_ADDRESS_BUCKET,
    PacketAnalyzer,
    increment_bounded,
    safe_terminal_text,
)


def test_terminal_control_characters_are_removed():
    value = "safe\n\x1b[31mred\x7f"
    result = safe_terminal_text(value)
    assert "\n" not in result
    assert "\x1b" not in result
    assert "\x7f" not in result
    assert result == "safe??[31mred?"


def test_terminal_text_is_length_limited():
    result = safe_terminal_text("x" * (MAX_DISPLAY_TEXT + 20))
    assert len(result) == MAX_DISPLAY_TEXT
    assert result.endswith("...")


def test_address_counter_has_a_fixed_key_budget():
    counts = Counter()
    for number in range(10):
        increment_bounded(counts, f"192.0.2.{number}", limit=3)
    assert counts["192.0.2.0"] == 1
    assert counts["192.0.2.1"] == 1
    assert counts["192.0.2.2"] == 1
    assert counts[OTHER_ADDRESS_BUCKET] == 7
    assert len(counts) == 4


def test_packet_capture_defaults_are_bounded():
    assert DEFAULT_PACKET_LIMIT == 1000
    assert DEFAULT_CAPTURE_DURATION == 30


def test_zero_packet_limit_is_rejected():
    with pytest.raises(ValueError, match="positive integer"):
        PacketAnalyzer(packet_limit=0)


def test_capture_duration_has_a_finite_upper_bound():
    with pytest.raises(ValueError, match="between 1 and 3600"):
        PacketAnalyzer(capture_duration=3601)


def test_run_passes_packet_and_time_limits_to_scapy(monkeypatch):
    captured_options = {}

    def fake_sniff(**kwargs):
        captured_options.update(kwargs)

    monkeypatch.setattr("packet_analyzer.sniff", fake_sniff)
    analyzer = PacketAnalyzer(packet_limit=7, capture_duration=5)
    analyzer.run()

    assert captured_options["count"] == 7
    assert captured_options["timeout"] == 5
    assert captured_options["store"] is False
