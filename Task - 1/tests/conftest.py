"""Provide Scapy import stubs for tests that do not require live capture."""

import importlib.util
import sys
import types
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = TASK_ROOT / "source-code"
sys.path.insert(0, str(SOURCE_DIR))

if importlib.util.find_spec("scapy") is None:
    scapy_module = types.ModuleType("scapy")
    all_module = types.ModuleType("scapy.all")

    for name in ("ARP", "DNS", "DNSQR", "Ether", "ICMP", "IP", "TCP", "UDP"):
        setattr(all_module, name, type(name, (), {}))

    def _sniff_stub(**_kwargs):
        return None

    all_module.sniff = _sniff_stub
    scapy_module.all = all_module
    sys.modules["scapy"] = scapy_module
    sys.modules["scapy.all"] = all_module
