from pathlib import Path
import re


def test_custom_rules_have_four_unique_sids_and_alert_only_actions():
    path = Path(__file__).resolve().parents[1] / "suricata" / "local.rules"
    rules = [
        line.strip() for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith(("alert ", "drop ", "reject "))
    ]
    assert len(rules) == 4
    assert all(rule.startswith("alert ") for rule in rules)
    sids = [re.search(r"sid:(\d+);", rule).group(1) for rule in rules]
    assert len(set(sids)) == 4
    assert all("threshold:" in rule for rule in rules)


def test_custom_rule_sids_use_local_range():
    path = Path(__file__).resolve().parents[1] / "suricata" / "local.rules"
    text = path.read_text(encoding="utf-8")
    sids = [int(value) for value in re.findall(r"sid:(\d+);", text)]
    assert all(9000000 <= sid < 10000000 for sid in sids)
