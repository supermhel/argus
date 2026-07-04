"""v0.3 new-rule firing tests: password-spray + priv-grant.

Loads the REAL rule YAMLs and feeds them events shaped exactly as the REAL
parsers (linux_ssh, windows_eventlog) emit -- not hand-waved synthetic shapes --
so a pass here means the rule can actually fire in production, not just in a
unit test with convenient fixtures. Zero infra (default in-process deque).

Run: C:/Python313/python.exe services/ws4-detection/test_v03_new_rules.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws2-normalization"))

from engine import load_rules  # noqa: E402
from parsers.linux_ssh import LinuxSshParser  # noqa: E402
from parsers.windows_eventlog import WindowsEventLogParser  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def rule_by_id(rules, rid):
    for r in rules:
        if r.id == rid:
            return r
    raise AssertionError(f"rule {rid} not loaded")


PASSWORD_SPRAY_ID = "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90"
PRIV_GRANT_ID = "7d3e9a52-1f6c-4a88-9b3d-2e5c8f1a6d40"


def run():
    rules = load_rules(RULES_DIR)
    base = 1_750_000_000

    # ---- PASSWORD SPRAY: one account, 8 distinct source IPs fires; 7 does not ----
    ssh = LinuxSshParser()
    spray = rule_by_id(rules, PASSWORD_SPRAY_ID)
    check(spray.stateful and spray.distinct_field == "src_endpoint.ip",
          "password-spray rule should be stateful distinct on src_endpoint.ip")

    fired = []
    for i in range(8):
        line = (f"Jun 10 13:55:{i:02d} db01 sshd[2154]: Failed password for "
                f"invalid user targetuser from 203.0.113.{10 + i} port 51000 ssh2")
        ev = ssh.parse({"raw": line, "meta": {"received_at": base + i,
                                              "ingest_id": f"spray{i}"}})
        check(ev is not None and ev["actor"]["user"]["name"] == "targetuser",
              "REAL linux_ssh parser must set actor.user.name on a failed auth")
        fired.append(spray.evaluate(ev))
    check(fired[:7] == [False] * 7, "password-spray: first 7 distinct source IPs must NOT fire")
    check(fired[7] is True, "password-spray: 8th distinct source IP MUST fire")

    # below threshold: a different account from only 7 distinct IPs never fires
    spray2 = rule_by_id(load_rules(RULES_DIR), PASSWORD_SPRAY_ID)
    fired2 = []
    for i in range(7):
        line = (f"Jun 10 14:00:{i:02d} db01 sshd[2160]: Failed password for "
                f"invalid user other from 198.51.100.{10 + i} port 51000 ssh2")
        ev = ssh.parse({"raw": line, "meta": {"received_at": base + 100 + i,
                                              "ingest_id": f"q{i}"}})
        fired2.append(spray2.evaluate(ev))
    check(not any(fired2), "password-spray: 7 distinct source IPs must NOT fire")

    # ---- PRIV GRANT: single-shot, fires on every real 4728/4732 event ----
    win = WindowsEventLogParser()
    grant = rule_by_id(rules, PRIV_GRANT_ID)
    check(not grant.stateful, "priv-grant should be single-shot (no window/threshold)")

    for event_id in (4728, 4732):
        ev = win.parse({"raw": {"EventID": event_id, "SubjectUserName": "admin",
                                "TargetUserName": "new_svc", "Computer": "dc01"},
                        "meta": {"ingest_id": f"grant-{event_id}"}})
        check(ev is not None and ev["class_uid"] == 3003 and ev["activity_id"] == 5,
              f"REAL windows_eventlog parser must emit class 3003/activity 5 for {event_id}")
        check(grant.evaluate(ev) is True,
              f"priv-grant: a real EventID {event_id} event MUST fire")

    # a plain logon (4624) must NOT match the priv-grant rule
    grant2 = rule_by_id(load_rules(RULES_DIR), PRIV_GRANT_ID)
    logon = win.parse({"raw": {"EventID": 4624, "TargetUserName": "jdoe",
                              "Computer": "dc01"}, "meta": {}})
    check(grant2.evaluate(logon) is False, "priv-grant: a plain logon must NOT match")


def main():
    run()
    if FAILS:
        print(f"[FAIL] v0.3 new rules: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] password-spray + priv-grant fire correctly on REAL parser output")


if __name__ == "__main__":
    main()
