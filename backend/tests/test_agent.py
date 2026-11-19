"""Agent response-action logic. Every system command is mocked — no firewall rule is ever touched."""
import importlib.util
import pathlib

import pytest

spec = importlib.util.spec_from_file_location("wolve_agent", pathlib.Path(__file__).resolve().parents[2] / "agent" / "wolve_agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class FakeNetsh:
    """Simulates netsh: tracks rules by (name, dir); can be told to fail one direction."""

    def __init__(self, fail_dir=None):
        self.rules, self.calls, self.fail_dir = set(), [], fail_dir

    def __call__(self, cmd, timeout=20):
        self.calls.append(cmd)
        assert isinstance(cmd, list), "commands must be argument lists, never shell strings"
        if cmd[:3] != ["netsh", "advfirewall", "firewall"]:
            return 1, "unexpected command"
        action = cmd[3]
        args = dict(a.split("=", 1) for a in cmd[5:] if "=" in a) if action == "add" else dict(a.split("=", 1) for a in cmd[4:] if "=" in a)
        name, d = args.get("name"), args.get("dir")
        assert name.startswith(agent.FW_RULE_PREFIX), "agent must only touch WOLVE-named rules"
        if action == "show":
            return (0, "rule") if (name, d) in self.rules else (1, "No rules match")
        if action == "add":
            if d == self.fail_dir:
                return 1, "access denied"
            self.rules.add((name, d))
            return 0, ""
        if action == "delete":
            before = len(self.rules)
            self.rules = {r for r in self.rules if not (r[0] == name and (d is None or r[1] == d))}
            return (0, "") if len(self.rules) < before else (1, "No rules match")
        return 1, "?"


@pytest.fixture
def win(monkeypatch):
    monkeypatch.setattr(agent, "IS_WINDOWS", True)
    monkeypatch.setattr(agent, "is_admin", lambda: True)
    fake = FakeNetsh()
    monkeypatch.setattr(agent, "_exec", fake)
    return fake


def test_refused_without_allow_response(win):
    status, msg = agent.execute({"type": "block_ip", "params": {"ip": "198.51.100.7"}}, allow=False)
    assert status == "refused" and not win.calls


def test_refused_when_not_admin(win, monkeypatch):
    monkeypatch.setattr(agent, "is_admin", lambda: False)
    status, msg = agent.execute({"type": "block_ip", "params": {"ip": "8.8.4.4"}}, allow=True)
    assert status == "refused" and "administrator" in msg and not win.calls


@pytest.mark.parametrize("ip", ["127.0.0.1", "0.0.0.0", "192.168.1.1", "10.0.0.5", "169.254.1.1", "224.0.0.1", "not-an-ip", "8.8.8.8; del *"])
def test_dangerous_or_invalid_targets_refused(win, ip):
    status, _ = agent.execute({"type": "block_ip", "params": {"ip": ip}}, allow=True)
    assert status in ("refused", "failed") and not win.calls


def test_block_is_idempotent_and_both_directions(win):
    assert agent.execute({"type": "block_ip", "params": {"ip": "8.8.4.4"}}, True)[0] == "done"
    assert win.rules == {("WOLVE-block-8.8.4.4", "out"), ("WOLVE-block-8.8.4.4", "in")}
    status, msg = agent.execute({"type": "block_ip", "params": {"ip": "8.8.4.4"}}, True)
    assert status == "done" and "already blocked" in msg and len(win.rules) == 2


def test_partial_failure_rolls_back(monkeypatch):
    monkeypatch.setattr(agent, "IS_WINDOWS", True)
    monkeypatch.setattr(agent, "is_admin", lambda: True)
    fake = FakeNetsh(fail_dir="in")
    monkeypatch.setattr(agent, "_exec", fake)
    status, msg = agent.execute({"type": "block_ip", "params": {"ip": "8.8.4.4"}}, True)
    assert status == "failed" and fake.rules == set(), "outbound rule must be removed when inbound fails"


def test_unblock_only_removes_wolve_rule(win):
    win.rules.add(("WOLVE-block-8.8.4.4", "in"))
    assert agent.execute({"type": "unblock_ip", "params": {"ip": "8.8.4.4"}}, True)[0] == "done"
    assert win.rules == set()
    status, msg = agent.execute({"type": "unblock_ip", "params": {"ip": "8.8.4.4"}}, True)
    assert status == "done" and "nothing to remove" in msg


def test_unknown_command_rejected(win):
    assert agent.execute({"type": "shell", "params": {"cmd": "whoami"}}, True)[0] == "failed" and not win.calls
