"""Tests for experiments/_target_lifecycle.py -- the 2026-08-14
fresh-target-per-trial infrastructure built in response to exp28's
memory-contamination postmortem. Fully offline: psutil/subprocess/requests
are monkeypatched with lightweight fakes so this suite never spawns a real
server or touches the network, matching this project's own established
"stub the boundary, not the logic under test" discipline. The actual
real-process start/stop/restart cycle for both `hardened_agent` and
`healthcare_agent` was separately, manually verified live against this
venv on 2026-08-14 (start -> healthy -> restart -> new pid, distinct from
the old one -> stop -> zero processes remaining) -- that live check is not
repeatable offline by construction (it needs a real port and a real
process), so it is not re-encoded here; this file instead locks down the
pure logic: which processes get matched and killed, and that health
polling actually blocks until healthy or times out."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from experiments import _target_lifecycle as tl


class _FakeProcess:
    """Minimal stand-in for psutil.Process -- just enough surface for
    find_target_processes/stop_target to operate on."""

    def __init__(self, pid, cmdline, alive_after_terminate=True):
        self.pid = pid
        self.info = {"pid": pid, "name": "python.exe", "cmdline": cmdline}
        self.terminated = False
        self.killed = False
        self._alive_after_terminate = alive_after_terminate

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


def test_find_target_processes_matches_only_this_targets_cmdline(monkeypatch):
    spec = tl.TARGETS["hardened_agent"]
    matching = _FakeProcess(111, ["python.exe", "-m", "uvicorn",
                                   "benchmarks.scaled_evals.agents.hardened_agent.main:app", "--port", "8004"])
    other_target = _FakeProcess(222, ["python.exe", "-m", "uvicorn",
                                       "benchmarks.scaled_evals.agents.healthcare_agent.main:app", "--port", "8003"])
    unrelated = _FakeProcess(333, ["node", "some_other_server.js"])

    monkeypatch.setattr(tl.psutil, "process_iter", lambda attrs: [matching, other_target, unrelated])

    found = tl.find_target_processes(spec)
    assert [p.pid for p in found] == [111]


def test_find_target_processes_returns_empty_when_nothing_matches(monkeypatch):
    spec = tl.TARGETS["hardened_agent"]
    monkeypatch.setattr(tl.psutil, "process_iter", lambda attrs: [])
    assert tl.find_target_processes(spec) == []


def test_stop_target_terminates_every_match_and_reports_the_count(monkeypatch):
    spec = tl.TARGETS["hardened_agent"]
    # The real, empirically-verified (2026-08-14) Windows behavior: one
    # logical server instance shows up as TWO matching processes (a
    # venv launcher parent + its re-exec'd child, both carrying the
    # identical command line) -- see stop_target's own docstring.
    parent = _FakeProcess(111, ["python.exe", "-m", "uvicorn",
                                 "benchmarks.scaled_evals.agents.hardened_agent.main:app"])
    child = _FakeProcess(112, ["python.exe", "-m", "uvicorn",
                                "benchmarks.scaled_evals.agents.hardened_agent.main:app"])

    monkeypatch.setattr(tl.psutil, "process_iter", lambda attrs: [parent, child])
    monkeypatch.setattr(tl.psutil, "wait_procs", lambda procs, timeout: (procs, []))  # all exited cleanly

    n = tl.stop_target("hardened_agent", timeout=1.0)

    assert n == 2
    assert parent.terminated and child.terminated
    assert not parent.killed and not child.killed  # graceful terminate was enough, no escalation needed


def test_stop_target_escalates_to_kill_for_stragglers(monkeypatch):
    proc = _FakeProcess(111, ["python.exe", "-m", "uvicorn",
                               "benchmarks.scaled_evals.agents.hardened_agent.main:app"])
    monkeypatch.setattr(tl.psutil, "process_iter", lambda attrs: [proc])
    # simulate: still alive after the graceful-terminate wait window
    monkeypatch.setattr(tl.psutil, "wait_procs", lambda procs, timeout: ([], procs))

    tl.stop_target("hardened_agent", timeout=1.0)

    assert proc.terminated  # graceful attempt was still made first
    assert proc.killed  # then escalated


def test_stop_target_is_a_silent_no_op_when_nothing_is_running(monkeypatch):
    monkeypatch.setattr(tl.psutil, "process_iter", lambda attrs: [])
    assert tl.stop_target("hardened_agent") == 0


def test_wait_for_health_returns_once_the_endpoint_responds_200(monkeypatch):
    spec = tl.TARGETS["hardened_agent"]
    calls = {"n": 0}

    def fake_get(url, timeout):
        calls["n"] += 1
        # not healthy yet on the first check, healthy on the second
        status = 200 if calls["n"] >= 2 else 503
        return SimpleNamespace(status_code=status)

    monkeypatch.setattr(tl.requests, "get", fake_get)
    monkeypatch.setattr(tl.time, "sleep", lambda s: None)  # don't actually block the test suite

    tl._wait_for_health(spec, timeout=5.0)  # must not raise
    assert calls["n"] >= 2


def test_wait_for_health_times_out_if_it_never_becomes_healthy(monkeypatch):
    spec = tl.TARGETS["hardened_agent"]

    monkeypatch.setattr(tl.requests, "get", lambda url, timeout: SimpleNamespace(status_code=503))
    fake_time = {"t": 0.0}
    monkeypatch.setattr(tl.time, "monotonic", lambda: fake_time["t"])

    def fake_sleep(s):
        fake_time["t"] += s + 0.1  # advance past the deadline quickly instead of really sleeping

    monkeypatch.setattr(tl.time, "sleep", fake_sleep)

    with pytest.raises(TimeoutError):
        tl._wait_for_health(spec, timeout=1.0)


def test_unknown_target_name_raises_a_clear_error():
    with pytest.raises(ValueError, match="Unknown target"):
        tl._spec("not_a_real_target")


def test_both_real_targets_are_registered_with_distinct_ports():
    assert set(tl.TARGETS) == {"hardened_agent", "healthcare_agent"}
    assert tl.TARGETS["hardened_agent"].port != tl.TARGETS["healthcare_agent"].port
    assert tl.TARGETS["hardened_agent"].health_url == "http://localhost:8004/health"
    assert tl.TARGETS["healthcare_agent"].health_url == "http://localhost:8003/health"
