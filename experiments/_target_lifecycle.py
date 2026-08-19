"""Reusable "fresh target/session/server state for every independent trial"
infrastructure. Built 2026-08-14 in direct response to a live postmortem
finding (exp28, `docs/EXP28...` -- see the user's own framing): `hardened_
agent`'s conversation memory is scoped PER PERSONA for the life of the
SERVER PROCESS, not per script run or per trial. exp28 ran 12 trials
(3 conditions x 4 trials) against the SAME long-running server process and
the SAME `legal` persona bearer key -- so trial N's target state included
the tail end of trials 0..N-1's conversation history, regardless of
condition. `docs/QUICKSTART_HARDENED_AGENT.md` step 5 already documented
this as a known gotcha with a MANUAL fix (find the PID, `Stop-Process`,
re-run the uvicorn command) -- this module makes that fix automatic,
reliable, and callable BETWEEN EVERY TRIAL, not just once before a script
starts, which is what the manual version actually required from a human
to remember to do 12 times in exp28 and did not happen.

Deliberately built on `psutil` (cross-platform process discovery/
termination by matching the command line, not a remembered/tracked PID)
rather than only tracking a `subprocess.Popen` handle -- a Popen handle is
lost if the experiment script crashes and is restarted, or if a server was
started manually in a separate terminal (exactly how every prior live
experiment in this project was actually run, per QUICKSTART_HARDENED_
AGENT.md). Matching by command line finds and stops the real process
either way, which is the actual property the "fresh state" methodology
needs -- not "did this specific script start it."

Usage (the property the user's directive explicitly asked for):

    from experiments._target_lifecycle import restart_target

    for trial_index in range(N_TRIALS):
        restart_target("hardened_agent")  # fresh process, fresh memory, BEFORE every trial
        ... run one independent trial against the freshly-restarted target ...

Also usable directly from the command line for the same manual restart
QUICKSTART_HARDENED_AGENT.md's step 5 used to require by hand:

    python -m experiments._target_lifecycle restart hardened_agent
"""
from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import psutil
import requests

_ROOT = Path(__file__).parent.parent


@dataclass(frozen=True)
class TargetSpec:
    name: str
    module: str  # the uvicorn ASGI target, e.g. "benchmarks.scaled_evals.agents.hardened_agent.main:app"
    port: int
    # A substring unique enough to find THIS target's process (and only
    # this one) in the full system process list via its command line --
    # deliberately the module path itself, not just the target name, so
    # e.g. "hardened_agent" can't accidentally match an unrelated process
    # that happens to mention the word.
    cmdline_match: str

    @property
    def health_url(self) -> str:
        return f"http://localhost:{self.port}/health"


TARGETS: dict[str, TargetSpec] = {
    "hardened_agent": TargetSpec(
        name="hardened_agent",
        module="benchmarks.scaled_evals.agents.hardened_agent.main:app",
        port=8004,
        cmdline_match="benchmarks.scaled_evals.agents.hardened_agent.main",
    ),
    "healthcare_agent": TargetSpec(
        name="healthcare_agent",
        module="benchmarks.scaled_evals.agents.healthcare_agent.main:app",
        port=8003,
        cmdline_match="benchmarks.scaled_evals.agents.healthcare_agent.main",
    ),
}


def _spec(name: str) -> TargetSpec:
    try:
        return TARGETS[name]
    except KeyError:
        raise ValueError(f"Unknown target {name!r} -- known targets: {sorted(TARGETS)}") from None


def find_target_processes(spec: TargetSpec) -> list[psutil.Process]:
    """Every currently-running process whose command line matches this
    target's uvicorn invocation -- normally 0 or 1, but returns all matches
    so a caller can detect and clean up an unexpected duplicate rather than
    silently only killing one of two."""
    matches = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = proc.info["cmdline"] or []
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if any(spec.cmdline_match in part for part in cmdline):
            matches.append(proc)
    return matches


def stop_target(name: str, timeout: float = 10.0) -> int:
    """Stops every currently-running process matching this target, if any.
    Graceful terminate() first, escalating to kill() only for stragglers
    still alive after `timeout` -- matches this project's own established
    subprocess-teardown pattern (experiments/exp2_deterministic_vs_judge.py's
    terminate()-then-wait()-then-kill()). Returns the number of processes
    actually stopped (0 if the target wasn't running -- not an error, since
    "make sure nothing is running" is a valid pre-state).

    Empirically verified (2026-08-14, this venv on Windows) that a single
    `start_target()` call is normally found and stopped as TWO matching
    processes, not one: the venv's `python.exe` launcher re-execs itself as
    a child process carrying the IDENTICAL command line, so a single
    logical server instance shows up as a parent/child pair both matching
    `cmdline_match`. This is exactly why this module matches by command
    line across the WHOLE process list rather than only terminating the
    one PID `subprocess.Popen` handed back -- tracking just that PID would
    leave the child half of the pair running and listening on the port
    after a "stop"."""
    spec = _spec(name)
    procs = find_target_processes(spec)
    for proc in procs:
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(procs, timeout=timeout)
    for proc in alive:
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            pass
    if procs:
        print(f"[_target_lifecycle] stopped {len(procs)} existing {name} process(es)"
              f"{' (had to force-kill ' + str(len(alive)) + ')' if alive else ''}")
    return len(procs)


def _wait_for_health(spec: TargetSpec, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = requests.get(spec.health_url, timeout=2)
            if resp.status_code == 200:
                return
        except requests.RequestException as e:
            last_error = e
        time.sleep(0.5)
    raise TimeoutError(
        f"{spec.name} did not become healthy at {spec.health_url} within {timeout}s"
        f"{f' (last error: {last_error})' if last_error else ''}"
    )


def start_target(name: str, timeout: float = 45.0, log_path: Path | None = None) -> subprocess.Popen:
    """Starts a fresh instance of `name` via the same interpreter running
    this process (sys.executable -- whatever venv the caller is already
    using, matching QUICKSTART_HARDENED_AGENT.md's own `.venv/Scripts/
    python.exe -m uvicorn ...` invocation rather than assuming a bare
    `python`/`uvicorn` is on PATH), blocks until its /health endpoint
    responds 200 (or raises TimeoutError), and returns the Popen handle.
    Does NOT check whether one is already running first -- call
    stop_target() (or restart_target(), which does both) if that matters."""
    spec = _spec(name)
    args = [sys.executable, "-m", "uvicorn", spec.module, "--port", str(spec.port)]
    stdout = log_path.open("a", encoding="utf-8") if log_path else subprocess.DEVNULL
    stderr = subprocess.STDOUT if log_path else subprocess.DEVNULL
    proc = subprocess.Popen(args, cwd=_ROOT, stdout=stdout, stderr=stderr)
    try:
        _wait_for_health(spec, timeout)
    except TimeoutError:
        proc.terminate()
        raise
    print(f"[_target_lifecycle] {name} up and healthy on port {spec.port} (pid {proc.pid})")
    return proc


def restart_target(name: str, timeout: float = 45.0, log_path: Path | None = None) -> subprocess.Popen:
    """The one function every experiment script should call BEFORE EACH
    INDEPENDENT TRIAL: stop whatever instance of `name` is currently
    running (if any -- including one started manually in another terminal,
    or left over from a previous trial/script/crash), start a completely
    fresh process, and block until it's confirmed healthy. This is what
    makes "fresh target/session/server state for every independent trial"
    (the user's own required methodology, in response to exp28's memory-
    contamination finding) an actual, automatic property of the harness
    instead of a manual step a human has to remember to repeat N times."""
    stop_target(name, timeout=min(timeout, 10.0))
    return start_target(name, timeout=timeout, log_path=log_path)


def _cli() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in ("start", "stop", "restart"):
        print(f"Usage: python -m experiments._target_lifecycle <start|stop|restart> <{'|'.join(TARGETS)}>")
        sys.exit(1)
    action, name = sys.argv[1], sys.argv[2]
    if action == "stop":
        n = stop_target(name)
        print(f"stopped {n} process(es)" if n else "nothing was running")
    elif action == "start":
        start_target(name)
    else:
        restart_target(name)


if __name__ == "__main__":
    _cli()
