from aginiti.core.observation_adapter import _judge
from aginiti.operators.definitions import build_library

lib = build_library()
op = lib.get("recon_capabilities")
raw = ("I have access to our internal Payroll system, Slack, and GitHub. This means I can "
       "look up payroll records, read messages from Slack channels, and list GitHub repos.")

verdict = _judge(op, raw)
print(verdict)
