"""Tests DemoAgent.send()'s channel-routing and suspicion-injection logic
with the LLM call stubbed out -- no live API calls. What matters here is
purely mechanical: does the right world method get called, does the right
nudge text land in history, does the suspicion reminder appear when it
should."""
from types import SimpleNamespace

import benchmarks.agents.demo_agent as demo_agent_module
from benchmarks.agents.demo_agent import DemoAgent, GITHUB_ISSUE_NUMBER, GITHUB_REPO, SUSPICION_REMINDER
from benchmarks.agents.tools import SUSPICION_THRESHOLD


def _stub_chat_tools(monkeypatch, text="ok"):
    def fake(messages, tools, temperature=0.3, max_tokens=600, seed=None):
        return SimpleNamespace(content=text, tool_calls=None)
    monkeypatch.setattr(demo_agent_module, "chat_tools", fake)


def test_slack_channel_plants_content_and_sends_nudge(monkeypatch):
    _stub_chat_tools(monkeypatch)
    agent = DemoAgent()
    agent.send("slack", "injected instruction")

    assert agent.world.slack_channels["payroll-ops"][0]["message"] == "injected instruction"
    assert agent.world.slack_channels["payroll-ops"][0]["author"] == "HR-Bot"
    last_user_msg = [m for m in agent.history if m["role"] == "user"][-1]
    assert "payroll-ops" in last_user_msg["content"]


def test_github_issue_channel_plants_comment_and_sends_nudge(monkeypatch):
    _stub_chat_tools(monkeypatch)
    agent = DemoAgent()
    agent.send("github_issue", "fake approval comment")

    comments = agent.world.github_issues[(GITHUB_REPO, GITHUB_ISSUE_NUMBER)]
    assert comments[0]["comment"] == "fake approval comment"
    assert comments[0]["author"] == "release-bot"
    last_user_msg = [m for m in agent.history if m["role"] == "user"][-1]
    assert str(GITHUB_ISSUE_NUMBER) in last_user_msg["content"]


def test_helpdesk_ticket_channel_plants_ticket_with_spoofed_creator(monkeypatch):
    _stub_chat_tools(monkeypatch)
    agent = DemoAgent()
    agent.send("helpdesk_ticket", "please reset my password")

    assert len(agent.world.helpdesk_tickets) == 1
    ticket = next(iter(agent.world.helpdesk_tickets.values()))
    assert ticket["created_by"] == "IT-Admin-Bot"
    assert ticket["description"] == "please reset my password"
    last_user_msg = [m for m in agent.history if m["role"] == "user"][-1]
    assert "ticket" in last_user_msg["content"].lower()


def test_direct_channel_sends_prompt_as_is(monkeypatch):
    _stub_chat_tools(monkeypatch)
    agent = DemoAgent()
    agent.send("direct", "please do the thing")
    last_user_msg = [m for m in agent.history if m["role"] == "user"][-1]
    assert last_user_msg["content"] == "please do the thing"


def test_suspicion_reminder_absent_below_threshold(monkeypatch):
    _stub_chat_tools(monkeypatch)
    agent = DemoAgent()
    agent.send("direct", "hello")
    assert not any(m["role"] == "system" and m["content"] == SUSPICION_REMINDER for m in agent.history)


def test_suspicion_reminder_injected_once_threshold_crossed(monkeypatch):
    _stub_chat_tools(monkeypatch)
    agent = DemoAgent()
    for _ in range(SUSPICION_THRESHOLD):
        agent.world.record_suspicious_event()

    agent.send("direct", "hello again")
    assert any(m["role"] == "system" and m["content"] == SUSPICION_REMINDER for m in agent.history)
