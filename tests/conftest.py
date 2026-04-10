from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from promptsanitizer import Firewall, Policy


@pytest.fixture
def fw() -> Firewall:
    return Firewall()


@pytest.fixture
def strict_fw() -> Firewall:
    return Firewall(policy=Policy.strict())


@pytest.fixture
def audit_fw() -> Firewall:
    return Firewall(policy=Policy.audit())


# ── Mock OpenAI objects ───────────────────────────────────────────────────────

def _make_openai_response(content: str) -> MagicMock:
    msg = MagicMock()
    msg.content = content
    choice = MagicMock()
    choice.message = msg
    response = MagicMock()
    response.choices = [choice]
    return response


@pytest.fixture
def mock_openai_response() -> MagicMock:
    return _make_openai_response("Here is the info: user@example.com and 192.168.1.1")


@pytest.fixture
def mock_openai_client(mock_openai_response: MagicMock) -> MagicMock:
    completions = MagicMock()
    completions.create.return_value = mock_openai_response
    chat = MagicMock()
    chat.completions = completions
    client = MagicMock()
    client.chat = chat
    return client


# ── Mock Anthropic objects ────────────────────────────────────────────────────

def _make_anthropic_response(text: str) -> MagicMock:
    block = MagicMock()
    block.type = "text"
    block.text = text
    response = MagicMock()
    response.content = [block]
    return response


@pytest.fixture
def mock_anthropic_response() -> MagicMock:
    return _make_anthropic_response("Call me at 555-123-4567 or email me@corp.io")


@pytest.fixture
def mock_anthropic_client(mock_anthropic_response: MagicMock) -> MagicMock:
    messages_api = MagicMock()
    messages_api.create.return_value = mock_anthropic_response
    client = MagicMock()
    client.messages = messages_api
    return client
