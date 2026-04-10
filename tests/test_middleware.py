from __future__ import annotations

from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from promptsanitizer import Firewall, Policy
from promptsanitizer.middleware._openai import _GuardedSyncCompletions, _GuardedAsyncCompletions
from promptsanitizer.middleware._anthropic import _GuardedSyncMessages, _GuardedAsyncMessages


# ── OpenAI sync ───────────────────────────────────────────────────────────────

class TestGuardedSyncCompletions:
    def test_inbound_message_is_redacted(self, mock_openai_client: MagicMock):
        fw = Firewall()
        guarded = _GuardedSyncCompletions(mock_openai_client.chat.completions, fw)

        messages = [{"role": "user", "content": "key: sk-abcdefghijklmnopqrstuvwxyz123456"}]
        guarded.create(messages=messages, model="gpt-4o")

        call_messages = mock_openai_client.chat.completions.create.call_args[1]["messages"]
        assert "[REDACTED:openai_key]" in call_messages[0]["content"]
        assert "sk-abcdef" not in call_messages[0]["content"]

    def test_outbound_response_is_redacted(self, mock_openai_client: MagicMock):
        fw = Firewall()
        mock_openai_client.chat.completions.create.return_value = _make_openai_response(
            "Here is sk-abcdefghijklmnopqrstuvwxyz123456 — be careful."
        )
        guarded = _GuardedSyncCompletions(mock_openai_client.chat.completions, fw)
        response = guarded.create(messages=[{"role": "user", "content": "hi"}], model="gpt-4o")

        assert "[REDACTED:openai_key]" in response.choices[0].message.content

    def test_clean_text_passes_through_unmodified(self, mock_openai_client: MagicMock):
        fw = Firewall()
        guarded = _GuardedSyncCompletions(mock_openai_client.chat.completions, fw)
        messages = [{"role": "user", "content": "Hello, how are you?"}]
        guarded.create(messages=messages, model="gpt-4o")

        call_messages = mock_openai_client.chat.completions.create.call_args[1]["messages"]
        assert call_messages[0]["content"] == "Hello, how are you?"

    def test_non_string_content_skipped(self, mock_openai_client: MagicMock):
        fw = Firewall()
        guarded = _GuardedSyncCompletions(mock_openai_client.chat.completions, fw)
        messages = [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
        guarded.create(messages=messages, model="gpt-4o")
        call_messages = mock_openai_client.chat.completions.create.call_args[1]["messages"]
        assert call_messages[0]["content"] == [{"type": "text", "text": "hello"}]


# ── OpenAI async ──────────────────────────────────────────────────────────────

class TestGuardedAsyncCompletions:
    @pytest.mark.asyncio
    async def test_inbound_redacted_async(self):
        fw = Firewall()
        mock_completions = MagicMock()
        mock_completions.create = AsyncMock(
            return_value=_make_openai_response("No secrets in response.")
        )
        guarded = _GuardedAsyncCompletions(mock_completions, fw)

        messages = [{"role": "user", "content": "key sk-abcdefghijklmnopqrstuvwxyz123456"}]
        await guarded.create(messages=messages, model="gpt-4o")

        call_messages = mock_completions.create.call_args[1]["messages"]
        assert "[REDACTED:openai_key]" in call_messages[0]["content"]

    @pytest.mark.asyncio
    async def test_outbound_redacted_async(self):
        fw = Firewall()
        mock_completions = MagicMock()
        mock_completions.create = AsyncMock(
            return_value=_make_openai_response("email: secret@corp.com")
        )
        guarded = _GuardedAsyncCompletions(mock_completions, fw)
        response = await guarded.create(messages=[{"role": "user", "content": "hi"}], model="gpt-4o")
        assert "[REDACTED:email]" in response.choices[0].message.content


# ── Anthropic sync ────────────────────────────────────────────────────────────

class TestGuardedSyncMessages:
    def test_inbound_message_is_redacted(self, mock_anthropic_client: MagicMock):
        fw = Firewall()
        guarded = _GuardedSyncMessages(mock_anthropic_client.messages, fw)

        messages = [{"role": "user", "content": "email: boss@secret.com"}]
        guarded.create(messages=messages, model="claude-3-5-sonnet-20241022", max_tokens=100)

        call_kwargs = mock_anthropic_client.messages.create.call_args[1]
        assert "[REDACTED:email]" in call_kwargs["messages"][0]["content"]

    def test_system_prompt_is_redacted(self, mock_anthropic_client: MagicMock):
        fw = Firewall()
        guarded = _GuardedSyncMessages(mock_anthropic_client.messages, fw)

        guarded.create(
            messages=[{"role": "user", "content": "hi"}],
            system="Connection: postgres://admin:p4ss@db.host/prod",
            model="claude-3-5-sonnet-20241022",
            max_tokens=100,
        )

        call_kwargs = mock_anthropic_client.messages.create.call_args[1]
        assert "[REDACTED:connection_string]" in call_kwargs["system"]

    def test_outbound_response_is_redacted(self, mock_anthropic_client: MagicMock):
        fw = Firewall()
        mock_anthropic_client.messages.create.return_value = _make_anthropic_response(
            "Your card 4111111111111111 is on file."
        )
        guarded = _GuardedSyncMessages(mock_anthropic_client.messages, fw)
        response = guarded.create(
            messages=[{"role": "user", "content": "hi"}],
            model="claude-3-5-sonnet-20241022",
            max_tokens=100,
        )
        assert "[REDACTED:credit_card]" in response.content[0].text


# ── Anthropic async ───────────────────────────────────────────────────────────

class TestGuardedAsyncMessages:
    @pytest.mark.asyncio
    async def test_async_inbound_redacted(self):
        fw = Firewall()
        mock_messages = MagicMock()
        mock_messages.create = AsyncMock(
            return_value=_make_anthropic_response("No secrets here.")
        )
        guarded = _GuardedAsyncMessages(mock_messages, fw)

        messages = [{"role": "user", "content": "ssn: 123-45-6789"}]
        await guarded.create(messages=messages, model="claude-3-5-sonnet-20241022", max_tokens=100)

        call_kwargs = mock_messages.create.call_args[1]
        assert "[REDACTED:ssn]" in call_kwargs["messages"][0]["content"]


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_openai_response(content: str) -> MagicMock:
    msg = MagicMock()
    msg.content = content
    choice = MagicMock()
    choice.message = msg
    response = MagicMock()
    response.choices = [choice]
    return response


def _make_anthropic_response(text: str) -> MagicMock:
    block = MagicMock()
    block.type = "text"
    block.text = text
    response = MagicMock()
    response.content = [block]
    return response
