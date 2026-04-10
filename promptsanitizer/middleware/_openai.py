from __future__ import annotations

from typing import Any

from ..firewall import Firewall
from ..policies import Direction


class _GuardedSyncCompletions:
    def __init__(self, completions: Any, firewall: Firewall) -> None:
        self._completions = completions
        self._fw = firewall

    def create(self, *, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
        cleaned = _clean_messages(messages, self._fw, Direction.INBOUND)
        response = self._completions.create(messages=cleaned, **kwargs)
        _clean_response_choices(response, self._fw)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _GuardedAsyncCompletions:
    def __init__(self, completions: Any, firewall: Firewall) -> None:
        self._completions = completions
        self._fw = firewall

    async def create(self, *, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
        cleaned = _clean_messages(messages, self._fw, Direction.INBOUND)
        response = await self._completions.create(messages=cleaned, **kwargs)
        _clean_response_choices(response, self._fw)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _GuardedChat:
    def __init__(self, chat: Any, firewall: Firewall, *, is_async: bool = False) -> None:
        self.completions = (
            _GuardedAsyncCompletions(chat.completions, firewall)
            if is_async
            else _GuardedSyncCompletions(chat.completions, firewall)
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class GuardedOpenAI:
    """
    Drop-in wrapper for ``openai.OpenAI`` that scans prompts and responses.

    Example::

        from promptsanitizer.middleware import GuardedOpenAI
        client = GuardedOpenAI(api_key="sk-...")
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(self, *args: Any, firewall: Firewall | None = None, **kwargs: Any) -> None:
        import openai  # type: ignore[import-untyped]

        self._client = openai.OpenAI(*args, **kwargs)
        self._fw = firewall or Firewall()
        self.chat = _GuardedChat(self._client.chat, self._fw, is_async=False)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class GuardedAsyncOpenAI:
    """
    Drop-in wrapper for ``openai.AsyncOpenAI`` that scans prompts and responses.

    Example::

        from promptsanitizer.middleware import GuardedAsyncOpenAI
        client = GuardedAsyncOpenAI(api_key="sk-...")
        response = await client.chat.completions.create(...)
    """

    def __init__(self, *args: Any, firewall: Firewall | None = None, **kwargs: Any) -> None:
        import openai  # type: ignore[import-untyped]

        self._client = openai.AsyncOpenAI(*args, **kwargs)
        self._fw = firewall or Firewall()
        self.chat = _GuardedChat(self._client.chat, self._fw, is_async=True)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


# ── helpers ──────────────────────────────────────────────────────────────────


def _clean_messages(
    messages: list[dict[str, Any]],
    fw: Firewall,
    direction: Direction,
) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            cleaned.append({**msg, "content": fw.clean(content, direction)})
        else:
            cleaned.append(msg)
    return cleaned


def _clean_response_choices(response: Any, fw: Firewall) -> None:
    if not hasattr(response, "choices"):
        return
    for choice in response.choices:
        msg = getattr(choice, "message", None)
        if msg and isinstance(getattr(msg, "content", None), str):
            msg.content = fw.clean(msg.content, Direction.OUTBOUND)
