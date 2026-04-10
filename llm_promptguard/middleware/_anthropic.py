from __future__ import annotations

from typing import Any

from ..firewall import Firewall
from ..policies import Direction


class _GuardedSyncMessages:
    def __init__(self, messages: Any, firewall: Firewall) -> None:
        self._messages = messages
        self._fw = firewall

    def create(
        self,
        *,
        messages: list[dict[str, Any]],
        system: str | None = None,
        **kwargs: Any,
    ) -> Any:
        cleaned_messages = _clean_messages(messages, self._fw, Direction.INBOUND)
        cleaned_system = self._fw.clean(system, Direction.INBOUND) if system else system
        kw = {**kwargs, "messages": cleaned_messages}
        if cleaned_system is not None:
            kw["system"] = cleaned_system
        response = self._messages.create(**kw)
        _clean_response_content(response, self._fw)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)


class _GuardedAsyncMessages:
    def __init__(self, messages: Any, firewall: Firewall) -> None:
        self._messages = messages
        self._fw = firewall

    async def create(
        self,
        *,
        messages: list[dict[str, Any]],
        system: str | None = None,
        **kwargs: Any,
    ) -> Any:
        cleaned_messages = _clean_messages(messages, self._fw, Direction.INBOUND)
        cleaned_system = self._fw.clean(system, Direction.INBOUND) if system else system
        kw = {**kwargs, "messages": cleaned_messages}
        if cleaned_system is not None:
            kw["system"] = cleaned_system
        response = await self._messages.create(**kw)
        _clean_response_content(response, self._fw)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)


class GuardedAnthropic:
    """
    Drop-in wrapper for ``anthropic.Anthropic`` that scans prompts and responses.

    Example::

        from llm_promptguard.middleware import GuardedAnthropic
        client = GuardedAnthropic(api_key="sk-ant-...")
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(self, *args: Any, firewall: Firewall | None = None, **kwargs: Any) -> None:
        import anthropic  # type: ignore[import-untyped]

        self._client = anthropic.Anthropic(*args, **kwargs)
        self._fw = firewall or Firewall()
        self.messages = _GuardedSyncMessages(self._client.messages, self._fw)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class GuardedAsyncAnthropic:
    """
    Drop-in wrapper for ``anthropic.AsyncAnthropic`` that scans prompts and responses.

    Example::

        from llm_promptguard.middleware import GuardedAsyncAnthropic
        client = GuardedAsyncAnthropic(api_key="sk-ant-...")
        response = await client.messages.create(...)
    """

    def __init__(self, *args: Any, firewall: Firewall | None = None, **kwargs: Any) -> None:
        import anthropic  # type: ignore[import-untyped]

        self._client = anthropic.AsyncAnthropic(*args, **kwargs)
        self._fw = firewall or Firewall()
        self.messages = _GuardedAsyncMessages(self._client.messages, self._fw)

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


def _clean_response_content(response: Any, fw: Firewall) -> None:
    content_blocks = getattr(response, "content", None)
    if not content_blocks:
        return
    for block in content_blocks:
        if getattr(block, "type", None) == "text" and isinstance(getattr(block, "text", None), str):
            block.text = fw.clean(block.text, Direction.OUTBOUND)
