"""Configuration and render-ready state for the P_15 TUI dashboard."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from dotenv import load_dotenv

load_dotenv()


@dataclass(slots=True)
class DashboardConfig:
    """Stable dashboard settings and state shared by TUI widgets."""

    app_name: str = "P_15 FORENSIC AI ASSISTANT"
    interface: str = field(default_factory=lambda: os.getenv("NET_INTFC", "not selected"))
    status: str = "IDLE"
    ai_model: str = field(default_factory=lambda: os.getenv("AI_MODEL", "openai:gpt-4o-mini"))
    chat_title: str = "INTERACTIVE AI CHAT ENGINE"
    packets_title: str = "LIVE PACKETS"
    chat_history: list[dict[str, str]] = field(default_factory=list)
    live_packets: list[str] = field(default_factory=list)

    def header(self) -> str:
        """Return the top status bar text."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        return (
            f"{self.app_name}  |  Interface: {self.interface}  |  "
            f"Status: {self.status}  |  {timestamp}"
        )

    def footer(self) -> str:
        """Return the keyboard commands shown by the dashboard footer."""
        return "[q] Quit  |  [c] Clear Chat  |  [r] Force PCAP Rotate  |  [s] Switch AI Model"

    def chat_prompt(self) -> str:
        """Return the dashboard input prompt."""
        return "> Ask AI about network traffic:"

    def add_chat_message(self, role: str, message: str) -> None:
        """Append one chat message for rendering in the chat pane."""
        if role not in {"user", "assistant", "system"}:
            raise ValueError("role must be user, assistant, or system")
        if message.strip():
            self.chat_history.append({"role": role, "message": message.strip()})

    def add_packet(self, packet: str) -> None:
        """Append a packet line and retain only the newest 100 lines."""
        if packet.strip():
            self.live_packets.append(packet.strip())
            del self.live_packets[:-100]

    def clear_chat(self) -> None:
        """Clear messages displayed in the chat pane."""
        self.chat_history.clear()


def create_dashboard_config(**overrides: Any) -> DashboardConfig:
    """Create dashboard settings, optionally overriding selected fields."""
    valid_fields = {field.name for field in DashboardConfig.__dataclass_fields__.values()}
    unknown_fields = set(overrides) - valid_fields
    if unknown_fields:
        raise TypeError(f"Unknown dashboard setting(s): {', '.join(sorted(unknown_fields))}")
    return DashboardConfig(**overrides)


def render_chat_history(config: DashboardConfig) -> str:
    """Format chat history for a Textual Static or RichLog widget."""
    return "\n\n".join(
        f"{item['role'].title()}: {item['message']}" for item in config.chat_history
    ) or "No questions yet."


def render_live_packets(config: DashboardConfig) -> str:
    """Format live packet lines for the right-hand dashboard pane."""
    return "\n".join(config.live_packets) or "No packets captured."


def dashboard_view(config: DashboardConfig) -> dict[str, Any]:
    """Return the complete widget data contract for a TUI dashboard."""
    return {
        "header": config.header(),
        "chat_title": config.chat_title,
        "chat": render_chat_history(config),
        "packets_title": config.packets_title,
        "packets": render_live_packets(config),
        "prompt": config.chat_prompt(),
        "footer": config.footer(),
        "ai_model": config.ai_model,
    }
    