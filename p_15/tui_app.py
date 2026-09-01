"""Three-pane Textual TUI for P_15.

Layout (three window regions, no popups):

+--------------------------------------------------------------+
|  Left: Live packet logs   |  Main: Internal AI chat system   |
|  (raw packets seen flown) |  (conversation pane)             |
+--------------------------------------------------------------+
|  Bottom: clean rectangular input  (red/Enter to send, q to quit) |
+--------------------------------------------------------------+
"""

from __future__ import annotations

from datetime import datetime

from rich.markup import escape
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, RichLog, Static

from .ai_engine import query_ai
from .config import DashboardConfig
from .snifer import packet_summary
from .vector_store import PacketVectorStore


def _force_redraw(log: RichLog) -> None:
    """Ensure new content is visible: scroll to bottom and force a repaint."""
    if log.is_running:
        log.scroll_end(animate=False)
        log.refresh()


class PacketLogWidget(RichLog):
    """Left-hand pane: lines describing every raw packet as it flows."""

    def __init__(self, **kwargs) -> None:
        super().__init__(highlight=True, markup=True, wrap=True, **kwargs)
        self.border_title = "LIVE PACKETS"

    def log_packet(self, packet) -> None:
        line = packet_summary(packet)
        self.write(Text.from_markup(f"[dim]{self._now()}[/dim]  {escape(str(line))}"))
        _force_redraw(self)

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%H:%M:%S")


class ChatPaneWidget(RichLog):
    """Main pane: the internal AI-based chat system."""

    def __init__(self, **kwargs) -> None:
        super().__init__(highlight=True, markup=True, wrap=True, **kwargs)
        self.border_title = "INTERNAL AI CHAT"

    def add_user(self, message: str) -> None:
        self.write(Text.from_markup(f"[bold cyan]You:[/bold cyan] {escape(message)}"))
        _force_redraw(self)

    def add_assistant(self, message: str) -> None:
        self.write(Text.from_markup(f"[bold green]AI:[/bold green] {escape(message)}"))
        _force_redraw(self)

    def add_system(self, message: str) -> None:
        self.write(Text.from_markup(f"[dim][i]{escape(message)}[/i][/dim]"))
        _force_redraw(self)


class UserInputWidget(Input):
    """Bottom clean rectangular input."""


class P15TUI(App):
    """Main Textual application for the P_15 dashboard."""

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
    ]

    CSS = """
    Screen {
        layout: vertical;
    }

    #topbar {
        height: 1;
    }

    #columns {
        height: 1fr;
    }

    #packet_log {
        width: 38%;
        border: round #1461a3;
        background: #0f1923;
        padding: 0 1;
    }

    #chat_pane {
        width: 1fr;
        border: round #2e7d32;
        background: #0d1410;
        padding: 0 1;
    }

    #prompt_row {
        height: 5;
        border: round #8a6d3b;
        background: #16160f;
        padding: 1 1;
    }

    #user_input {
        height: 3;
    }

    .pane-title {
        text-style: bold;
        color: #b0bec5;
    }
    """

    def __init__(self, config: DashboardConfig, interface: str | None = None) -> None:
        super().__init__()
        self.config = config
        self.interface = interface
        self.vector_store = PacketVectorStore()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="columns"):
            yield PacketLogWidget(id="packet_log")
            yield ChatPaneWidget(id="chat_pane")
        with Vertical(id="prompt_row"):
            yield Static(
                "Ask the internal AI about the network traffic below.  "
                "[b]q[/b] to quit, [b]Enter[/b] to send.",
                id="prompt_hint",
            )
            yield UserInputWidget(
                placeholder="> Ask AI about network traffic...",
                id="user_input",
            )
        yield Footer()

    def on_mount(self) -> None:
        self.title = self.config.app_name
        self.sub_title = f"Interface: {self.interface or self.config.interface}"
        self.chat_pane = self.query_one("#chat_pane", ChatPaneWidget)
        self.packet_log = self.query_one("#packet_log", PacketLogWidget)
        self._seed_from_pcap()
        self._refresh_context_status()
        self.chat_pane.add_system(
            "Chat system ready. Type a question and press Enter. "
            "The AI answers using the captured packet context."
        )
        self.start_capture()

    def _refresh_context_status(self) -> None:
        self.sub_title = (
            f"Interface: {self.interface or self.config.interface}  |  "
            f"Context: {len(self.vector_store)} packets"
        )

    def _seed_from_pcap(self) -> None:
        """Load any existing capture.pcap into the context vector store."""
        from scapy.all import PcapReader

        import os

        pcap_path = os.path.join(os.getcwd(), "capture.pcap")
        if not os.path.exists(pcap_path):
            return
        try:
            with PcapReader(pcap_path) as reader:
                packets = [pkt for pkt in reader][:200]
            added = self.vector_store.add_packets(packets)
            self._refresh_context_status()
            if added:
                self.chat_pane.add_system(
                    f"Loaded {added} packet(s) from capture.pcap into context."
                )
        except Exception as exc:  # noqa: BLE001
            self.chat_pane.add_system(f"Could not load capture.pcap: {exc}")

    @on(Input.Submitted, "#user_input")
    def on_submit(self, event: Input.Submitted) -> None:
        message = event.value.strip()
        if not message:
            event.input.clear()
            return
        self.chat_pane.add_user(message)
        event.input.clear()
        self.send_to_ai(message)

    @work(thread=True, exclusive=True)
    def send_to_ai(self, message: str) -> None:
        self._set_status("Analyzing...")
        try:
            result = query_ai(
                message,
                retriever=self.vector_store,
                model=self.config.ai_model,
                limit=5,
            )
            answer = result.get("answer", "No answer returned.")
        except Exception as exc:  # noqa: BLE001 - report inline in the chat pane
            answer = self._contextual_reply(message, exc)
        self.call_from_thread(self._deliver_ai, answer)

    def _contextual_reply(self, message: str, exc: Exception) -> str:
        """Fallback answer built from the packet context when the AI is
        unavailable (no API key / no network). Keeps the chat functional."""
        retrieved = self.vector_store.retrieve(message, k=5)
        total = len(self.vector_store)
        banner = (
            "AI provider unavailable (no/expired API key). "
            "Showing context-based summary instead."
        )
        if not retrieved:
            return (
                f"{banner}\nNo packets in the context store ({total} total) to "
                "answer from. Start/allow live capture or load a capture.pcap."
            )
        lines = [f"{banner}\nRelevant packets from context ({total} total):"]
        for index, record in enumerate(retrieved, start=1):
            summary = record.get("summary", "unknown")
            text = record.get("readable_text", "")
            if text:
                lines.append(f"  {index}. {summary} | payload: {text[:80]}")
            else:
                lines.append(f"  {index}. {summary}")
        return "\n".join(lines)

    def _deliver_ai(self, answer: str) -> None:
        self.chat_pane.add_assistant(answer)
        self._set_status(self.config.status)

    def _set_status(self, status: str) -> None:
        self.config.status = status

    @work(thread=True, exclusive=True)
    def start_capture(self) -> None:
        from scapy.all import sniff
        import os

        iface = self.interface or self.config.interface
        if os.name == "posix" and os.geteuid() != 0:
            self.call_from_thread(
                self.chat_pane.add_system,
                "Live capture needs root. Run as 'sudo python3 main.py' — "
                "or place a capture.pcap in the project folder for context.",
            )
            return
        while True:
            try:
                sniff(
                    iface=iface,
                    count=20,
                    timeout=10,
                    prn=self._on_packet,
                    store=False,
                )
            except Exception as exc:  # noqa: BLE001
                self.call_from_thread(
                    self.chat_pane.add_system,
                    f"Capture stopped or interface unavailable: {exc}",
                )
                return

    def _on_packet(self, packet) -> None:
        self.vector_store.add_packet(packet)
        self.call_from_thread(self.packet_log.log_packet, packet)
        self.call_from_thread(self._refresh_context_status)


def run_tui(config: DashboardConfig, interface: str | None = None) -> None:
    P15TUI(config, interface).run()


def main() -> None:
    from .config import create_dashboard_config

    run_tui(create_dashboard_config())
