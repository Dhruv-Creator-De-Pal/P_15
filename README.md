# P_15

A command-line assistant for inspecting, storing, and reasoning about local network traffic. It captures session data, keeps a local record of what it sees, and optionally consults a language model to help interpret the results.

Built in Python with a dependency list small enough to be readable, and designed to run on any 64-bit Linux/Unix host (x86-64 or ARM64) where a wired interface is available.

---

## Overview

P_15 streamlines the everyday workflow of examining traffic on a local interface. Instead of juggling raw capture files, ad-hoc scripts, and manual lookup, it offers:

- A guided startup routine that checks privileges, detects usable interfaces, and validates the environment before anything runs.
- A capture routine that writes new observations to a PCAP file for later review.
- A small local store and a query path that can enrich raw bytes with human-readable context.
- An optional AI component for summarizing or asking questions about what was collected.

The project favors clarity and determinism over complexity. Each step is explicit, logged to the terminal, and easy to trace.

---

## Features

- **Environment validation** — confirms elevated privileges and picks a live interface before capture begins.
- **Interface selection** — lists available wired interfaces and lets you choose one.
- **Traffic recording** — writes captured frames to `capture.pcap` for offline inspection.
- **Decoded context** — reconstructs frames from stored bytes and surfaces readable payloads when present.
- **Optional AI analysis** — summarizes sessions or answers questions about collected records using your own model key.
- **Local-only by default** — logs and the SQLite store stay on the machine; nothing leaves it except an explicit AI request you trigger.

---

## Requirements

- **Python 3.10+**
- **Root / Administrator privileges** — required to read from network interfaces.
- **Linux/Unix** operating system.
- A wired interface whose name begins with `eth`.

No compiled binaries are required. The tool runs wherever Python runs, on both **x86-64** and **ARM64** hosts (e.g. desktop Linux, Raspberry Pi 4/5, or a cloud ARM instance).

---

## Installation

```bash
cd P_15
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Configure credentials (optional)

AI-powered features need a provider key. Copy the template and fill it in:

```bash
cp .env.example .env
```

The startup flow also prompts for provider keys and writes them to `.env` for you. The `.env` file is excluded from version control.

---

## Usage

```bash
sudo python main.py
```

On Windows, run from an elevated (Administrator) terminal instead.

### What happens

1. The tool verifies it has the privileges needed to open an interface.
2. It lists available wired interfaces and asks which one to use.
3. It performs a short trial capture to confirm the interface is live.
4. It records frames to `capture.pcap` and reports how many were seen.

Example session:

```
Welcome to the P_15..........(Network Sniffer and Analyzer Tool)
Checking for root/administrator privileges...
Root privileges confirmed. Proceeding with the script.
Checking for network interfaces...
Available Ethernet interfaces:
eth0

Please select the ethernet interface you want to use for sniffing: eth0
Ethernet interface is up and running.
All checks passed. Proceeding with the script.
Starting packet sniffing...
Captured 10 packets.
```

---

## Configuration

Settings live in an optional `.env` file or as environment variables.

| Variable | Purpose | Default |
| --- | --- | --- |
| `OPENAI_API_KEY` | OpenAI provider key | — |
| `GEMINI_API_KEY` | Gemini provider key | — |
| `ANTHROPIC_API_KEY` | Anthropic provider key | — |
| `HF_TOKEN` | Hugging Face token | — |
| `AI_MODEL` | Default model identifier | `openai:gpt-4o-mini` |

The capture layer reads no configuration of its own; frame counts and rotation are handled by the routine in `p_15/snifer.py`.

---

## Project structure

```
P_15/
├── main.py              # Entry point
├── requirements.txt     # Python dependencies
├── .env.example         # Credential template (placeholder only)
├── capture.pcap         # Latest recording file
└── p_15/
    ├── __init__.py
    ├── test.py          # Privilege, interface, and pre-run checks
    ├── snifer.py        # Capture and frame decoding
    ├── ai_engine.py     # Optional AI analysis helpers
    └── config.py        # Dashboard configuration state
```

---

## Troubleshooting

**"No ethernet interfaces found"**
Check your interfaces with `ip link show`. The tool looks for names beginning with `eth`; a wireless interface (e.g. `wlan0`) is not matched.

**"Please run the script as root"**
Use `sudo python main.py` on Linux/macOS, or run the terminal as Administrator on Windows.

**"Ethernet interface is down"**
Bring it up: `sudo ip link set eth0 up`, then confirm with `ip link show eth0`.

**Capture permissions denied**
Scapy needs elevated privileges to open raw sockets. Ensure you are running with `sudo`/Administrator and that the interface is not administratively down.

---

## Notes

- Elevated privileges are required to open network interfaces.
- Recordings are written to `capture.pcap`, a local file.
- Stored data lives in the local SQLite database and is not transmitted.
- Network data may be sensitive. Only run this on interfaces and networks you are authorized to inspect, and review `.env` before sharing the repository.
