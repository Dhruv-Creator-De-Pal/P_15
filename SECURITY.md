# Security Policy

## Reporting a Vulnerability

Please do **not** open a public issue for security problems. Report privately through the repository owner's preferred secure channel (see the project's GitHub security advisories) and include as much detail as possible: affected version, steps to reproduce, and impact.

You should receive an acknowledgement within 72 hours. If the issue is confirmed, we will coordinate a fix and disclosure.

## Scope

The following are in scope:

- Privilege escalation or code execution via captured packet data.
- Injection of malicious prompts or packet fields into the AI analysis path.
- Data leakage outside the local machine beyond what the user explicitly triggers.

## Notes for Contributors and Users

- **Secrets live in `.env`, which is gitignored.** Never commit `.env`, API keys, tokens, or other credentials. Use `.env.example` as the template and leave API keys blank by default.
- **Captures are sensitive.** Files under `data/` and any `*.pcap` output may contain real network traffic (SSIDs, MAC addresses, IPs, payloads). They are gitignored and must not be committed or pushed.
- **Local-only by default.** Logs and the SQLite store stay on the machine. Data leaves the machine only when you explicitly make an AI request.
- **The tool requires root/administrator privileges** to read network interfaces. Run it only on networks you own or are authorized to monitor.