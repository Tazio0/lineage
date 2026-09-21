# Lineage

[![Lineage CI](https://github.com/Tazio0/lineage/actions/workflows/ci.yml/badge.svg)](https://github.com/Tazio0/lineage/actions/workflows/ci.yml)

eBPF runtime detector for suspicious process spawning on Linux.

Lineage monitors `execve` events and classifies parent-child process relationships to detect when services spawn unexpected shells — a common indicator of compromise.

## Why this matters

When an attacker exploits a web server, database, or other network service, one of the first things they do is spawn a shell (`/bin/sh`, `bash`, etc.) to run commands. This is documented as [MITRE ATT&CK T1059.004 — Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/).

A process like `nginx` or `postgres` should never spawn a shell under normal operation. When it does, that's a strong signal of compromise. Lineage watches for exactly this pattern in real time at the kernel level.

## Architecture

```
┌──────────────────────────────────┐
│           Linux Kernel           │
│                                  │
│  sched_process_exec tracepoint   │
│         ▼                        │
│  ┌─────────────────────┐         │
│  │  exec_probe.c (eBPF)│         │
│  │  extracts: PID, PPID│         │
│  │  comm, filename, UID │        │
│  └────────┬────────────┘         │
│           │ perf buffer          │
└───────────┼──────────────────────┘
            ▼
┌──────────────────────────────────┐
│        User-Space Python         │
│                                  │
│  detector.py ── reads events     │
│       ▼                          │
│  engine.py ── classifies parent  │
│       ▼                          │
│  alerts.py ── formats alert with │
│               MITRE tag + reason │
│       ▼                          │
│  stdout (analyst / SIEM)         │
└──────────────────────────────────┘
```

**Kernel layer**: An eBPF probe attached to the `sched_process_exec` tracepoint captures every `execve` call system-wide. It extracts the parent process name, child binary path, PID, PPID, and UID, then pushes a struct through a perf buffer to user space.

**User-space layer**: The Python engine receives these events and classifies the parent process against known baselines:
- **Legitimate** parents (terminal emulators, shells) are silently ignored.
- **High-risk** parents (web servers, databases, SSH daemon) trigger a CRITICAL alert.
- **Unknown** parents trigger a WARNING alert.

The engine has zero dependency on BCC or the kernel — it works with plain Python data and is fully unit-testable.

## Sample output

```
[2026-09-12T18:30:01.123456+00:00] CRITICAL: parent=nginx child=sh uid=33 mitre=T1059 — nginx is a high-risk service and spawned sh
[2026-09-12T18:30:45.654321+00:00] WARNING: parent=evince child=bash uid=1000 mitre=T1059 — evince is not recognised and spawned bash
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # bash/zsh
source .venv/bin/activate.fish   # fish
pip install -r requirements-dev.txt
```

### Running the detector (requires root and BCC)

```bash
sudo python3 -m lineage.detector
```

This requires:
- Linux with BCC installed (`apt install bpfcc-tools python3-bpfcc` on Debian/Ubuntu)
- Kernel headers matching your running kernel
- Root privileges (eBPF needs kernel access)

## Tests

```bash
pytest tests/ -v
# or: make test
```

All tests run without BCC or kernel access. They simulate kernel events as plain Python data.

## Lint & format

```bash
ruff check lineage/ tests/
black --check lineage/ tests/
# or: make lint (check) / make format (auto-fix)
```

## Project structure

```
lineage/
├── lineage/
│   ├── engine.py      # classification logic (BCC-free, independently testable)
│   ├── alerts.py      # alert formatting with MITRE ATT&CK tagging
│   └── detector.py    # kernel event listener, loads eBPF probe via BCC
├── probes/
│   └── exec_probe.c   # eBPF C probe (compiled at runtime by BCC)
├── tests/
│   ├── test_engine.py    # unit tests for classification
│   ├── test_alerts.py    # unit tests for alert formatting
│   ├── test_detector.py  # unit tests for event decoding
│   └── test_scenarios.py # acceptance tests (full pipeline simulation)
├── Makefile           # developer task automation
├── pyproject.toml     # tool configuration (ruff, black)
└── requirements-dev.txt
```

## License

MIT

<!-- WTC-Q3ZURWH7 -->
