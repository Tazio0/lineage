# Lineage

eBPF runtime detector for suspicious process spawning on Linux.

Lineage monitors `execve` events and classifies parent-child process relationships to detect when services spawn unexpected shells — a common indicator of compromise.

## How it works

1. An eBPF probe (planned) captures `execve` events from the kernel
2. The Python engine classifies the parent process against known baselines
3. Alerts are generated with severity levels and MITRE ATT&CK tags

Classification levels:
- **CRITICAL** — a high-risk service (e.g. `nginx`, `sshd`) spawned a shell
- **WARNING** — an unrecognised process spawned a shell
- **NONE** — expected behavior (e.g. terminal emulator spawning `bash`)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # bash/zsh
source .venv/bin/activate.fish   # fish
pip install -r requirements-dev.txt
```

## Tests

```bash
pytest tests/ -v
```

## Lint

```bash
ruff check lineage/ tests/
black --check lineage/ tests/
```

## Project structure

```
lineage/
├── lineage/
│   ├── engine.py      # classification logic (BCC-free, independently testable)
│   ├── alerts.py      # alert formatting with MITRE ATT&CK tagging
│   └── detector.py    # kernel event listener (planned)
├── probes/
│   └── exec_probe.c   # eBPF probe (planned)
├── tests/
│   ├── test_engine.py
│   └── test_alerts.py
└── requirements-dev.txt
```

## License

MIT

<!-- WTC-Q3ZURWH7 -->
