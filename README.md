# Rewind: Behavioral Anti-Ransomware Defense for Linux

Detects, stops, and reverses ransomware attacks **without signatures** — pure behavior.
Watches file changes → multi-signal detection (decoy, entropy, speed, sustained) →
SIGSTOP + SIGKILL attacker → restore from clean snapshot → SHA-256 verify.

**Status:** 211 tests passing. 13/13 spec acceptance scenarios green (see `docs/acceptance_matrix.md`).

**Stack:** Python 3.14 · Flask · psutil · watchdog · SQLite · pytest
**Runs on:** Linux (inotify, POSIX signals)

## Quick start

    python3 generate_samples.py
    sudo -E env "PATH=$PATH" python3 main.py
    python3 dashboard/app.py    # dashboard at http://127.0.0.1:5000
