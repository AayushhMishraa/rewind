# Rewind: Behavioral Anti-Ransomware Defense for Linux

**Detects. Stopped. Undone.**

Rewind is a behavior-based anti-ransomware system for Linux that detects attacks **without signatures**, stops the attacker process, and **automatically restores** damaged files from verified clean snapshots.

Traditional antivirus matches known malware signatures — a new ransomware sample bypasses it. Rewind asks a different question: **"what is this process doing?"** Bulk-encrypting 25 files in 5 seconds is a behavior, regardless of what malware code is doing it. And because detection without recovery is not enough, Rewind's real differentiator is the **time machine**: it undoes the damage and verifies every restored file with SHA-256.

---

## How it works

The pipeline:

1. **File change detected** by the watcher (`watchdog`/inotify)
2. **Signal fused** by the detection engine (DECOY, SPEED, ENTROPY, SUSTAINED, SLOW_SUSPICION)
3. **Verdict decided**: CLEAN → save known-good copy; SUSPICIOUS → pause snapshots; CONFIRMED → respond
4. **Response**: `SIGSTOP` freezes the attacker, `SIGKILL` terminates the tree, quiet-period confirmed
5. **Recovery**: newest clean snapshot restored atomically, alien files quarantined
6. **Verification**: SHA-256 of every restored file compared against the original manifest

**Detection signals** (any one can trigger; combinations are stronger):

- **DECOY** — tampered with a `!DECOY_*` bait file (attackers iterate alphabetically, hit the trap first)
- **SPEED** — 25+ distinct files modified within 5 seconds
- **ENTROPY** — file content turned from readable text (~4.2 bits/byte) to encrypted noise (≥ 7.5)
- **SUSTAINED** — one signal persisted 3+ seconds without a break
- **SLOW_SUSPICION** — 3+ distinct files turned to noise within 60 seconds (catches slow attackers)

---

## Architecture

| Layer | Purpose | Key files |
|---|---|---|
| **Watcher** | File change events + process PID attribution via `psutil`/inotify | `watcher/file_watcher.py` |
| **Detection** | Fuse 5 signals into CLEAN / SUSPICIOUS / CONFIRMED verdict | `detection/detection_engine.py` |
| **Response** | SIGSTOP then SIGKILL the attacker process tree (R2 guarded) | `response/response_engine.py` |
| **Recovery** | Snapshots + delayed-promotion known-good + atomic restore + SHA-256 verify | `recovery/` |
| **Dashboard** | Live status, incident feed, timeline, guarded Simulate buttons | `dashboard/` |

**Stack:** Python 3.14 · Flask · psutil · watchdog · SQLite · pytest
**Platform:** Linux (inotify, POSIX signals — deliberate platform target)

---

## Testing & evaluation

**228 automated tests** across unit, integration, and live acceptance scenarios.

**13 acceptance scenarios** covering every spec requirement, traced in [`docs/acceptance_matrix.md`](docs/acceptance_matrix.md):

| ID | Scenario | Result |
|---|---|---|
| S1a | Decoy path attack | ✅ |
| S1b | Speed+entropy no-decoys | ✅ |
| S1-live | Dashboard Simulate button → real attack | ✅ |
| S2 | Attacker in a separate process family | ✅ |
| S3a | Strong XOR (high entropy) | ✅ |
| S3b | **Stealth weak XOR (SUSTAINED catches it)** | ✅ |
| S3c | Legit zip → no alarm | ✅ |
| S3d | Legit tar → no alarm | ✅ |
| S3e | Legit edits → trusted after 10 s | ✅ |
| S3f | Legit bulk edit → no alarm | ✅ |
| S4 | Snapshot timer mid-attack | ✅ |
| S5 | No echo alarm after restore | ✅ |
| S6 | Unattributed → kill nobody, restore still happens | ✅ |
| C.10 | Slow-burn attacker (1 file / 3 s) | ✅ |

**Evaluation harness** runs each scenario 5× and reports median + worst-case detection time — see [`evaluation/results.md`](evaluation/results.md).

---

## Quick start

Setup:

    git clone https://github.com/AayushhMishraa/rewind.git
    cd rewind
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python3 generate_samples.py

Run Rewind (needs root for /proc handle inspection):

    sudo -E env "PATH=$PATH" python3 main.py

In another terminal, start the dashboard:

    python3 dashboard/app.py
    # open http://127.0.0.1:5000

Click any **Simulate** button in the dashboard to trigger a real (harmless) attacker and watch Rewind detect, kill, and restore in real time.

---

## Repository structure

    rewind/
    ├── config.py                      # single source of truth: thresholds, paths, intervals
    ├── main.py                        # RewindApp orchestrator + CLI entry
    ├── generate_samples.py            # 100 test files + sandbox marker + original hashes
    │
    ├── core/                          # pipeline router, events, state, logger, activity
    ├── watcher/                       # file watcher + PID attribution + pause control
    ├── detection/                     # 5 signals → verdict
    ├── recovery/                      # snapshots, known-good (delayed promotion), restore
    ├── response/                      # R2 guard, SIGSTOP/SIGKILL, attribution sweep
    ├── dashboard/                     # Flask app + templates + static assets
    │
    ├── test_ransomware/               # harmless attackers (v1, v2, --weak, slow_3s, wiper)
    ├── tests/                         # 228 automated tests
    ├── docs/acceptance_matrix.md      # spec → test → result traceability
    ├── evaluation/                    # 5x reliability harness + results.md
    └── tools/                         # CLI inspectors + SHA-256 verifier

---

## Design rules (enforced, not just documented)

- **R1 — Separation:** detection modules judge, they don't act
- **R2 — Runtime guard:** `respond_to_attack` raises `RuntimeError` if `verdict.level != "CONFIRMED"`
- **R3 — Traceability:** every action logged as JSON-lines with `incident_trace_id`
- **R4 — Process safety:** multi-sweep attribution; if ambiguous, kill nobody
- **R5 — Self-protection:** never kill Rewind itself, its ancestor shells, or PID 1
- **R6 — Snapshot safety:** no snapshot during active alert / cooldown
- **R7 — Sandbox guard:** attacker scripts refuse to run outside a `.REWIND_SANDBOX` folder
- **R8 — Behavior over names:** no allowlists; decisions based on what a process *does*

---

## Known limitations (documented honestly)

- **Platform-specific:** Linux only (inotify, POSIX signals). Porting to Windows/Mac would require replacing the watcher and kill layers (~3 modules).
- **Slow-burn detection has a cost:** 3+ files encrypted by a *user* (not an attacker) within 60 s is flagged and rolled back. Deliberate trade-off — safety over convenience.
- **Snapshot can bake in damage:** a snapshot taken *after* an undetected slow wiper becomes the new reference. Documented in the known-good fix's docstring.
- **Containers/cgroups:** not supported. A malicious process inside a container is not isolated from the host pipeline.
- **Attacker variants not fully tested:** `copy-then-delete`, `rename-then-encrypt`, `fork-spray`, and compression-based attacks are future work.

---

## Why this project

Ransomware defense requires both **detection** (behavioral, not signature-based) and **recovery** (because detection alone can't prevent damage — it can only limit it). Rewind implements both, with real automated tests against real attacker processes, and honestly documents its limitations. It's not production-ready EDR, but the architecture — multi-signal fusion, confirmed-only response, atomic verified restore — mirrors what commercial products do.

**License:** MIT (educational/demo use).

---

*Detected. Stopped. Undone.*