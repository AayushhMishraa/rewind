"""Rewind configuration: the single source of truth for every setting and threshold.

Paths are absolute (built from this file's location) so Rewind behaves the same
no matter which folder you start it from.
"""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Paths ---
PROTECTED_DIR = os.path.join(BASE_DIR, "protected_folder")
SAFETY_DIR = os.path.join(BASE_DIR, "safety_copies")
TEST_DATA_DIR = os.path.join(BASE_DIR, "test_data")
HASHES_PATH = os.path.join(TEST_DATA_DIR, "original_hashes.json")
DB_PATH = os.path.join(BASE_DIR, "rewind.db")
LOG_PATH = os.path.join(BASE_DIR, "rewind.log")
SENTINEL_NAME = ".REWIND_SANDBOX"      # marker file proving a folder is a safe test sandbox
DECOY_PREFIX = "!DECOY_"               # '!' sorts first alphabetically (unlike '~')

# --- Sample data ---
SAMPLE_COUNT = 100
SAMPLE_MIN_BYTES = 8192                # small files can't reach high entropy, so keep them big

# --- Speed signal (ONE unit: distinct files changed per window) ---
SPEED_WINDOW_SECONDS = 5
SPEED_MIN_DISTINCT_FILES = 25          # >= 25 distinct files in 5s (= 5 files/sec)

# --- Entropy signal ---
ENTROPY_THRESHOLD = 7.5                # new entropy must be >= this
ENTROPY_BASELINE_MAX = 6.5             # file must have been BELOW this before
ENTROPY_MIN_FILE_BYTES = 4096          # smaller files can't reach 7.5; skip them
ENTROPY_SAMPLE_BYTES = 65536           # only read the first 64 KB of a file

# --- Escalation ---
SUSTAINED_SUSPICION_SECONDS = 3
SUSPICION_GAP_RESET_SECONDS = 2

# --- Recovery ---
SNAPSHOT_INTERVAL_SECONDS = 30
SNAPSHOT_KEEP = 5
SNAPSHOT_COOLDOWN_AFTER_ALERT = 10
POISONED_SNAPSHOT_RATIO = 0.20         # >20% high-entropy files -> reject snapshot
QUIET_PERIOD_SECONDS = 2
QUIET_MAX_WAIT_SECONDS = 10

# --- Response ---
MAX_ATTRIBUTION_SWEEP_SUSPECTS = 3
UNATTRIBUTED_PID = -1
FOLDER_WIDE_ACTOR = "*"

# --- Dashboard ---
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000

# --- Speed signal: the burst must still be happening (added in Stage 2) ---
SPEED_RECENT_SECONDS = 1               # "right now" = the last 1 second
SPEED_RECENT_MIN_FILES = 3             # at least 3 distinct files changed in that second

# --- Response engine (added in Stage 4) ---
RESPONSE_SWEEP_COUNT = 20              # how many quick looks for the attacker...
RESPONSE_SWEEP_INTERVAL = 0.05         # ...this many seconds apart (about 1 s in total)
SUSPECT_MIN_CPU_SECONDS = 0.02         # a "cwd only" suspect must have used at least this much CPU
KILL_WAIT_SECONDS = 3                  # how long to wait for killed processes to disappear

# --- Pipeline (added in Stage 5) ---
ELEVATED_CALM_SECONDS = 5              # no suspicious events for this long -> back to NORMAL
