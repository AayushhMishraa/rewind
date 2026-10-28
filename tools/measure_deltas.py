#!/usr/bin/env python3
import sys
from pathlib import Path

# Make the project root importable so `from generate_samples import ...` works
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import random
from generate_samples import make_document_text
from detection.entropy_checker import calculate_entropy_bytes

WEAK_KEY = bytes([0x5A, 0xC3, 0x17, 0x9E])
def weak_xor(data):
    return bytes(b ^ WEAK_KEY[i % 4] for i, b in enumerate(data))

rng = random.Random(42)
original = make_document_text(0, rng).encode("utf-8")
orig_size = len(original)
orig_entropy = calculate_entropy_bytes(original)

zf = bytes(orig_size)
zf_entropy = calculate_entropy_bytes(zf)

wx = weak_xor(original)
wx_entropy = calculate_entropy_bytes(wx)

legit = original + b"A person's legitimate edit.\n"
legit_size = len(legit)
legit_entropy = calculate_entropy_bytes(legit)

print(f"Original : size={orig_size}, entropy={orig_entropy:.2f}")
print(f"Zero-fill: size={orig_size}, entropy={zf_entropy:.2f} (delta size=0, entropy={zf_entropy - orig_entropy:.2f})")
print(f"Weak XOR : size={orig_size}, entropy={wx_entropy:.2f} (delta size=0, entropy={wx_entropy - orig_entropy:.2f})")
print(f"Legit edit: size={legit_size}, entropy={legit_entropy:.2f} (delta size=+{legit_size - orig_size}, entropy={legit_entropy - orig_entropy:.2f})")
