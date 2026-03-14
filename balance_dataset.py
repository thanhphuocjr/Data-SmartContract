import json
import random
import csv
from collections import Counter

input_file = "dataset.jsonl"
output_jsonl = "dataset_balanced.jsonl"
output_csv = "dataset_balanced.csv"

records = []

# ----------------------
# Load dataset
# ----------------------
with open(input_file, encoding="utf-8") as f:
    for line in f:
        records.append(json.loads(line))

no_vul = []
vul = []

# ----------------------
# Split class (handle single label as string)
# ----------------------
for r in records:
    label = r.get("label", "Unknown")
    
    # Handle both string and list formats
    if isinstance(label, list):
        label = label[0] if label else "Unknown"

    if label == "No Vulnerability":
        no_vul.append(r)
    else:
        vul.append(r)

print("Original dataset")
print(f"No Vulnerability: {len(no_vul):,}")
print(f"Vulnerabilities: {len(vul):,}")

# ----------------------
# Balance dataset
# ----------------------

TARGET_NO_VUL = 30000

no_vul_sample = random.sample(
    no_vul,
    min(TARGET_NO_VUL, len(no_vul))
)

balanced = vul + no_vul_sample
random.shuffle(balanced)

print(f"\nBalanced dataset: {len(balanced):,}")

# ----------------------
# Label distribution
# ----------------------

counter = Counter()

for r in balanced:
    label = r.get("label", "Unknown")
    if isinstance(label, list):
        label = label[0] if label else "Unknown"
    counter[label] += 1

print("\nLabel distribution:")
for k, v in sorted(counter.items(), key=lambda x: -x[1]):
    pct = 100 * v / len(balanced)
    print(f"{k:25s} {v:7,d} ({pct:5.1f}%)")

# ----------------------
# Save JSONL
# ----------------------

with open(output_jsonl, "w", encoding="utf-8") as f:
    for r in balanced:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

# ----------------------
# Save CSV (Updated for single-label format)
# ----------------------

with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)

    writer.writerow([
        "id",
        "function",
        "lines",
        "check",
        "label",
        "code"
    ])

    for r in balanced:
        label = r.get("label", "Unknown")
        if isinstance(label, list):
            label = label[0] if label else "Unknown"
        
        checks = r.get("check", [])
        if isinstance(checks, list):
            checks_str = "|".join(checks)
        else:
            checks_str = str(checks)
        
        writer.writerow([
            r.get("id", ""),
            r.get("function", ""),
            r.get("lines", ""),
            checks_str,
            label,
            r.get("code", "")
        ])

print(f"\nSaved JSONL: {output_jsonl}")
print(f"Saved CSV:   {output_csv}")
