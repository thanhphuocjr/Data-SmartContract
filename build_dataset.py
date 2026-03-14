"""
build_dataset.py
─────────────────
Build dataset từ kết quả phân tích smart contract (Slither).

Định dạng output:
    ID    : địa chỉ contract (ví dụ 0x0a0a7c26...)
    Code  : source code của function bị phát hiện lỗi
    Label : tên lỗ hổng theo vulnerabilities_mapping.csv

Cách dùng:
    python build_dataset.py
    python build_dataset.py --result result.json \
                            --mapping vulnerabilities_mapping.csv \
                            --sol 0xABC....sol \
                            --out_jsonl dataset.jsonl \
                            --out_csv   dataset.csv
"""

import json, csv, os, argparse, re

DEFAULT_RESULT  = "result.json"
DEFAULT_MAPPING = "vulnerabilities_mapping.csv"
DEFAULT_JSONL   = "dataset.jsonl"
DEFAULT_CSV     = "dataset.csv"

# Hardcode mapping cho các check cần ignore
IGNORE_CHECKS = {
    ("slither", "reentrancy-benign"),
    ("slither", "unused-return"),
}

# Priority order for resolving multi-labels
LABEL_PRIORITY = [
    "reentrancy",
    "access_control",
    "denial_service",
    "time_manipulation",
    "unchecked_low_calls",
    "No Vulnerability"
]

def resolve_label(labels):
    """
    Resolve multi-labels by choosing the highest priority one
    """
    if not labels:
        return "No Vulnerability"
    
    # Filter out "Ignore" and "Other"
    real_labels = [lbl for lbl in labels if lbl not in ("Ignore", "Other")]
    
    if not real_labels:
        # Only ignore/other checks found
        return "No Vulnerability"
    
    # Find the highest priority label
    for priority_label in LABEL_PRIORITY:
        if priority_label in real_labels:
            return priority_label
    
    # Default to first real label if not in priority
    return real_labels[0]


def load_result(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "stdout" in data:
        data = json.loads(data["stdout"])
    return data


def remove_comments(code):
    """
    Remove single-line (//) and multi-line (/* */) comments from Solidity code
    """
    # Remove multi-line comments /* */
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    
    # Remove single-line comments //
    lines = code.split('\n')
    cleaned_lines = []
    for line in lines:
        # Find comment start //
        comment_idx = line.find('//')
        if comment_idx != -1:
            # Keep only the part before //
            line = line[:comment_idx]
        # Remove trailing whitespace
        line = line.rstrip()
        if line:  # Only add non-empty lines
            cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)



def load_mapping(path):
    mapping = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        ignore_col = "Ignore"
        label_cols = [c for c in reader.fieldnames
                      if c not in ("Tools", "Vulnerability name", ignore_col)]
        for row in reader:
            tool  = row["Tools"].strip().lower()
            check = row["Vulnerability name"].strip()
            label = None
            for col in label_cols:
                if row.get(col, "").strip().upper() == "TRUE":
                    label = col; break
            if label is None and row.get(ignore_col, "").strip().upper() == "TRUE":
                label = "Ignore"
            if label:
                mapping[(tool, check)] = label
    
    # Add hardcoded ignore checks
    for check_key in IGNORE_CHECKS:
        mapping[check_key] = "Ignore"
    
    return mapping


def load_sol(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    return [""] + lines   # index 1-based


def find_sol_file(contract_id, base_dir=None, contracts_dir=None):
    """Find .sol file in base_dir or contracts_dir"""
    if base_dir:
        c = os.path.join(base_dir, f"{contract_id}.sol")
        if os.path.isfile(c): return c
    
    if contracts_dir:
        c = os.path.join(contracts_dir, f"{contract_id}.sol")
        if os.path.isfile(c): return c
    
    return None


def extract_code(sol_lines, line_numbers):
    return "".join(
        sol_lines[ln] for ln in line_numbers if 0 < ln < len(sol_lines)
    ).strip()

def extract_full_function(sol_lines, line_numbers):
    """
    Extract full Solidity function containing the vulnerability lines.
    Uses brace matching to detect function scope.
    """
    if not line_numbers:
        return ""

    start_line = min(line_numbers)
    end_line   = max(line_numbers)

    # Tìm dòng bắt đầu function
    func_start = start_line
    while func_start > 1:
        line = sol_lines[func_start].strip()
        if line.startswith("function") or line.startswith("constructor"):
            break
        func_start -= 1

    # Nếu không tìm thấy keyword function
    if func_start <= 1:
        func_start = start_line

    # Brace matching để tìm end
    brace_count = 0
    func_end = func_start
    started = False

    for i in range(func_start, len(sol_lines)):
        line = sol_lines[i]

        if "{" in line:
            brace_count += line.count("{")
            started = True

        if "}" in line:
            brace_count -= line.count("}")

        if started and brace_count == 0:
            func_end = i
            break

    return "".join(sol_lines[func_start:func_end+1]).strip()


def find_function_by_name(sol_lines, func_name):
    """
    Fallback: tìm function theo tên nếu Slither không trả line numbers
    """
    start = None

    for i, line in enumerate(sol_lines):
        if f"function {func_name}" in line:
            start = i
            break

    if start is None:
        return ""

    brace_count = 0
    started = False

    for i in range(start, len(sol_lines)):
        line = sol_lines[i]

        if "{" in line:
            brace_count += line.count("{")
            started = True

        if "}" in line:
            brace_count -= line.count("}")

        if started and brace_count == 0:
            return "".join(sol_lines[start:i+1]).strip()

    return ""

def build_dataset(result_path, mapping_path, sol_path=None, contracts_dir=None):
    result   = load_result(result_path)
    mapping  = load_mapping(mapping_path)

    contract_id = result["contract"]
    tool        = result["tool"].strip().lower()

    if sol_path is None:
        sol_path = find_sol_file(
            contract_id,
            base_dir=os.path.dirname(os.path.abspath(result_path)),
            contracts_dir=contracts_dir
        )
    if not sol_path or not os.path.isfile(sol_path):
        raise FileNotFoundError(
            f"Không tìm thấy '{contract_id}.sol'. "
            f"Đặt file cùng thư mục hoặc dùng --sol <path> or --contracts-dir <path>."
        )

    sol_lines = load_sol(sol_path)
    print(f"[INFO] Contract : {contract_id}")
    print(f"[INFO] Sol file : {sol_path}  ({len(sol_lines)-1} dòng)")

    functions = {}
    skipped = []

    for item in result["analysis"]:
        check = item["check"]
        label = mapping.get((tool, check))
        if label is None:
            skipped.append(check); continue

        func_elements = [e for e in item.get("elements", [])
                         if e.get("type") == "function"]
        if not func_elements:
            skipped.append(f"{check}(no func)"); continue

        seen = set()
        for el in func_elements:
            lines = el.get("source_mapping", {}).get("lines", [])

            if lines:
                code = extract_full_function(sol_lines, lines)
            else:
                code = find_function_by_name(sol_lines, el["name"])
            
            # Remove comments from code
            code = remove_comments(code)
            
            key   = (el["name"], lines[0] if lines else 0)
            if key in seen: continue
            seen.add(key)
            
            func_key = (contract_id, el["name"])
            if func_key not in functions:
                functions[func_key] = {
                    "id": contract_id,
                    "code": code,
                    "label_checks": {},  # Map label -> list of checks
                    "function": el["name"],
                    "lines": f"{lines[0]}-{lines[-1]}" if lines else ""
                }

            # Track checks per label
            if label not in functions[func_key]["label_checks"]:
                functions[func_key]["label_checks"][label] = []
            functions[func_key]["label_checks"][label].append(check)
            
    if skipped:
        print(f"[WARN] Bỏ qua: {sorted(set(skipped))}")
        
    records = []

    for f in functions.values():
        # Get all labels
        all_labels = list(f["label_checks"].keys())
        
        # Resolve to single label using priority
        chosen_label = resolve_label(all_labels)
        
        # Get checks for the chosen label
        chosen_checks = f["label_checks"].get(chosen_label, [])
        
        records.append({
            "id": f["id"],
            "code": f["code"],
            "label": chosen_label,
            "check": chosen_checks,
            "function": f["function"],
            "lines": f["lines"]
        })
    
    return records


def save_jsonl(records, path):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            # Gộp lists thành string nếu cần
            label = r["label"]
            if isinstance(label, list):
                label = label
            check = r.get("check", [])
            if isinstance(check, list):
                check = check
            
            f.write(json.dumps(
                {
                    "id": r["id"],
                    "code": r["code"],
                    "label": label,
                    "check": check,
                    "function": r.get("function", ""),
                    "lines": r.get("lines", "")
                },
                ensure_ascii=False
            ) + "\n")
    print(f"[OK]  JSONL : {path}  ({len(records)} records)")


def save_csv(records, path):
    if not records: return
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "code", "label", "check", "function", "lines"])
        for r in records:
            label = r["label"]
            if isinstance(label, list):
                label = "|".join(sorted(label))
            check = r.get("check", [])
            if isinstance(check, list):
                check = "|".join(sorted(set(check)))  # Use set to avoid duplicates
            else:
                check = str(check)
            w.writerow([
                r["id"], 
                r["code"], 
                label,
                check,
                r.get("function", ""),
                r.get("lines", "")
            ])
    print(f"[OK]  CSV  : {path}  ({len(records)} records)")


def main():
    parser = argparse.ArgumentParser(description="Build dataset from SmartBugs contract analysis results")
    parser.add_argument("--result",        default=None,
                        help="Path to result.json file (or --result-dir for batch)")
    parser.add_argument("--result-dir",    default=None,
                        help="Directory containing result.json files (batch mode)")
    parser.add_argument("--mapping",       default=DEFAULT_MAPPING,
                        help="Path to vulnerabilities_mapping.csv")
    parser.add_argument("--sol",           default=None,
                        help="Path to specific .sol file")
    parser.add_argument("--contracts-dir", default=None,
                        help="Directory containing .sol contract files")
    parser.add_argument("--out_jsonl",     default=DEFAULT_JSONL)
    parser.add_argument("--out_csv",       default=DEFAULT_CSV)
    args = parser.parse_args()

    # If no result specified, show help
    if not args.result and not args.result_dir:
        parser.print_help()
        print("\n" + "="*60)
        print("EXAMPLE USAGE:")
        print("="*60)
        print("\n1. Single contract:")
        print('   python3 build_dataset.py \\')
        print('     --result "/path/to/result.json" \\')
        print('     --contracts-dir "/path/to/contracts" \\')
        print('     --mapping "/path/to/vulnerabilities_mapping.csv"')
        print("\n2. Batch mode (all contracts in folder):")
        print('   python3 build_dataset.py \\')
        print('     --result-dir "/path/to/results/slither/icse20" \\')
        print('     --contracts-dir "/path/to/contracts" \\')
        print('     --mapping "/path/to/vulnerabilities_mapping.csv"')
        return

    # Batch mode
    if args.result_dir:
        if not os.path.isdir(args.result_dir):
            print(f"[ERROR] Directory not found: {args.result_dir}")
            return
        
        all_records = []
        result_files = []
        
        # Find all result.json files
        for root, dirs, files in os.walk(args.result_dir):
            if "result.json" in files:
                result_files.append(os.path.join(root, "result.json"))
        
        print(f"[INFO] Found {len(result_files)} result files")
        
        for i, result_file in enumerate(result_files, 1):
            try:
                records = build_dataset(result_file, args.mapping,
                                      sol_path=args.sol,
                                      contracts_dir=args.contracts_dir)
                all_records.extend(records)
                print(f"[{i}/{len(result_files)}] OK")
            except Exception as e:
                print(f"[{i}/{len(result_files)}] ERROR: {e}")
        
        print(f"\n{'─'*60}")
        print(f"  Total records : {len(all_records)}")
        lc = {}
        cc = {}
        for r in all_records:
            label = r["label"]
            if isinstance(label, list):
                label = label[0] if label else "Unknown"
            lc[label] = lc.get(label, 0) + 1
            
            checks = r.get("check", [])
            if not isinstance(checks, list):
                checks = [checks] if checks else []
            for chk in checks:
                cc[chk] = cc.get(chk, 0) + 1
        
        print(f"\n  Vulnerability Labels:")
        for lbl, cnt in sorted(lc.items(), key=lambda x: -x[1]):
            print(f"    {lbl:30s}: {cnt:6d}")
        
        print(f"\n  Detected Checks (top 15):")
        for chk, cnt in sorted(cc.items(), key=lambda x: -x[1])[:15]:
            print(f"    {chk:50s}: {cnt:6d}")
        print(f"{'─'*60}\n")
        
        save_jsonl(all_records, args.out_jsonl)
        save_csv(all_records,   args.out_csv)
        return

    # Single contract mode
    records = build_dataset(args.result, args.mapping, 
                           sol_path=args.sol, 
                           contracts_dir=args.contracts_dir)

    print(f"\n{'─'*60}")
    print(f"  Tổng records : {len(records)}")
    lc = {}
    cc = {}
    for r in records:
        label = r["label"]
        if isinstance(label, list):
            label = label[0] if label else "Unknown"
        lc[label] = lc.get(label, 0) + 1
        
        checks = r.get("check", [])
        if not isinstance(checks, list):
            checks = [checks] if checks else []
        for chk in checks:
            cc[chk] = cc.get(chk, 0) + 1
    
    print(f"\n  Vulnerability Labels:")
    for lbl, cnt in sorted(lc.items(), key=lambda x: -x[1]):
        print(f"    {lbl:30s}: {cnt:6d}")
    
    print(f"\n  Detected Checks (top 10):")
    for chk, cnt in sorted(cc.items(), key=lambda x: -x[1])[:10]:
        print(f"    {chk:50s}: {cnt:6d}")
    print(f"{'─'*60}\n")

    # Preview 3 records
    for r in records[:3]:
        print(f"ID       : {r['id']}")
        print(f"Function : {r.get('function', 'N/A')}")
        print(f"Lines    : {r.get('lines', 'N/A')}")
        checks_str = ", ".join(r.get('check', []))
        print(f"Check    : {checks_str}")
        print(f"Label    : {r['label']}")
        print(f"Code     : {r['code'][:120]}{'...' if len(r['code'])>120 else ''}")
        print()

    save_jsonl(records, args.out_jsonl)
    save_csv(records,   args.out_csv)


if __name__ == "__main__":
    main()