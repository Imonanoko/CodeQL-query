#!/usr/bin/env python3


import argparse
import csv
import os
from typing import List

REQUIRED_FILES: List[str] = [
    "CWE-022.csv", "CWE-078.csv", "CWE-079.csv", "CWE-095.csv", "CWE-113.csv",
    "CWE-117.csv", "CWE-326.csv", "CWE-327.csv", "CWE-329.csv", "CWE-347.csv",
    "CWE-377.csv", "CWE-502.csv", "CWE-643.csv", "CWE-760.csv", "CWE-918.csv",
    "CWE-943.csv", "CWE-1333.csv",
]

def repo_leaf_from_full_name(full_name: str) -> str:
    full_name = (full_name or "").strip().strip("/")
    if "/" in full_name:
        return full_name.split("/")[-1]
    return full_name

def folder_for_row(base_dir: str, full_name: str) -> str:
    return os.path.join(base_dir, repo_leaf_from_full_name(full_name))

def missing_required_files(folder: str) -> List[str]:
    missing = []
    for fname in REQUIRED_FILES:
        path = os.path.join(folder, fname)
        if not os.path.isfile(path):
            missing.append(fname)
    return missing

def main():
    parser = argparse.ArgumentParser(description="Check for required CWE CSVs per repo folder.")
    parser.add_argument("--input-csv", required=True, help="Path to the input CSV containing at least a 'full_name' column.")
    parser.add_argument("--base-dir", required=True, help="Root directory that contains per-repo folders (<base-dir>/<repo>/).")
    parser.add_argument("--output-csv", required=True, help="Path to write rows where required files are missing.")
    parser.add_argument("--include-missing-list", action="store_true",
                        help="Append a 'missing_files' column with a semicolon-separated list of missing CSVs.")
    args = parser.parse_args()

    with open(args.input_csv, newline="", encoding="utf-8") as f_in:
        reader = csv.DictReader(f_in)
        if "full_name" not in reader.fieldnames:
            raise SystemExit("Input CSV must contain a 'full_name' column.")
        input_fieldnames = reader.fieldnames[:]

        output_fieldnames = input_fieldnames[:]
        if args.include_missing_list and "missing_files" not in output_fieldnames:
            output_fieldnames.append("missing_files")

        os.makedirs(os.path.dirname(os.path.abspath(args.output_csv)), exist_ok=True)

        with open(args.output_csv, "w", newline="", encoding="utf-8") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=output_fieldnames)
            writer.writeheader()

            for row in reader:
                full_name = row.get("full_name", "")
                target_folder = folder_for_row(args.base_dir, full_name)
                missing = missing_required_files(target_folder)

                if missing:
                    if args.include_missing_list:
                        row = dict(row)
                        row["missing_files"] = ";".join(missing)
                    writer.writerow(row)

if __name__ == "__main__":
    main()
