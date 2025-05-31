import json
import os
import sys
import csv
import pandas as pd

# Set working directory to script's parent directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ""))  # or further up if needed
sys.path.insert(0, ROOT_DIR)

TOP25_CWE_PATH = os.path.join(ROOT_DIR, "top_25cwe.csv")
CVE_INPUT_PATH = os.path.join(ROOT_DIR, "patch_db_cwe.json")
OUTPUT_PATH = os.path.join(ROOT_DIR, "patch_db_cwe_names.json")

def filter_entries_with_cwe(input_file: str, output_file: str) -> None:
    input_path = os.path.join(ROOT_DIR, input_file)
    output_path = os.path.join(ROOT_DIR, output_file)

    with open(input_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    filtered = [entry for entry in records if entry.get("CWE_ID", "NA") != "NA"]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(filtered, f, indent=2)

    print(f"✅ Filtered {len(filtered)} entries saved to {output_path}")

def load_top25_cwe(csv_path: str) -> dict:
    cwe_map = {}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe_id = row.get("CWE-ID", "").strip()
            name = row.get("Name", "").strip()
            if cwe_id and name:
                cwe_map[cwe_id] = name
    return cwe_map

def load_cve_examples(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def attach_cwe_names(cve_data: list, cwe_map: dict) -> list:
    for entry in cve_data:
        cwe_id = entry.get("CWE_ID", "").strip()
        entry["CWE_Name"] = cwe_map.get(cwe_id, cwe_id)
    return cve_data


if __name__ == "__main__":
    # keep the CWE records
    # filter_entries_with_cwe("patch_db.json", "patch_db_cwe.json")

    # cwe_dict = load_top25_cwe(TOP25_CWE_PATH)
    # print(f"✅ Loaded {len(cwe_dict)} CWE mappings from Top 25")

    # cve_data = load_cve_examples(CVE_INPUT_PATH)
    # print(f"🔍 Loaded {len(cve_data)} CVE entries")

    # enriched = attach_cwe_names(cve_data, cwe_dict)
    # print(f"✅ All records now have CWE_Name (top 25 name or original ID)")

    # with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    #     json.dump(enriched, f, indent=2)
    # print(f"📦 Output written to {OUTPUT_PATH}")

    df = pd.read_csv(TOP25_CWE_PATH)
    json_data = df.to_json(orient="records", indent=2)
    with open("cwe_top25.json", "w", encoding="utf-8") as f:
        f.write(json_data)
    print(f"✅ Converted {TOP25_CWE_PATH} to JSON format")