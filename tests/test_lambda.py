import os
import shutil
import pytest
from lambda_function import generate_rules, parse_csv, save_rules_to_s3, load_csv

# Paths for local test files
INPUT_DIR = os.path.join("tests", "inputs")
OUTPUT_DIR = os.path.join("tests", "outputs")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "suricata.rules")

# -------------------------------
# Test CSV parsing
# -------------------------------
def test_parse_csv():
    csv_content = "domain,subdomain,action,protocol,log\nexample.com,,pass,tls,1"
    rows = parse_csv(csv_content)
    assert len(rows) == 1
    assert rows[0]['domain'] == "example.com"
    assert rows[0]['protocol'] == "tls"

# -------------------------------
# Test full rule generation
# -------------------------------
def test_generate_rules_basic():
    input_path = os.path.join(INPUT_DIR, "input_sample_basic.csv")
    output_path = os.path.join(OUTPUT_DIR, "output_sample_basic.txt")

    with open(input_path, "r", encoding="utf-8") as f:
        lines = f.read()

    with open(output_path, "r") as f:
        expected_output = f.read().splitlines()

    rules = generate_rules(lines)
    assert isinstance(rules, list)
    assert len(rules) > 0, "No rules were generated!"
    assert len(rules) == len(expected_output), "Mismatch in number of generated rules"

    for i in range(len(rules)):
        print(f"Generated: {rules[i]}")
        print(f"Expected : {expected_output[i]}")
        assert rules[i] == expected_output[i]
    
