import os
import shutil
import pytest
from lambda_function import generate_rules, parse_csv, save_rules_to_s3, load_csv, normalize_source
from unittest.mock import patch

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
    
def test_generate_rules_custom_vpc(monkeypatch):
    mock_cidr = "10.0.0.0/16"
    monkeypatch.setattr("lambda_function.get_vpc_cidr", lambda vpc_id: mock_cidr)
    input_path = os.path.join(INPUT_DIR, "input_sample_vpc.csv")
    output_path = os.path.join(OUTPUT_DIR, "output_sample_vpc.txt")

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

def test_generate_rules_multiple_vpc():
    vpc_to_cidr = {
        "vpc-111111": "10.0.0.0/16",
        "vpc-222222": "10.2.0.0/16",
    }

    input_path = os.path.join(INPUT_DIR, "input_sample_multiple_vpc.csv")
    output_path = os.path.join(OUTPUT_DIR, "output_sample_multiple_vpc.txt")
    with open(input_path, "r", encoding="utf-8") as f:
        lines = f.read()

    with open(output_path, "r") as f:
        expected_output = f.read().splitlines()

    with patch("lambda_function.get_vpc_cidr") as mock_get_cidr:
        mock_get_cidr.side_effect = lambda vpc_id: vpc_to_cidr.get(vpc_id, None)
        rules = generate_rules(lines)



    assert isinstance(rules, list)
    assert len(rules) > 0, "No rules were generated!"
    assert len(rules) == len(expected_output), "Mismatch in number of generated rules"

    for i in range(len(rules)):
        print(f"Generated: {rules[i]}")
        print(f"Expected : {expected_output[i]}")
        assert rules[i] == expected_output[i]        
        
def test_normalize_source_multiple_vpcs(monkeypatch):
    mock_cidrs = {
        "vpc-111111": "10.0.0.0/16",
        "vpc-222222": "10.2.0.0/16",
    }

    def mock_get_vpc_cidr(vpc_id):
        return mock_cidrs.get(vpc_id)

    monkeypatch.setattr("lambda_function.get_vpc_cidr", mock_get_vpc_cidr)

    result = normalize_source("vpc-111111;vpc-222222")
    assert result == "[10.0.0.0/16, 10.2.0.0/16]"

    result = normalize_source("vpc-111111")
    assert result == "10.0.0.0/16"

    result = normalize_source("")
    assert result == "$HOME_NET"