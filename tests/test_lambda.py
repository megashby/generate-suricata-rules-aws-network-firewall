import os
import shutil
import pytest
from lambda_function import generate_rules, parse_csv, save_rules, load_csv

# Paths for local test files
INPUT_DIR = os.path.join("tests", "inputs")
OUTPUT_DIR = os.path.join("tests", "outputs")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "suricata.rules")

# Ensure outputs directory exists and is empty before each test
@pytest.fixture(autouse=True)
def clean_outputs():
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    yield
    # Optionally clean up after test
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)

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
    csv_content = """domain,subdomain,action,protocol,log
evil.com,**,drop,"tls;http",1
nice.com,"evil;bad;",drop,tls,1
test.org,,pass,http,0
test.com,badsubdomain,drop,,1
test.com,*,,,0
"""
    rules = generate_rules(csv_content)
    
    # Example assertion: check the start and end of the rule set
    assert rules[0].startswith("alert tls $HOME_NET")  # first rule is alert for logging
    assert rules[-1].startswith("pass tls $HOME_NET")  # last rule is a pass/drop rule

    # Assert total number of rules is as expected
    # You can also assert full content as a single string if desired
    expected_rules_str = "\n".join(rules)
    assert "evil.com" in expected_rules_str
    assert "test.com" in expected_rules_str
    assert "nice.com" in expected_rules_str

# -------------------------------
# Test load_csv and save_rules with local files
# -------------------------------
def test_load_and_save_rules_local():
    # Load CSV from local file
    csv_content = load_csv()
    rules = generate_rules(csv_content)

    # Save rules locally
    save_rules(rules)

    # Check that output file was created
    assert os.path.exists(OUTPUT_FILE)

    # Read back and verify content
    with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
        content = f.read()
    assert "evil.com" in content
    assert "test.org" in content
