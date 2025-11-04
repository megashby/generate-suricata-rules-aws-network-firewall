import json
import pytest
from lambda_function import (
    normalize_protocols,
    normalize_subdomains,
    build_content_rule,
    generate_rules,
    lambda_handler
)

def test_normalize_protocols():
    assert normalize_protocols("tls;http") == ["tls", "http"]
    assert normalize_protocols("invalid;tls") == ["tls"]
    assert normalize_protocols("") == ["tls"]

def test_normalize_subdomains():
    assert normalize_subdomains("evil;bad") == ["evil", "bad"]
    assert normalize_subdomains("**") == ["", "*"]
    assert normalize_subdomains("") == [""]

def test_build_content_rule_tls():
    rule = build_content_rule("tls", "example.com", False)
    assert "tls.sni" in rule
    assert "example.com" in rule

def test_generate_rules_basic():
    rows = [
        {"domain": "evil.com", "subdomain": "**", "action": "drop", "protocol": "tls;http", "log": "1"},
        {"domain": "test.org", "subdomain": "", "action": "pass", "protocol": "http", "log": "0"},
    ]
    rules = generate_rules(rows)
    expected_output = "\n".join([
        'alert tls $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for evil.com via TLS (logged)"; tls.sni; content:"evil.com"; startswith; endswith; nocase; sid:1;)',
        'drop tls $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for evil.com via TLS"; tls.sni; content:"evil.com"; startswith; endswith; nocase; sid:2;)',
        'alert tls $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for .evil.com via TLS (logged)"; tls.sni; content:".evil.com"; dotprefix; endswith; nocase; sid:3;)',
        'drop tls $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for .evil.com via TLS"; tls.sni; content:".evil.com"; dotprefix; endswith; nocase; sid:4;)',
        'alert http $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for evil.com via HTTP (logged)"; http.host; content:"evil.com"; startswith; endswith; sid:5;)',
        'drop http $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for evil.com via HTTP"; http.host; content:"evil.com"; startswith; endswith; sid:6;)',
        'alert http $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for .evil.com via HTTP (logged)"; http.host; content:".evil.com"; dotprefix; endswith; sid:7;)',
        'drop http $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"DROP traffic for .evil.com via HTTP"; http.host; content:".evil.com"; dotprefix; endswith; sid:8;)',
        'pass http $HOME_NET any -> $EXTERNAL_NET any (flow:to_server; msg:"PASS traffic for test.org via HTTP"; http.host; content:"test.org"; startswith; endswith; sid:9;)',
    ])

    assert "\n".join(rules) == expected_output

def test_lambda_handler(tmp_path):
    csv_file = "inputs/input_sample.csv"
    output_file = tmp_path / "rules.rules"
    event = {"csv_file": csv_file, "output_file": str(output_file)}

    response = lambda_handler(event)
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    assert "Generated" in body["message"]
