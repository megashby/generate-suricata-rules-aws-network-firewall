import csv
import json
from pathlib import Path

VALID_PROTOCOLS = {'dns', 'tls', 'http', 'smtp', 'ftp', 'tcp', 'udp'}

def parse_csv(csv_file):
    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)


def normalize_protocols(protocols_input):
    if not protocols_input:
        return ['tls']
    protocols = [p.strip().lower() for p in protocols_input.replace(',', ';').split(';') if p.strip()]
    valid = [p for p in protocols if p in VALID_PROTOCOLS]
    return valid or ['tls']


def normalize_subdomains(subdomains_input):
    if not subdomains_input:
        return ['']
    subdomains = [s.strip().lower() for s in subdomains_input.replace(',', ';').split(';') if s.strip()]
    if '**' in subdomains:
        subdomains = ['', '*']
    return list(dict.fromkeys(subdomains)) or ['']


def build_content_rule(protocol, fqdn, wildcard=False):
    extra = 'dotprefix; endswith;' if wildcard else 'startswith; endswith;'
    if protocol == 'dns':
        return f'dns.query; content:"{fqdn}"; {extra} nocase;'
    elif protocol == 'tls':
        return f'tls.sni; content:"{fqdn}"; {extra} nocase;'
    elif protocol == 'http':
        return f'http.host; content:"{fqdn}"; {extra}'
    else:
        return f'content:"{fqdn}"; {extra} nocase;'


def generate_rules(rows):
    sid = 1
    rules = []

    for row in rows:
        domain = row.get('domain', '').strip()
        if not domain:
            print("Skipping row with no domain.")
            continue

        action = (row.get('action', 'pass')).strip().lower()
        if action not in ('pass', 'drop'):
            print(f"{domain}: invalid action '{action}', defaulting to pass")
            action = 'pass'

        log_flag = (row.get('log', '1')).strip()
        if log_flag not in ('0', '1'):
            print(f"Invalid log flag '{log_flag}' for domain {domain}, defaulting to 1")
            log_flag = '1'

        protocols = normalize_protocols(row.get('protocol', 'tls'))
        subdomains = normalize_subdomains(row.get('subdomain'))

        for protocol in protocols:
            for sub in subdomains:
                wildcard = sub == '*'
                fqdn = f".{domain}" if wildcard else (f"{sub}.{domain}" if sub else domain)
                content_rule = build_content_rule(protocol, fqdn, wildcard)
                flow_rule = 'flow:to_server;'

                if log_flag == '1':
                    rules.append(
                        f'alert {protocol} $HOME_NET any -> $EXTERNAL_NET any '
                        f'({flow_rule} msg:"{action.upper()} traffic for {fqdn} via {protocol.upper()} (logged)"; '
                        f'{content_rule} sid:{sid};)'
                    )
                    sid += 1

                rules.append(
                    f'{action} {protocol} $HOME_NET any -> $EXTERNAL_NET any '
                    f'({flow_rule} msg:"{action.upper()} traffic for {fqdn} via {protocol.upper()}"; '
                    f'{content_rule} sid:{sid};)'
                )
                sid += 1

    return rules


def save_rules(rules, output_file):
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules))
    print(f"Generated {len(rules)} rules -> {output_file}")


def generate_suricata_rules(csv_file, output_file="outputs/suricata.rules"):
    rows = parse_csv(csv_file)
    rules = generate_rules(rows)
    save_rules(rules, output_file)
    return rules

def lambda_handler(event=None, context=None):
    csv_file = event.get("csv_file", "inputs/input_sample.csv") if event else "inputs/input_sample.csv"
    output_file = event.get("output_file", "outputs/suricata.rules") if event else "outputs/suricata.rules"

    try:
        rules = generate_suricata_rules(csv_file, output_file)
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": f"Generated {len(rules)} rules successfully.",
                "output_file": output_file
            })
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }


def main():
    generate_suricata_rules("inputs/input_sample.csv")

main()