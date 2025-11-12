import os
import csv
import boto3
from io import StringIO
from botocore.exceptions import BotoCoreError, ClientError

def get_vpc_cidr(vpc_id):
    try:
        ec2 = boto3.client("ec2")
        response = ec2.describe_vpcs(VpcIds=[vpc_id])
        vpcs = response.get("Vpcs", [])
        if vpcs and "CidrBlock" in vpcs[0]:
            return vpcs[0]["CidrBlock"]
    except (BotoCoreError, ClientError, KeyError, IndexError) as e:
        print(f"Warning: could not fetch CIDR for {vpc_id}: {e}")
    return None

def parse_csv(csv_file):
    reader = csv.DictReader(StringIO(csv_file))
    return [row for row in reader]

def normalize_source(source_vpc_input):
    src_net = "$HOME_NET"
    if not source_vpc_input:
        return src_net

    # Split on commas or semicolons
    vpc_ids = [
        v.strip()
        for v in source_vpc_input.replace(",", ";").split(";")
        if v.strip()
    ]
    if not vpc_ids:
        return src_net

    cidr_blocks = []
    for vpc_id in vpc_ids:
        cidr = get_vpc_cidr(vpc_id)
        if cidr:
            cidr_blocks.append(cidr)

    if cidr_blocks:
        # Suricata-style CIDR list with spaces
        return "[" + ", ".join(cidr_blocks) + "]" if len(cidr_blocks) > 1 else cidr_blocks[0]
    
    return src_net 


def normalize_protocols(protocols_input):
    protocols = [p.strip() for p in protocols_input.replace(',', ';').split(';') if p.strip()]
    valid_protocols = {'dns', 'tls', 'http', 'smtp', 'ftp', 'tcp', 'udp'}
    protocols = [p for p in protocols if p in valid_protocols]
    return list(dict.fromkeys(protocols)) or ['tls']


def normalize_subdomains(subdomains_input):
    subdomains = [s.strip() for s in subdomains_input.replace(',', ';').split(';') if s.strip()]
    if not subdomains:
        subdomains = ['']
    elif '**' in subdomains:
        subdomains = ['', '*']
    return list(dict.fromkeys(subdomains))

def build_content_rule(protocol, domain, sub):
    if sub == '':
        extra = 'startswith; endswith;'
        fqdn = domain
    elif sub == '*':
        extra = 'dotprefix; endswith;'
        fqdn = f".{domain}"
    else:
        extra = 'startswith; endswith;'
        fqdn = f"{sub}.{domain}"

    if protocol == 'dns':
        return f'dns.query; content:"{fqdn}"; {extra} nocase;'
    elif protocol == 'tls':
        return f'tls.sni; content:"{fqdn}"; {extra} nocase;'
    elif protocol == 'http':
        return f'http.host; content:"{fqdn}"; {extra}'
    else:
        return f'content:"{fqdn}"; {extra} nocase;'

def generate_rules(csv_content):
    sid = 1
    rules = []
    rows = parse_csv(csv_content)

    for row in rows:
        domain = row['domain'].strip()
        subdomains_input = (row.get('subdomain') or '').strip().lower()
        action = (row.get('action', 'pass')).strip().lower()
        log_flag = (row.get('log', '1')).strip()
        protocols_input = (row.get('protocol', 'tls')).strip().lower()
        source_vpc = (row.get('source_vpc') or '').strip()

        if not domain:
            continue
        if action not in ('pass', 'drop'):
            action = 'pass'
        if log_flag not in ('0', '1'):
            log_flag = '1'

        src_net = normalize_source(source_vpc)
        protocols = normalize_protocols(protocols_input)
        subdomains = normalize_subdomains(subdomains_input)
        
        for protocol in protocols:
            for sub in subdomains:
                content_rule = build_content_rule(protocol, domain, sub)
                flow_rule = 'flow:to_server;'

                if log_flag == '1':
                    alert_rule = (
                        f'alert {protocol} {src_net} any -> $EXTERNAL_NET any '
                        f'({flow_rule} msg:"{action.upper()} traffic for {domain} via {protocol.upper()} (logged)"; '
                        f'{content_rule} sid:{sid};)'
                    )
                    rules.append(alert_rule)
                    sid += 1

                rule = (
                    f'{action} {protocol} {src_net} any -> $EXTERNAL_NET any '
                    f'({flow_rule} msg:"{action.upper()} traffic for {domain} via {protocol.upper()}"; '
                    f'{content_rule} sid:{sid};)'
                )
                rules.append(rule)
                sid += 1

    return rules

def load_csv():
    bucket = os.environ.get("RULES_BUCKET")
    if bucket:
        # Lambda: read from S3
        s3 = boto3.client("s3")
        input_key = "input/input_sample.csv"
        obj = s3.get_object(Bucket=bucket, Key=input_key)
        return obj["Body"].read().decode("utf-8")

def save_rules_to_s3(rules, output_file=None):
    content = "\n".join(rules)
    bucket = os.environ.get("RULES_BUCKET")
    if bucket:
        # Lambda: write to S3
        s3 = boto3.client("s3")
        output_key = "output/suricata.rules"
        s3.put_object(Bucket=bucket, Key=output_key, Body=content.encode("utf-8"))
    else:
        print('No output bucket configured!')


def lambda_handler(event=None, context=None):
    csv_content = load_csv()
    rules = generate_rules(csv_content)
    save_rules_to_s3(rules)
    return {"rules_generated": len(rules)}