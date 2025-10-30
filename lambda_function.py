import csv

def generate_suricata_rules(csv_file, output_file="outputs/suricata.rules"):
    sid = 1
    rules = []

    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            domain = row['domain'].strip()
            subdomains_input = (row.get('subdomain') or '').strip().lower()
            action = (row.get('action', 'pass')).strip().lower()
            log_flag = (row.get('log', '1')).strip()
            protocol = (row.get('protocol','tls')).strip().lower()

            if not domain:
                print("Skipping row with no domain.")
                continue

            # Only allow 'pass' or 'drop'
            if action not in ('pass', 'drop'):
                print(f"{domain}: has no action '{action}', defaulting to pass")
                action = 'pass'

            if log_flag not in ('0', '1'):
                print(f"Defaulting log=1 for domain '{domain}' (was '{log_flag}')")
                log_flag = '1'

            if protocol not in ('dns', 'tls', 'http', 'smtp', 'ftp', 'tcp', 'udp'):
                print(f"Defaulting protocol to 'tls' for domain '{domain}' (was '{protocol}')")
                protocol = 'tls'

            # Split multiple subdomains
            subdomains = [s.strip() for s in subdomains_input.replace(',', ';').split(';') if s.strip()]
            if not subdomains:
                # Empty subdomain → exact domain only
                subdomains = ['']  

            # Generate rules for each subdomain
            for sub in subdomains:
                if sub == '':
                    fqdn = domain
                    content_rule_extra = 'startswith; endswith;'
                elif sub == '*':
                    fqdn = f".{domain}"  # wildcard
                    content_rule_extra = 'endswith;'
                else:
                    fqdn = f"{sub}.{domain}"
                    content_rule_extra = 'startswith; endswith;'

                # Build content rule
                if protocol == 'dns':
                    content_rule = f'dns.query; content:"{fqdn}"; {content_rule_extra} nocase;'
                elif protocol == 'tls':
                    content_rule = f'tls.sni; content:"{fqdn}"; {content_rule_extra} nocase;'
                elif protocol == 'http':
                    # HTTP does not support nocase
                    content_rule = f'http.host; content:"{fqdn}"; {content_rule_extra}'
                else:
                    content_rule = f'content:"{fqdn}"; {content_rule_extra} nocase;'

                flow_rule = 'flow:to_server;'

                # If log == 1, add an alert rule first
                if log_flag == '1':
                    alert_rule = (
                        f'alert {protocol} $HOME_NET any -> $EXTERNAL_NET any '
                        f'({flow_rule} msg:"{action.upper()} traffic for {fqdn} via {protocol.upper()} (logged)"; '
                        f'{content_rule} sid:{sid}; rev:1;)'
                    )
                    rules.append(alert_rule)
                    sid += 1

                # Then add the main pass/drop rule
                rule = (
                    f'{action} {protocol} $HOME_NET any -> $EXTERNAL_NET any '
                    f'({flow_rule} msg:"{action.upper()} traffic for {fqdn} via {protocol.upper()}"; '
                    f'{content_rule} sid:{sid}; rev:1;)'
                )
                rules.append(rule)
                sid += 1

    # Write all generated rules to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(rules))

    print(f"Generated {len(rules)} rules and saved to {output_file}")

def main():
    generate_suricata_rules("inputs/input_sample.csv")

main()
