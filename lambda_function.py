import csv

def generate_suricata_rules(csv_file, output_file="outputs/suricata.rules"):
    sid = 1
    rules = []

    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            domain = row['domain'].strip()
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

            if protocol == 'dns':
                content_rule = f'dns.query; content:"{domain}"; nocase;'
            elif protocol == 'tls':
                content_rule = f'tls.sni; content:"{domain}"; nocase;'
            elif protocol == 'http':
                content_rule = f'http.host; content:"{domain}"; '
            else:
                # Fallback generic content match (rarely used, but safe)
                content_rule = f'content:"{domain}"; nocase;'       

            # If log == 1, add an alert rule first
            if log_flag in ('1'):
                alert_rule = (
                    f'alert dns any any -> any any '
                    f'(msg:"LOG traffic for domain {domain}"; '
                    f'dns.query; content:"{domain}"; nocase; '
                    f'sid:{sid}; rev:1;)'
                )
                rules.append(alert_rule)
                sid += 1

            # Then add the main pass/drop rule
            rule = (
                f'{action} {protocol} any any -> any any '
                f'(msg:"{action.upper()} traffic for domain {domain} via {protocol}"; '
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