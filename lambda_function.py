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
                subdomains = ['none']

            # Generate rules for each subdomain
            for sub in subdomains:
                if sub.lower() == 'none':
                    fqdn = domain
                elif sub == '*':
                    fqdn = f".{domain}"  # Suricata style for wildcard
                else:
                    fqdn = f"{sub}.{domain}"    

            if protocol == 'dns':
                content_rule = f'dns.query; content:"{fqdn}"; nocase;'
            elif protocol == 'tls':
                content_rule = f'tls.sni; content:"{fqdn}"; nocase;'
            elif protocol == 'http':
                content_rule = f'http.host; content:"{fqdn}"; '
            else:
                # Fallback generic content match (rarely used, but safe)
                content_rule = f'content:"{fqdn}"; nocase;'       

            # If log == 1, add an alert rule first
            if log_flag in ('1'):
                alert_rule = (
                    f'alert {protocol} any any -> any any '
                    f'(msg:"{action.upper()} traffic for {fqdn} via {protocol.upper()}"; '
                    f'{content_rule} sid:{sid}; rev:1;)'
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