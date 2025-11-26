# generate-suricata-rules-aws-network-firewall
Generate Suricata-style rules suitable for ingestion into AWS Network Firewall from a simple CSV of domains and options. The project includes a small Lambda-compatible handler (`lambda_handler`) that reads input from S3 and writes generated rules back to S3.

This project was developed as part of the AWS re:Invent session **DEV206 - Automating Suricata rules for AWS Network Firewall**.

**Quick summary:**
- Input: CSV rows describing domains, optional subdomains, protocols and logging options.
- Output: Suricata rules (alerts and actions) emitted as plain text.

**Features**
- Support for multiple protocols (tls, dns, http)
- Optional lookup of VPC CIDRs via AWS EC2 API (for `source_vpc` values)
- Flexible subdomain matching (exact, wildcard, PCRE for single-label subdomains)
- Lambda handler that reads/writes from S3 when `RULES_BUCKET` is set

**Repository layout**
- `lambda_function.py`: main implementation (generator, normalizers, Lambda handler)
- `inputs/`: example CSVs used by tests and examples
- `tests/`: unit tests (run with `pytest`)

**CSV input format**
The CSV must include at least a `domain` column. Other supported columns (optional):

- `domain` (required): e.g. `example.com`
- `subdomain` (optional): one of:
	- blank — match the domain itself
	- `*` — match single-label subdomains (PCRE used to require a label before the domain)
	- `**` — match any subdomain or the domain (uses startswith/endswith)
	- a specific label like `www` or `api` (can be a comma/semicolon-separated list)
- `protocol` (optional): comma/semicolon-separated list. Valid values: `dns`, `tls`, `http`. Defaults to `tls`.
- `action` (optional): `pass` or `drop` (defaults to `pass`)
- `log` (optional): `1` to generate a logging `alert` rule plus the action rule, `0` to disable the alert (defaults to `1`)
- `source_vpc` (optional): one or more VPC IDs (comma/semicolon-separated). If provided, the generator will attempt to resolve VPC CIDRs via the EC2 `describe_vpcs` API. If resolution fails, `$HOME_NET` is used.

Example CSV row:

```
domain,subdomain,protocol,action,log,source_vpc
example.com,*,tls,pass,1,vpc-0123456789abcdef0
```

**Usage — AWS Lambda**

1. Deploy the Lambda with `lambda_function.lambda_handler` as the handler.
2. Set environment variable `RULES_BUCKET` to the S3 bucket that contains your input CSV. You can configure the S3 keys with environment variables:

- `INPUT_KEY` — S3 key for the input CSV (default: `input/input_sample.csv`)
- `OUTPUT_KEY` — S3 key for the output rules file (default: `output/suricata.rules`)
3. The handler reads `input/input_sample.csv` from S3 and writes `output/suricata.rules` back to the same bucket.

**Testing**

Run unit tests with `pytest` from the project root:

```bash
pytest -q
```

There are example input CSVs under `inputs/` used by the tests.

**Environment / AWS permissions**
When running in Lambda the code will call:
- `ec2:DescribeVpcs` (if resolving `source_vpc` values)
- `s3:GetObject` and `s3:PutObject` (requires `RULES_BUCKET` to be set)
