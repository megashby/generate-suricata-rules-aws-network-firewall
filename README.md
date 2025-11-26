# generate-suricata-rules-aws-network-firewall

Generate Suricata-style rules suitable for ingestion into AWS Network Firewall from a simple CSV of domains and options. The project includes a small Lambda-compatible handler (`lambda_handler`) that reads input from S3 and writes generated rules back to S3.

**Quick summary:**
- Input: CSV rows describing domains, optional subdomains, protocols and options.
- Output: Suricata rules (alerts and actions) emitted as plain text.

**Features**
- Support for multiple protocols (tls, dns, http, tcp, udp, etc.)
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
- `protocol` (optional): comma/semicolon-separated list. Valid values: `dns`, `tls`, `http`, `smtp`, `ftp`, `tcp`, `udp`. Defaults to `tls`.
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
2. Set environment variable `RULES_BUCKET` to the S3 bucket that contains `input/input_sample.csv` (or change `load_csv` to read a different key).
3. The handler reads `input/input_sample.csv` from S3 and writes `output/suricata.rules` back to the same bucket.

**Testing**

Run unit tests with `pytest` from the project root:

```bash
pytest -q
```

There are example input CSVs under `inputs/` used by the tests.

**Environment / AWS permissions**
When running in Lambda (or locally with AWS credentials), the code will call:
- `ec2:DescribeVpcs` (if resolving `source_vpc` values)
- `s3:GetObject` and `s3:PutObject` (if `RULES_BUCKET` is set and S3 I/O is used)

If you do not set `RULES_BUCKET` and call `lambda_handler`, the current implementation will not read input or write output (it expects S3 in Lambda). For local generation use `generate_rules()` directly with CSV text.

**Contributing / Next steps**
- Add a small CLI wrapper to read a file path and write output directly (convenience for local workflows).
- Add `requirements.txt` or `pyproject.toml` for reproducible installs.
- Support specifying S3 input/output keys via environment variables or handler event payloads.

**License**
This repository does not include a license file. Add a `LICENSE` if you intend to publish or share.
