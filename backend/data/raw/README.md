# Synthetic incident and telemetry fixtures

This directory contains controlled synthetic inputs for demonstrations and tests. The JSON files under `incidents/` are supported incident scenarios; the JSON files at this directory level are component fixtures. The backend uses these fixtures, so keep them in the repository.

These files do not describe real incidents or live attack infrastructure. Their IPs and domains use documentation or reserved ranges such as RFC 5737 addresses and `example.com` domains. Hashes and payload references are demonstration data. Do not treat benchmark output as evidence of a real-world incident.

Threat intelligence clients can enrich supported indicators when configured. External lookups are separate from these fixed fixtures and may be unavailable without credentials or network access. Automated client tests should mock external services.
