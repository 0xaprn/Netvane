# Security and privacy

Netvane processes supplied text locally. It does **not** resolve domains, probe networks, launch shell commands, fetch update scripts, or transmit telemetry.

Its inputs are untrusted text. Output defaults to a new file created with restrictive permissions where supported; existing files require `--force`. The tool rejects final-component output symlinks and never intentionally overwrites a named input. On systems supporting `O_NOFOLLOW`, it also asks the OS to reject symlinks when opening output files. This protects against common mistakes, **not** against every hostile filesystem or privilege-boundary attack.

**Sensitive data:** `--audit`, `--format csv`, `--format jsonl` and `--keep-urls` can preserve raw strings or full URLs, including paths, tokens and query parameters. Treat outputs as potentially sensitive. Review and redact files before sharing them.

The parser recognizes formats heuristically and can miss or misclassify indicators. It has no built-in public suffix database, cannot prove a domain exists, and is not a live vulnerability scanner.

## Reporting a security issue

Do not post exploit details, secrets or private logs in public issues. Use [GitHub private vulnerability reporting](https://github.com/0xaprn/netvane/security/advisories/new) when the repository's private reporting feature is enabled. If reporting is unavailable, open a public issue asking for a private contact method **without revealing the vulnerability**. Include a minimal sanitized reproduction and the affected version in the private report.
