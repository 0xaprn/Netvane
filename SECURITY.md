# Security and privacy

Netvane processes supplied text locally. It does **not** resolve domains, probe networks, launch shell commands, fetch update scripts, or transmit telemetry.

Its inputs are untrusted text. Output defaults to a new file created with restrictive permissions where supported; existing files require `--force`. The tool rejects final-component output symlinks and never intentionally overwrites a named input. On systems supporting `O_NOFOLLOW`, it also asks the OS to reject symlinks when opening output files. This protects against common mistakes, **not** against every hostile filesystem or privilege-boundary attack.

**Sensitive data:** `--audit`, `--format csv`, `--format jsonl` and `--keep-urls` can preserve raw strings or full URLs, including paths, tokens and query parameters. Treat outputs as potentially sensitive. Review and redact files before sharing them.
