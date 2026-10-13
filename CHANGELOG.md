# Changelog

## 1.0.0 — Initial public release

- Renamed and packaged as **Netvane**, with the `netvane` terminal command.
- Added a restrained red-and-charcoal interactive terminal interface and eight numbered presets plus custom mode.
- Added an advanced wizard step for export formats, separated IP/domain files, audit logs, scope and exclusions.
- Extracts and validates IPv4, IPv6, domains, HTTP(S) URLs and CIDR networks from text, CSV, TSV, JSON, JSONL and gzip files.
- Added optional defang decoding, normalization, per-finding provenance, filtering, sorting and SQLite deduplication.
- Protects existing outputs by default, rejects output symlinks, and uses user-only permissions for new output files where supported.
- Includes a dependency-free local user installer, Python standard-library tests and GitHub Actions CI.

> Release versions describe Netvane only; this changelog does not imply earlier public Netvane releases.
