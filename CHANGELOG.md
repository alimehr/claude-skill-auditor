# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-28

### Added

- `skill-security-review` skill: quarantine, read-only review, fixed-format risk report, and approval-gated, per-project, manual-only install.
- `scripts/scan.py`: standard-library, read-only static scanner (file inventory, frontmatter notes, file flags, pattern matches for network, execution, secrets, file system, destructive commands, persistence, installs, obfuscation, prompt injection, hidden Unicode and HTML comments).
- Claude Code plugin marketplace (`skill-auditor@claude-skill-auditor`).
- Documentation: README, design and threat model, example report.
- Unit tests for the scanner.
