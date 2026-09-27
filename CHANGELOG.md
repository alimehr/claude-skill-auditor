# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-09-28

### Fixed

- Scanner: Windows user paths such as `C:\Users\...` are now flagged (the pattern only matched a doubled backslash).
- Scanner: output is written as UTF-8, so reports with non-ASCII text no longer crash on Windows consoles.
- Skill: Windows fallback when Python is missing (PowerShell `Get-ChildItem` / `Select-String`), and a note to use `py -3` or `python` when `python3` is unavailable.
- Tests: fixtures are written as UTF-8, and the symlink test is skipped where symlinks cannot be created.
## [1.0.0] - 2026-09-28

### Added

- `skill-security-review` skill: quarantine, read-only review, fixed-format risk report, and approval-gated, per-project, manual-only install.
- `scripts/scan.py`: standard-library, read-only static scanner (file inventory, frontmatter notes, file flags, pattern matches for network, execution, secrets, file system, destructive commands, persistence, installs, obfuscation, prompt injection, hidden Unicode and HTML comments).
- Claude Code plugin marketplace (`skill-auditor@claude-skill-auditor`).
- Documentation: README, design and threat model, example report.
- Unit tests for the scanner.
