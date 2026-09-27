# Security policy

## What to report

- A way to get a harmful skill past `skill-security-review` without it being flagged (for example a new hiding trick, or text that makes the reviewer skip files or install without approval).
- A problem in this repository itself, such as the scanner reading outside the target folder, following symlinks, or executing anything.

## How to report

Please **do not** open a public issue for a working bypass.

- Preferred: use GitHub's private vulnerability reporting on this repository (**Security** tab, then **Report a vulnerability**).
- If that is not available, open an issue titled "Security contact request" without any details, and you will be contacted privately.

Please include the smallest example that reproduces the problem, what you expected, and what happened.

## Scope and expectations

This project is a review aid, not a guarantee (see [Limitations](README.md#limitations)). Reports that improve detection are welcome even when they are not strictly "vulnerabilities". Vulnerabilities in Claude, Claude Code or third-party skills themselves should be reported to their owners.
