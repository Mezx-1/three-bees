# Security policy

Three Bees (3B) is a hackathon MVP. Please don't use it to protect real data until it has been reviewed.

## Reporting a vulnerability
Please report security problems privately through GitHub: **Security → Report a vulnerability** on this repository. Don't open a public issue.

Include what you found, how to reproduce it, and what an attacker could do with it. We will reply as soon as we can.

## What we already do
- Uploaded files are never executed. They are stored inert with a `.quarantined` suffix.
- Passwords are stored as scrypt hashes, and session tokens are stored hashed.
- External IP/DNS lookups are off by default and never include private IPs.
- The full audit is in [docs/AUDIT_REPORT.md](docs/AUDIT_REPORT.md).
