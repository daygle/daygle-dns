# Security Policy

Daygle DNS is a network-facing service that terminates plaintext DNS, DoT,
DoH, and DoQ, authenticates zone transfers and dynamic updates, signs zones
with DNSSEC, and exposes an HTTP API/GUI. We take reports about all of these
surfaces seriously.

## Supported versions

Only the latest release on the `main` branch receives security fixes. There
are no long-term-support branches yet; upgrading is the supported mitigation
for any published vulnerability (see [Upgrading](README.md#upgrading) in the
README - the installer is idempotent and preserves your data).

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately through one of these channels:

1. **GitHub private vulnerability reporting (preferred).** Use the
   *Security* tab of the repository → *Report a vulnerability*. This creates
   a private advisory thread visible only to maintainers and you.
2. If GitHub reporting is unavailable, contact a maintainer directly and ask
   for a private channel; we will set one up.

### What to include

- A description of the vulnerability and its **impact** (what an attacker
  gains, and from where - LAN, WAN, a secondary, an API client…).
- The affected component and version (`daygle-dns --version`).
- Reproduction steps or a proof of concept: the config used (with secrets
  redacted), the client commands (`dig`, `curl`, a TSIG/DNSSEC script), and
  the observed vs. expected behavior.
- Which listener/protocol is involved (UDP/TCP 53, DoT, DoH, DoQ, API/GUI),
  and whether `api.users`, `api_token`, TSIG keys, or ACLs were configured -
  many findings depend on the deployment posture.

Please give us a reasonable window (up to 90 days) to fix and publish before
any public disclosure, and coordinate the disclosure text with us. We will
credit reporters by name or handle in the release notes unless you prefer to
stay anonymous.

## Response targets

- **Acknowledgment:** within 3 business days of the report.
- **Status updates:** at least every 7 days while a fix is in progress.
- **Fix and advisory:** we aim to ship a patch and publish the advisory (via
  GitHub Security Advisories) once the fixed release is out. Regressions on
  the fix are treated with the same priority.

## Scope

**In scope:**

- The `daygle-dns` server and every listener: plaintext UDP/TCP, DoT
  (RFC 7858), DoH (RFC 8484), DoQ (RFC 9250).
- Zone transfer security (AXFR/IXFR ACLs, TSIG RFC 8945), NOTIFY handling,
  and RFC 2136 dynamic-update authentication.
- DNSSEC signing/rollover correctness (bogus chains, signature windows, key
  mishandling).
- The REST API and embedded GUI: authentication, session handling, role
  enforcement (`admin`/`viewer`), secret redaction, and the settings-update
  path.
- The policy engine's enforcement of blocklists/ACLs (bypasses), rate-limit
  bypasses, and split-horizon answer leaking across client groups.
- The SQLite store's handling of untrusted record content (injection via
  zone imports or dynamic updates).
- `install.sh` (what it downloads, where it writes, privilege use).

**Out of scope:**

- Volumetric denial-of-service that requires saturating the host's network
  link (rate limiting is best-effort, not a firewall).
- Reports about *missing* hardening that is documented and opt-in, e.g.
  running the API on a public interface without `api.users`, or using
  self-signed certificates where the config explicitly chose them.
- Vulnerabilities in third-party crates. Please report those upstream (and
  feel free to open a normal issue pointing at it so we can bump the
  dependency). We track dependencies with `cargo audit`.
- Social engineering, phishing, or physical attacks.
- Attacks requiring an already-compromised host or administrator account.

## Safe harbor

We will not pursue or support action against anyone who researches Daygle
DNS in good faith: avoid degrading service for other users, avoid accessing
or modifying data beyond what is needed to demonstrate the issue, use
dedicated test instances rather than third-party deployments, and stop and
report immediately if you encounter real user data unintentionally.

## Deployment hardening checklist

While you're here - the settings that most affect Daygle's security posture:

- Put the API on a trusted interface (`api.listen = "127.0.0.1"` by default).
  Console login is already enforced by default - the first GUI visit creates
  the admin account. Add per-person accounts with `admin`/`viewer` roles from
  the console's Users page rather than sharing one login (or the legacy
  shared `api_token`). The last enabled admin is protected from removal, and
  disabling or deleting an account signs out its sessions immediately.
  Protect the database file: it stores the password hashes.
- Gate AXFR/IXFR and dynamic updates with `axfr_networks` /
  `update_networks` allow-lists and bind TSIG keys to sensitive zones.
- Use real (non-self-signed) certificates for publicly reachable DoT/DoH/DoQ
  listeners.
- Keep `rate_limit` enabled and sized for your client population.
- Back up `/var/lib/daygle-dns/daygle-dns.db` before upgrades; it holds your
  zones, records, and DNSSEC key state.

See [`daygle-dns.toml.example`](daygle-dns.toml.example) for every option
with commentary, and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how
the pieces enforce these controls.
