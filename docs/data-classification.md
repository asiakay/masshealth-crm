# Data Classification — masshealth-crm

## Two-database architecture

This Worker uses two Cloudflare D1 databases with different access tiers:

| Database | Binding | Purpose | Access |
|---|---|---|---|
| `masshealth-crm-db` | `DB` | Real patient/facility data | Auth-gated (all methods) |
| `masshealth-crm-demo-db` | `DEMO_DB` | Synthetic fixtures only | Public read-only |

### Why the split exists

The public `.pages.dev` URL is open to the internet. Routing unauthenticated requests to a demo database means real patient names, facility contacts, and case identifiers are never exposed over an open network connection, even accidentally.

### How routing works

The Worker checks authentication on every request:

1. **`Cf-Access-Authenticated-User-Email` header present** (injected by Cloudflare Access at the edge) → real `DB`, all methods allowed
2. **`Authorization: Bearer <WRITE_TOKEN>`** (local dev / API clients) → real `DB`, all methods allowed  
3. **No auth** → public `DEMO_DB`, GET only; writes return `403 Demo mode: authenticate to perform write operations`

No frontend changes are required — the browser's CF Access session automatically includes the header for authenticated users.

---

## What is demo-safe

Data committed to this repo or stored in `masshealth-crm-demo-db` must be **entirely synthetic**:

- Patient names: first name + last initial only (e.g. `Arthur V.`, `Eleanor V.`, `Thomas G.`)
- Facility names: clearly fictional or suffixed with `(DEMO)`
- Docket/case numbers: `SAMPLE-` prefix (e.g. `SAMPLE-2024-CV-00001`)
- No real courts, counties, or jurisdictions
- No real contact info (phone, email, address)

See `CONTRIBUTING.md` for the full naming convention.

## What is NOT demo-safe

The following must live only in the production `masshealth-crm-db` (behind Cloudflare Access) and must **never** be committed to this repository:

- Real patient full names or initials that could identify someone
- Real facility names, NPI numbers, or contact details
- Actual docket numbers, case numbers, or court identifiers
- Real street addresses or geographic identifiers linked to an individual
- Any combination of fields that could re-identify a person

---

## Setting up the demo database

The `masshealth-crm-demo-db` D1 database (ID `940f410a-76d1-485f-89bc-29b9dd19e66d`) must be initialized before deploying:

```bash
# 1. Apply schema
wrangler d1 execute masshealth-crm-demo-db --remote --file=db/schema.sql

# 2. Seed synthetic fixtures
wrangler d1 execute masshealth-crm-demo-db --remote --file=db/seed-demo.sql
```

Re-run step 2 whenever you want to reset the demo data (it uses `INSERT`, so run `DELETE FROM facilities; DELETE FROM patients;` first if resetting).

---

## Automated PII backstop: data-scan

[`asiakay/data-scan`](https://github.com/asiakay/data-scan) is a reusable GitHub Action that scans every PR and push to `main` for PII/PHI-shaped patterns before they can be merged:

- SSN (`###-##-####` format)
- US phone numbers
- US street address patterns
- Court docket number patterns (configurable placeholder — set `docket-pattern` input for your jurisdiction)
- Repo-specific denylist (real names, docket numbers, addresses stored as a GitHub secret, never committed)

The workflow is wired in at `.github/workflows/data-scan.yml`.

### Adding real entries to the denylist

1. Go to **Settings → Secrets and variables → Actions → New repository secret**
2. Name: `DATA_SCAN_DENYLIST`
3. Value: one entry per line (names, docket numbers, addresses to hard-block)

The secret is injected into `.data-scan/denylist.txt` at CI time and never stored in the repo. See `.data-scan/denylist.txt.example` in `asiakay/data-scan` for the format.

### What data-scan doesn't catch

This is a **backstop, not a guarantee**. It will not catch:
- Encoded or obfuscated data (base64, hex, etc.)
- PII with typos that defeat the regex
- Non-US address or phone formats
- Binary files, PDFs, or images
- Data already in git history before this workflow was added

Treat a clean scan as "no obvious PII found," not "definitely no PII."
