# Contributing

## Data handling — public repo, private case data

Both `asiakay/masshealth-crm` and `asiakay/repo-dashboard` are **public repositories**.

**The following must never be committed to seed data, fixtures, config, or any file that enters git history:**

- Real patient or ward names (even first name only)
- Real docket, case, or court file numbers
- Real court or county names linked to an active case
- Real street addresses or room/unit numbers for a ward
- Personal contact details for family members or legal representatives
- Facility contact details beyond what the facility publicly lists itself (website, NPI registry)

**Real case data lives only in the live D1 database and private records — never in git.**

**Fixtures and seed data must use:**

- Fictitious names in the format: first name + last initial only (e.g. "Arthur V.", "Eleanor V.")
- A clearly synthetic docket number with a `SAMPLE-` prefix (e.g. `SAMPLE-0000-GD`)
- No real court, county, or jurisdiction names tied to an active case
- A prominent `// SAMPLE DATA` or `/* SAMPLE */` comment adjacent to any fixture

If you are unsure whether a detail is safe to commit, leave it out and add it directly in the live database instead.
