# Tenable CTEM Maturity Assessment — Claude skill

Measures a Tenable One tenant, classifies the customer across the five stages of the Exposure
Management Maturity Model, and delivers a three-quarter improvement roadmap and a self-contained
HTML dashboard.

**Read only.** No write tool is ever called.

## Requirements

This skill does not talk to the tenant itself. It consumes the **`tenable-ctem-mcp`** server, which
must be registered and connected first — see the repository root for installation, credentials and
TLS notes.

Without that server the skill cannot run: there is one execution path, not two.

## Installation

Copy this directory to your skills location, or install the `.skill.zip` from the repository:

```
~/.claude/skills/tenable-ctem-maturity-assessment/     # global
.claude/skills/tenable-ctem-maturity-assessment/       # project-scoped
```

Then verify the server before the first run:

```
ctem_diagnostics()      → expect verdict: ok
```

## Invocation

Ask in plain language — *"run a CTEM maturity assessment"*, *"what stage is my customer at"*,
*"avaliação de maturidade CTEM"*, *"evaluación de madurez CTEM"*. This is the primary path, and the
one the skill is written for: the description matches on all three languages.

The explicit form works too, when you want to name the skill instead of describing the task:

```
/tenable-ctem-maturity-assessment
```

Both reach the same place.

The skill opens by discovering the tenant and proposing a mapping — which tag category is
criticality, which is owner, which scans represent the recurring assessment — and asks you to
confirm before measuring anything.

## Report language

Chosen at Step 0: **EN, PT-BR or ES**. It governs the operator dialogue, the report prose and the
dashboard's initial language. Data read from the tenant — tag names, values, scan names — is printed
exactly as it exists there.

## What it delivers

- 19 indicators across the five CTEM stages, each with the literal filter that produced it
- The **effective stage** and the **average stage** side by side, and the stage that limits the whole
- A three-quarter roadmap ordered by effort against impact
- A single self-contained HTML dashboard, exportable and openable offline

## Before showing a report to a customer

**The thresholds are this skill's criterion, not Tenable's.** No official Tenable material publishes
a numeric threshold per maturity stage; the model is qualitative. Every cutoff appears in the report
labelled with its origin.

**A gap is not a zero.** A query that fails becomes a declared gap with a named cause and leaves the
calculation.

**MTTR may come back as a declared gap, and that is the correct result** when the underlying windows
turn out to be made only of scan dates — the number would measure assessment cadence, which two
other indicators already measure.

Full detail in `references/` and in the repository's `OVERVIEW.md`.

## Licence

See the repository `LICENSE`.
