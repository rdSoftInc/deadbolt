# Deadbolt interactive wizard map

This map records the Guided Mode capabilities and their direct-command parity.
The direct CLI remains the canonical automation interface.

| Wizard area | Existing command or behavior | Status |
|---|---|---|
| Start web assessment | `deadbolt web TARGETS` | implemented |
| Resume web assessment | `deadbolt web TARGETS --resume-from RUN` | implemented |
| Start/resume network assessment | `deadbolt network TARGETS --engagement FILE` | implemented |
| Start Android assessment | `deadbolt android APK [--output DIR]` | implemented |
| Start iOS assessment | `deadbolt ios IPA [--output DIR]` | implemented |
| Tool status | `deadbolt tools status [--offline]` | implemented |
| Repair/build tools | `deadbolt tools build` with tool/domain/drift filters | implemented |
| Upgrade planning/testing | `deadbolt tools upgrade plan/test` | implemented |
| Upgrade promotion/rollback | `deadbolt tools upgrade promote/rollback` | implemented |
| Environment health | `deadbolt tools doctor/status/providers` | implemented |
| Reports | `deadbolt reports open/generate` | implemented |
| Scope | engagement management and read-only `scope.yaml` review | implemented |
| Run history | guided browser over `outputs/run_*` | implemented |
| Wordlists | ffuf uses deterministic repository-local shallow list | current limitation; provider migration is separate work |

## Navigation contract

1. Start an assessment
   1. Web application
      1. Saved engagement
      2. Workspace `scope.yaml`
   2. Network (saved engagement required)
   3. Android application
   4. iOS application
2. Previous assessments
3. Scanner tools
4. Reports
5. Environment health
6. Engagements and scope
7. Exit

Every executable wizard action must show its equivalent direct command and
require confirmation before starting a scan or changing external state.

Engagement drafts are reviewed before save, header values are redacted from
review and validation output, and Web launch is blocked when recorded policy
constraints cannot yet be enforced by every scanner adapter.

The previous-assessments branch discovers `outputs/run_*` directories newest
first. The report library opens technical or stakeholder reports and can
regenerate both from preserved metadata and normalized findings.
