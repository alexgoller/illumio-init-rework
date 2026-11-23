# Dry run and script generation

Goal: customers can preview (`-DryRun`) or generate (`-Generate az|ps`) the onboarding instead of running it blind.

## Plan

- [x] 1. Merge `illumio-init-extended.ps1` into `illumio-init.ps1` (`-nsgRoleId`, `-nsgRoleName`, Reader pre-check); keep the extended file as a forwarding wrapper
- [x] 2. Route every Azure / CloudSecure change through `Invoke-Change`
- [x] 3. `-DryRun`: reads run, changes are only reported, summary at the end
- [x] 4. `-Generate az|ps` with `-OutFile`: offline, no Azure login, secrets only via environment variables
- [x] 5. Tests (`tests/run-tests.ps1`, mocked Az cmdlets, fake `az`/`curl` for the generated bash script)
- [x] 6. README
- [x] 7. Run the tests in PowerShell (7.7.0, `brew install powershell`): 106 checks pass

## Decisions

- `-Generate` is always offline. The generated script checks existing state itself when it runs
  (differs from the first proposal, which had an online variant too).
- `-Generate` covers onboarding, adding permissions to an existing app and secret rotation.
  `-remove` and `-whitelistStorageAccounts` are `-DryRun` only.
- `-azfw` now assigns the firewall role for a new app as well (it did so only together with `-nsg`),
  otherwise the generated script would reproduce that gap.
- An NSG role passed with `-nsgRoleId` / `-nsgRoleName` that does not exist is an error
  (the extended script fell back to a default role name and then failed on the assignment).

## Review

Status: implemented on branch `dry-run-generate`, tests pass, not committed.

Checked (2026-11-23, PowerShell 7.7.0 on macOS):
- `pwsh tests/run-tests.ps1`: all 106 checks pass. Az cmdlets are mocked; the generated bash script runs
  against fake `az` / `curl` and passes `bash -n` and `shellcheck`.
- The first run had 2 failures, both bugs in the tests (a one-line call log collapsed to a string;
  the secret check was case-insensitive and matched `$appSecret`). No change to the scripts was needed.
- README: all 22 internal links resolve.

Not checked:
- No run with the real Az module or against a real Azure subscription.
- No run on PowerShell 7.4, the minimum the script accepts.
- The changed Mermaid diagram was not rendered.

Next: a dry run and a generated script against a sandbox subscription before merging to main.
