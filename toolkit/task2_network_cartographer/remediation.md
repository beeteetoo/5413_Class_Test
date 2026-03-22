# Remediation Archetypes

## Archetype 1: Disable the Feature
Use when: the vulnerability IS a feature that is misconfigured or unnecessary.

Example: CVE-2015-3306 — mod_copy is a legitimate FTP feature with no access control.
Fix: disable the feature. Comment out LoadModule mod_copy.c in proftpd.conf, restart.
Verify: FTP still responds on port 21. SITE CPFR now returns 500 Unknown command.

This is the correct archetype for today's vulnerability.

## Archetype 2: Kill the Listener
Use when: an illegitimate process is listening — it should not exist at all.

Example: a backdoor opens a second port and waits for a connection.
Fix: identify the PID, kill the process, remove the trigger (cronjob, startup script).
Verify: port is closed. Legitimate service is unaffected.

## Archetype 3: Replace the Binary
Use when: the executable itself is malicious or has been compromised.

Example: a backdoored binary that introduces a vulnerability on install.
Fix: remove the binary, verify the clean source, reinstall.
Verify: service starts correctly. Vulnerability no longer present.

## The verification step is non-optional.
A remediation that closes the vulnerability but breaks the service is not a fix.
A fix must satisfy two conditions:
  1. The vulnerability is closed.
  2. The service continues to function correctly.
Both must be demonstrated.
