# The Intelligence Chain

## Step 1: Banner
220 ProFTPD 1.3.5 Server

The scanner found a service. The service announced its name and version.
This is voluntary disclosure — the server is required by protocol to respond
on connect. It chose to include the version string. We read it.

## Step 2: NVD Lookup
Banner → software name + version → search nvd.nist.gov → find CVE entries

The National Vulnerability Database catalogues published vulnerabilities.
If a CVE exists for this version of this software, it will appear here.
The CVE number, the CVSS score, and the description are all public.

## Step 3: Mechanism
CVE description → what the vulnerability actually does

A CVE entry tells you the vulnerability exists. It does not always tell you
the mechanism clearly. Read carefully. Look for: what operation, what
authentication requirement, what the attacker controls.

mod_copy adds two FTP SITE commands to ProFTPD:

SITE CPFR <path>    Copy From — marks a file as the source
SITE CPTO <path>    Copy To — copies the source file to a new path

These commands run with the permissions of the FTP daemon process.
No authentication is required to issue them.

The FTP protocol communicates over a TCP connection.
Commands are plain text strings terminated with \r\n.
Response codes indicate success or failure:
    350 = "I have your source, give me the destination"
    250 = "Copy successful"
    500 = "Unknown command" (if mod_copy is disabled)

The attack: CPFR any readable file → CPTO any writable location → retrieve.

## Step 4: Python Translation
Mechanism → socket calls → working code

The mechanism is the blueprint. Python is the tool. Every mechanism
can be expressed in socket calls. This is the translation step.

verify_banner()     — confirms the target before acting (professional practice)
exploit_mod_copy()  — SITE CPFR + SITE CPTO via raw socket
retrieve_file()     — HTTP GET via requests

All three functions have one job each.
Error handling at each step — stops cleanly on failure.

## Step 5: Evidence

[+] Retrieved 1642 bytes
root:x:0:0:root:/root:/bin/bash
...
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash

The contents are the evidence.
The evidence is the starting point for the next step.

## Step 5: Evidence
Code runs → output captured → artefact recorded

The chain produces evidence. Record it. Commit it. Version it.
The output is not the end — it is the starting point for the next step.
