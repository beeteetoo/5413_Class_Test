# Kit Bag Analysis — Session B

## What the scanner (scan.py / gateway_scanner.py) found:
- Port 21: ProFTPD 1.3.5 — the FTP entry point
- Port 80:   Apache — the HTTP delivery mechanism (empty banner, but open)
- Port 22:   OpenSSH — the credential target


## What the exploit used:
- Port 21: FTP socket → SITE CPFR + SITE CPTO
- Port 80:   HTTP GET → retrieve the copied file

## The scanner provided both entry points.
Without the scanner, we would not have known:
- That port 2121 was ProFTPD 1.3.5 specifically (the version that matters)
- That port 80 was available for file retrieval
The scanner is not a reconnaissance step. It is a prerequisite.

## Week 4 connection:
The HTTP retrieval in exploit_mod_copy is exactly what web_enum.py does:
    requests.get(url)
    response.text
The code is already written. The Week 4 tool formalises it.

## Week 3 connection:
vagrant is a username.
SSH is on port 22.
brute.py will test whether msfadmin has a weak password.

## Week 1 connection:
The exploit generated FTP traffic.
That traffic appears in the system's auth and FTP logs.
log_parser.py reads those logs.
The footprint we left is evidence we created.
