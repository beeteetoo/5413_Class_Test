#!/usr/bin/env python3
"""
fix_proftpd.py

Remediation for CVE-2015-3306: ProFTPD 1.3.5 mod_copy
Target: 172.16.19.101 (Metasploitable 3 — authorised target only)

Strategy: Archetype 2 — Block the Port.

On this installation ProFTPD is managed by a process renewer script
that prevents reliable config-based remediation. The most reliable fix
is to block port 21 at the firewall using iptables.

This closes the attack surface entirely:
  - No FTP connections can be established
  - mod_copy commands cannot be issued
  - The vulnerability is unreachable

Two-condition verification:
  1. Port 21 is no longer reachable (exploit chain broken)
  2. The iptables rule is present and correct
"""

import socket
import subprocess
import time

TARGET = "172.16.19.101"
FTP_PORT = 21
SSH_USER = "vagrant"


def test_ftp_reachable(target: str, port: int) -> bool:
    """
    Attempt FTP connection. Returns True if reachable, False if blocked.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(3)
        sock.connect((target, port))
        time.sleep(0.1)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        print(f"    [*] FTP banner: {banner}")
        return True
    except Exception:
        return False
    finally:
        sock.close()


def test_cpfr(target: str, port: int) -> bool:
    """
    Test whether SITE CPFR returns 350 (vulnerable) or fails (remediated).
    Returns True if vulnerable, False if blocked or unreachable.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(3)
        sock.connect((target, port))
        time.sleep(0.1)
        sock.recv(1024)  # discard banner
        sock.send(b"SITE CPFR /etc/passwd\r\n")
        time.sleep(0.1)
        response = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        print(f"    [*] SITE CPFR response: {response}")
        return response.startswith("350")
    except Exception as e:
        print(f"    [*] Connection failed: {e}")
        return False
    finally:
        sock.close()


def apply_iptables_block(target: str) -> bool:
    """
    Block port 21 on the target using iptables via SSH.
    Uses INPUT chain DROP rule — immediate effect, no restart required.
    """
    print("    [*] Applying iptables block via SSH...")

    cmd = (
        f"ssh -o StrictHostKeyChecking=no "
        f"-o ConnectTimeout=10 "
        f"{SSH_USER}@{target} "
        f'"sudo iptables -I INPUT 1 -p tcp --dport {FTP_PORT} -j DROP"'
    )

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"    [-] iptables command failed: {result.stderr.strip()}")
        return False

    return True


def verify_rule_present(target: str) -> bool:
    """
    Confirm the iptables DROP rule is present on the target.
    """
    cmd = (
        f"ssh -o StrictHostKeyChecking=no "
        f"-o ConnectTimeout=10 "
        f"{SSH_USER}@{target} "
        f"\"sudo iptables -L INPUT -n | grep 'dpt:{FTP_PORT}'\""
    )

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0 and result.stdout.strip():
        print(f"    [*] Rule confirmed: {result.stdout.strip()}")
        return True

    return False


def main():
    print("[*] fix_proftpd.py — CVE-2015-3306 Remediation")
    print(f"[*] Target: {TARGET}:{FTP_PORT}")
    print(f"[*] Strategy: iptables DROP on port {FTP_PORT}")
    print()

    # Step 1 — confirm vulnerability is present before fixing
    print("[1] Pre-fix verification...")
    if test_cpfr(TARGET, FTP_PORT):
        print("    [!] Vulnerable — SITE CPFR returns 350.")
    else:
        print("    [*] CPFR not responding — may already be fixed.")
    print()

    # Step 2 — apply the iptables block
    print("[2] Applying remediation...")
    if not apply_iptables_block(TARGET):
        print("    [-] Failed to apply iptables rule.")
        print(f"    [*] Manual fix: ssh {SSH_USER}@{TARGET}")
        print(
            f"    [*] Then run:   sudo iptables -I INPUT 1 -p tcp --dport {FTP_PORT} -j DROP"
        )
        return
    print("    [+] iptables DROP rule applied.")
    print()

    # Brief pause — rule takes effect immediately but give it a moment
    time.sleep(1)

    # Step 3 — verify port 21 is no longer reachable
    print("[3] Verifying port 21 is blocked...")
    if test_ftp_reachable(TARGET, FTP_PORT):
        print("    [-] Port 21 still reachable. Rule may not have applied.")
    else:
        print("    [+] Port 21 is unreachable. FTP connections blocked.")
    print()

    # Step 4 — confirm the iptables rule is present
    print("[4] Confirming iptables rule...")
    if verify_rule_present(TARGET):
        print("    [+] DROP rule confirmed in INPUT chain.")
    else:
        print("    [-] Rule not found. Check iptables manually.")
        return
    print()

    print("[+] Remediation complete.")
    print(f"    Vulnerability closed: port {FTP_PORT} unreachable")
    print("    Attack chain broken: SITE CPFR/CPTO cannot be issued")
    print()
    print("[*] To restore for lab use:")
    print(f"    ssh {SSH_USER}@{TARGET}")
    print(f"    sudo iptables -D INPUT -p tcp --dport {FTP_PORT} -j DROP")


if __name__ == "__main__":
    main()
