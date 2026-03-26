"""test_gateway_probe.py — Mini test suite for the demo tool."""

import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

SCRIPT = Path(__file__).parent / "gateway_probe.py"
TEST_USER = "testuser"
TEST_PASS = "pr0bepass"


def _free_port():
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def ftp_server(tmp_path):
    """Start a local FTP server with known credentials."""
    port = _free_port()
    auth = DummyAuthorizer()
    auth.add_user(TEST_USER, TEST_PASS, str(tmp_path), perm="elradfmw")
    handler = FTPHandler
    handler.authorizer = auth
    handler.passive_ports = range(60000, 60100)
    server = FTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.close_all()


def run_probe(args):
    """Run gateway_probe.py with given arguments."""
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + args,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_finds_correct_password(ftp_server, tmp_path):
    """Tool must find the password and print the success message."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong1\nwrong2\npr0bepass\nwrong3\n")

    result = run_probe(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            TEST_USER,
            "--wordlist",
            str(wordlist),
            "--port",
            str(ftp_server),
        ]
    )

    assert result.returncode == 0
    assert "FOUND" in result.stdout
    assert "pr0bepass" in result.stdout


def test_reports_exhaustion(ftp_server, tmp_path):
    """Tool must report exhaustion when no password matches."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("bad1\nbad2\nbad3\n")

    result = run_probe(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            TEST_USER,
            "--wordlist",
            str(wordlist),
            "--port",
            str(ftp_server),
        ]
    )

    assert "EXHAUSTED" in result.stdout


def test_stops_after_success(ftp_server, tmp_path):
    """Tool must not continue testing after finding the password."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong1\npr0bepass\nnever_tried\n")

    result = run_probe(
        [
            "127.0.0.1",
            "--service",
            "ftp",
            "--user",
            TEST_USER,
            "--wordlist",
            str(wordlist),
            "--port",
            str(ftp_server),
        ]
    )

    assert "never_tried" not in result.stdout
    assert "never_tried" not in result.stderr
