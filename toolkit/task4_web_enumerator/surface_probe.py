import argparse
import sys

import requests
from bs4 import BeautifulSoup, Comment

SENSITIVE_PATHS = [
    "/robots.txt",
    "/admin",
    "/phpmyadmin",
    "/login",
    "/.git",
    "/drupal",
    "/drupal/CHANGELOG.txt",
    "/dbadmin",
]


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP enumeration tool — analyse headers, extract comments, probe paths"
    )
    parser.add_argument("url", help="Target URL (e.g., http://172.16.19.101)")
    return parser.parse_args()


def analyse_headers(url: str) -> tuple[dict, str]:
    """
    Send a GET request to the target URL.
    Return a dict of security-relevant headers and the response text.
    """
    response = requests.get(url, timeout=5)

    headers = {}
    headers["Server"] = response.headers.get("Server", "Not disclosed")
    headers["X-Powered-By"] = response.headers.get("X-Powered-By", "Not disclosed")

    return headers, response.text


def extract_comments(html: str) -> list[str]:
    """
    Parse HTML and return all comment strings, stripped of whitespace.
    """
    soup = BeautifulSoup(html, "html.parser")
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    return [c.strip() for c in comments]


def check_sensitive_paths(base_url: str, paths: list[str]) -> list[dict]:
    """
    Probe each path appended to the base URL.
    Return a list of dicts: {path, status_code, status}.
    """
    results = []

    for path in paths:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                status = "FOUND"
            elif resp.status_code == 404:
                status = "NOT FOUND"
            elif resp.status_code == 403:
                status = "FORBIDDEN"
            elif resp.status_code in (301, 302):
                status = "REDIRECT"
            else:
                status = f"HTTP {resp.status_code}"

            results.append(
                {
                    "path": path,
                    "status_code": resp.status_code,
                    "status": status,
                }
            )
        except requests.exceptions.RequestException:
            results.append(
                {
                    "path": path,
                    "status_code": None,
                    "status": "ERROR",
                }
            )

    return results


def main() -> None:
    """Coordinate: parse arguments, run analysis, format output."""
    args = parse_arguments()
    url = args.url

    # Phase 1: Headers and page content
    try:
        headers, html = analyse_headers(url)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not connect to {url}: {e}", file=sys.stderr)
        sys.exit(1)

    # Phase 2: Extract comments from page source
    comments = extract_comments(html)

    # Phase 3: Probe sensitive paths
    path_results = check_sensitive_paths(url, SENSITIVE_PATHS)

    # Output — three contracted sections
    print("[HEADERS]")
    for key, value in headers.items():
        print(f"  {key}: {value}")

    print()
    print("[COMMENTS]")
    if comments:
        for c in comments:
            print(f"  {c}")
    else:
        print("  No comments found.")

    print()
    print("[SENSITIVE PATHS]")
    for r in path_results:
        print(f"  {r['path']} — {r['status']} ({r['status_code']})")


if __name__ == "__main__":
    main()
