# The Benji Protocol

**COM5413 — Programming for Cyber Security**
**University of Bolton | HE5**

---

**Student Name:**
**Student ID:**
**Cohort:**

---

## Repository Structure

```
/toolkit/                          # Weekly tool builds (Part 1)
/field_tests/                      # IMF-issued unit tests — do not modify
/vulnerability_hunt/               # Capstone assessment submission (Part 2)
/docs/                             # Build log and documentation
AI_LOG.md                          # AI usage audit — mandatory
requirements.txt                   # Python dependencies
```

---

## The Toolkit

Brief one-line description of each tool as you complete it:

| Task | Tool | What It Does | Status |
|------|------|--------------|--------|
| 1 | `log_parser.py` | | |
| 2 | `scan.py` | | |
| 3 | `brute.py` | | |
| 4 | `web_enum.py` | | |

---

## Running the Tools

```bash
# Task 1
python toolkit/task1_evidence_collector/log_parser.py <log_file>

# Task 2
python toolkit/task2_network_cartographer/scan.py <target_ip> --ports 1-1024

# Task 3
python toolkit/task3_access_validator/brute.py <target_ip> --service ftp --user <user> --wordlist <file>

# Task 4
python toolkit/task4_web_enumerator/web_enum.py <url>
```

---

## Running the Field Tests

```bash
pip install pytest
pytest field_tests/ -v
```

---

## Git Tag Reference

| Tag | Meaning |
|-----|---------|
| `w1` | Task 1 complete — tests passing |
| `w2` | Task 2 complete — tests passing |
| `w3` | Task 3 complete — tests passing |
| `w4` | Task 4 complete — tests passing |
| `hunt-final` | Vulnerability Hunt submission — NO COMMITS AFTER THIS TAG |



Here are other users in the system
Username Password Admin Status
leia_organa help_me_obiwan Yes
luke_skywalker like_my_father_beforeme Yes
han_solo nerf_herder Yes
artoo_detoo b00p_b33p No
c_three_pio Pr0t0c07 No
ben_kenobi thats_no_m00n No
