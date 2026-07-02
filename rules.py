"""
Threat detection signatures and ATT&CK mappings.
"""

# Signatures commonly associated with SQL injection attempts.
SQL_PATTERNS = [
    "' or 1=1",
    "union select",
    "drop table",
    "information_schema",
    "sleep("
]

# Signatures commonly associated with cross-site scripting payloads.
XSS_PATTERNS = [
    "<script>",
    "javascript:",
    "onerror=",
    "alert("
]

# Common scanning and exploitation tools that may indicate reconnaissance.
SUSPICIOUS_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "curl",
    "wpscan"
]

# Map each detection type to a relevant MITRE ATT&CK technique ID.
MITRE_MAPPING = {
    "SQL Injection": "T1190",
    "XSS": "T1059",
    "Brute Force": "T1110",
    "Suspicious Tool": "T1595",
    "Invalid User Enumeration": "T1580",
    "Root Login Attack": "T1110",
    "Privileged Command Execution": "T1548"
}