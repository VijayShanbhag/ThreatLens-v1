import re

from collections import (
    defaultdict,
    Counter
)

from rules import (
    SQL_PATTERNS,
    XSS_PATTERNS,
    SUSPICIOUS_AGENTS,
    MITRE_MAPPING
)

# Regex used to extract IPv4 addresses from log lines.
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"


def extract_ip(log_line):
    """
    Extract first IP address from a log line.
    """

    # Look for the first IPv4 address in the line.
    match = re.search(
        IP_REGEX,
        log_line
    )

    if match:
        return match.group()

    return "Unknown"


def create_alert(
    attack_type,
    severity,
    ip,
    log
):

    # Build a consistent alert dictionary for all detectors.
    """
    Standardized alert structure.
    """

    return {
        "type": attack_type,
        "severity": severity,
        "ip": ip,
        "mitre": MITRE_MAPPING.get(
            attack_type,
            "Unknown"
        ),
        "log": log.strip()
    }


def detect_web_attacks(logs):
    """
    Detect:
    SQLi
    XSS
    Suspicious User Agents
    """

    alerts = []

    for line in logs:

        # Normalize the line for case-insensitive matching.
        lower_line = line.lower()

        ip = extract_ip(line)

        # SQL Injection

        for pattern in SQL_PATTERNS:

            if pattern in lower_line:

                alerts.append(
                    create_alert(
                        "SQL Injection",
                        "HIGH",
                        ip,
                        line
                    )
                )

        # XSS

        for pattern in XSS_PATTERNS:

            if pattern in lower_line:

                alerts.append(
                    create_alert(
                        "XSS",
                        "HIGH",
                        ip,
                        line
                    )
                )

        # Suspicious Tools

        for tool in SUSPICIOUS_AGENTS:

            if tool in lower_line:

                alerts.append(
                    create_alert(
                        "Suspicious Tool",
                        "LOW",
                        ip,
                        line
                    )
                )

    return alerts


def detect_bruteforce(logs):

    alerts = []

    # Track repeated failed authentication attempts per source IP.
    failed_attempts = {}

    for line in logs:

        # Look for repeated password failures that suggest brute-force activity.
        if "failed password" in line.lower():

            ip = extract_ip(line)

            timestamp = " ".join(
                line.split()[:3]
            )

            if ip not in failed_attempts:

                failed_attempts[ip] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            failed_attempts[ip]["count"] += 1
            failed_attempts[ip]["last"] = timestamp

    for ip, data in failed_attempts.items():

        # Raise an alert only after the threshold of repeated failures is met.
        if data["count"] >= 5:

            alerts.append(
                create_alert(
                    "Brute Force",
                    "MEDIUM",
                    ip,
                    (
                        f"Attempts: {data['count']} | "
                        f"First Seen: {data['first']} | "
                        f"Last Seen: {data['last']}"
                    )
                )
            )

    return alerts


def detect_invalid_users(logs):

    alerts = []

    # Aggregate invalid-user attempts by source IP.
    invalid_users = {}

    for line in logs:

        # Detect password spraying or account enumeration behavior.
        if "invalid user" in line.lower():

            ip = extract_ip(line)

            timestamp = " ".join(
                line.split()[:3]
            )

            if ip not in invalid_users:

                invalid_users[ip] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            invalid_users[ip]["count"] += 1
            invalid_users[ip]["last"] = timestamp

    for ip, data in invalid_users.items():

        alerts.append(
            create_alert(
                "Invalid User Enumeration",
                "MEDIUM",
                ip,
                (
                    f"Attempts: {data['count']} | "
                    f"First Seen: {data['first']} | "
                    f"Last Seen: {data['last']}"
                )
            )
        )

    return alerts


def detect_root_attacks(logs):

    alerts = []

    # Track attempts against the root account separately.
    root_attempts = {}

    for line in logs:

        # Look for direct root login attempts that are usually high priority.
        if "failed password for root" in line.lower():

            ip = extract_ip(line)

            timestamp = " ".join(
                line.split()[:3]
            )

            if ip not in root_attempts:

                root_attempts[ip] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            root_attempts[ip]["count"] += 1
            root_attempts[ip]["last"] = timestamp

    for ip, data in root_attempts.items():

        alerts.append(
            create_alert(
                "Root Login Attack",
                "HIGH",
                ip,
                (
                    f"Attempts: {data['count']} | "
                    f"First Seen: {data['first']} | "
                    f"Last Seen: {data['last']}"
                )
            )
        )

    return alerts

   


def detect_sudo_activity(logs):
    """
    Detect privileged command execution.
    Aggregate by username.
    """

    alerts = []

    # Aggregate sudo usage by username to spot privileged activity.
    users = {}

    for line in logs:

        # Detect sudo usage as a sign of privileged command execution.
        if "sudo:" in line.lower():

            try:

                user = line.split("sudo:")[1].split(":")[0].strip()

            except:

                user = "Unknown"

            timestamp = " ".join(
                line.split()[:3]
            )

            if user not in users:

                users[user] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            users[user]["count"] += 1
            users[user]["last"] = timestamp

    for user, data in users.items():

        alerts.append(
            create_alert(
                "Privileged Command Execution",
                "LOW",
                user,
                (
                    f"User: {user} | "
                    f"Commands: {data['count']} | "
                    f"First Seen: {data['first']} | "
                    f"Last Seen: {data['last']}"
                )
            )
        )

    return alerts


def run_all_detections(
    apache_logs,
    auth_logs
):
    """
    Master detection engine.
    """

    alerts = []

    # Run all detection modules in sequence and combine their results.
    alerts.extend(
        detect_web_attacks(
            apache_logs
        )
    )

    alerts.extend(
        detect_bruteforce(
            auth_logs
        )
    )

    alerts.extend(
        detect_invalid_users(
            auth_logs
        )
    )

    alerts.extend(
        detect_root_attacks(
            auth_logs
        )
    )

    alerts.extend(
        detect_sudo_activity(
            auth_logs
        )
    )

    return alerts