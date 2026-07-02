# Import detection modules and report renderer.
from detector import (
    detect_web_attacks,
    detect_bruteforce,
    detect_invalid_users,
    detect_root_attacks,
    detect_sudo_activity
)

from report_generator import (
    generate_html
)

from collections import Counter
from datetime import datetime
import json
import os


def read_log(path):
    """
    Read log file safely.
    """

    try:

        # Open the provided log file and return its lines.
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return file.readlines()

    except FileNotFoundError:

        print(f"[ERROR] Missing file: {path}")

        return []


def calculate_score(alerts):

    # Start with a neutral score and add weighted points by severity.
    score = 0

    for alert in alerts:

        if alert["severity"] == "HIGH":
            score += 30

        elif alert["severity"] == "MEDIUM":
            score += 15

        else:
            score += 5

    return min(score, 100)


def get_risk_level(score):

    # Map the threat score to a simple risk category.
    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


def create_report_directory():

    # Create a timestamped directory for this run's report artifacts.
    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    report_dir = os.path.join(
        "reports",
        timestamp
    )

    os.makedirs(
        report_dir,
        exist_ok=True
    )

    return report_dir


def save_json(alerts, report_dir):

    # Export the raw alerts to a JSON file for downstream analysis.
    json_path = os.path.join(
        report_dir,
        "report.json"
    )

    with open(
        json_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


def save_iocs(alerts, report_dir):

    # Save a deduplicated list of IP indicators to a text report.
    ioc_path = os.path.join(
        report_dir,
        "iocs.txt"
    )

    unique_ips = sorted(
    (
        alert["ip"]
        for alert in alerts
        if alert["ip"] != "Unknown"
    )
)

    with open(
        ioc_path,
        "w",
        encoding="utf-8"
    ) as file:

        for ip in unique_ips:

            file.write(
                ip + "\n"
            )


def save_summary(
    alerts,
    report_dir,
    score,
    risk
):

    # Build a plain-text summary showing count by severity and risk level.

    summary_path = os.path.join(
        report_dir,
        "summary.txt"
    )

    high = sum(
        1 for a in alerts
        if a["severity"] == "HIGH"
    )

    medium = sum(
        1 for a in alerts
        if a["severity"] == "MEDIUM"
    )

    low = sum(
        1 for a in alerts
        if a["severity"] == "LOW"
    )

    with open(
        summary_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "ThreatLens Incident Summary\n"
        )

        file.write(
            "=" * 40 + "\n\n"
        )

        file.write(
            f"Threat Score: {score}/100\n"
        )

        file.write(
            f"Risk Level: {risk}\n\n"
        )

        file.write(
            f"HIGH: {high}\n"
        )

        file.write(
            f"MEDIUM: {medium}\n"
        )

        file.write(
            f"LOW: {low}\n"
        )


def display_results(
    alerts,
    score,
    risk
):

    # Print the detected alerts and the overall security assessment.
    print()

    print("=" * 60)

    print(
        "THREATLENS SECURITY REPORT"
    )

    print("=" * 60)

    print()

    print(
        f"Threats Detected : {len(alerts)}"
    )

    print(
        f"Threat Score     : {score}/100"
    )

    print(
        f"Risk Level       : {risk}"
    )

    print()

    print("=" * 60)

    print("DETECTIONS")

    print("=" * 60)

    for alert in alerts:

        print()

        print(
            f"[{alert['severity']}] "
            f"{alert['type']}"
        )

        print(
            f"IP      : {alert['ip']}"
        )

        print(
            f"MITRE   : {alert['mitre']}"
        )

        print(
            f"Evidence: "
            f"{alert['log']}"
        )


def main():

    # Main entry point for the ThreatLens CLI analyzer.
    # Display the CLI banner for the analyzer.
    print("\n==============================")
    print("      THREATLENS v1.0")
    print("==============================")

    # Ask the user for the log file to analyze.
    log_path = input(
        "\nEnter log file path: "
    ).strip('"')

    # Read the contents of the provided log file.
    logs = read_log(log_path)

    if not logs:

        print(
            "\n[ERROR] No logs loaded."
        )

        return

    alerts = []

    # Run each detection module and gather all alerts.
    alerts.extend(
        detect_web_attacks(
            logs
        )
    )

    alerts.extend(
        detect_bruteforce(
            logs
        )
    )

    alerts.extend(
        detect_invalid_users(
            logs
        )
    )

    alerts.extend(
        detect_root_attacks(
            logs
        )
    )

    alerts.extend(
        detect_sudo_activity(
            logs
        )
    )

    # Convert the collected alerts into a risk score.
    score = calculate_score(
        alerts
    )

    # Translate the score into a human-readable risk label.
    risk = get_risk_level(
        score
    )

    # Print the findings to the console.
    display_results(
        alerts,
        score,
        risk
    )

    # Create a folder for the generated report files.
    report_dir = (
        create_report_directory()
    )

    # Save the report data in multiple formats.
    save_json(
        alerts,
        report_dir
    )

    save_iocs(
        alerts,
        report_dir
    )

    save_summary(
        alerts,
        report_dir,
        score,
        risk
    )

    generate_html(
        alerts,
        report_dir,
        score,
        risk
    )

    print()

    print("=" * 60)

    print(
        f"Reports Saved: {report_dir}"
    )

    print("=" * 60)

if __name__ == "__main__":
    main()
