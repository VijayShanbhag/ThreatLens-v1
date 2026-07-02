from collections import Counter
import os


def generate_html(
    alerts,
    report_dir,
    score,
    risk
):
    """
    Generate professional ThreatLens HTML report.
    """

    # Count alerts by severity to display them in the report summary.
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

    # Collect unique IPs to show as indicators of compromise.
    unique_ips = sorted(
        set(
            alert["ip"]
            for alert in alerts
        )
    )

    # Build the HTML report content and inject the alert summary values.
    html = f"""
    <html>

    <head>

    <title>ThreatLens Report</title>

    <style>

    body {{
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: Arial, sans-serif;
        margin: 30px;
    }}

    h1 {{
        color: #58a6ff;
    }}

    .card {{
        background-color: #161b22;
        padding: 15px;
        margin: 10px 0;
        border-radius: 8px;
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
    }}

    th {{
        background-color: #21262d;
    }}

    td, th {{
        border: 1px solid #30363d;
        padding: 10px;
        text-align: left;
    }}

    .high {{
        color: #ff4d4d;
        font-weight: bold;
    }}

    .medium {{
        color: #ffb347;
        font-weight: bold;
    }}

    .low {{
        color: #3fb950;
        font-weight: bold;
    }}

    </style>

    </head>

    <body>

    <h1>ThreatLens Security Report</h1>

    <div class="card">
        <h2>Threat Score</h2>
        <h3>{score}/100</h3>
        <p>Risk Level: {risk}</p>
    </div>

    <div class="card">
        <h2>Threat Summary</h2>

        <p class="high">
            HIGH Alerts: {high}
        </p>

        <p class="medium">
            MEDIUM Alerts: {medium}
        </p>

        <p class="low">
            LOW Alerts: {low}
        </p>

        <p>
            Total Threats: {len(alerts)}
        </p>
    </div>

    <div class="card">
        <h2>Indicators of Compromise (IOCs)</h2>

        <ul>
    """

    for ip in unique_ips:

        html += f"""
        <li>{ip}</li>
        """

    html += """
        </ul>
    </div>

    <div class="card">
        <h2>Detected Threats</h2>

        <table>

        <tr>
            <th>Severity</th>
            <th>Threat</th>
            <th>IP</th>
            <th>MITRE ATT&CK</th>
            <th>Evidence</th>
        </tr>
    """

    for alert in alerts:

        # Give each row a severity-specific CSS class for styling.
        severity_class = alert[
            "severity"
        ].lower()

        html += f"""
        <tr>

        <td class="{severity_class}">
            {alert['severity']}
        </td>

        <td>
            {alert['type']}
        </td>

        <td>
            {alert['ip']}
        </td>

        <td>
            {alert['mitre']}
        </td>

        <td>
            {alert['log']}
        </td>

        </tr>
        """

    html += """
        </table>
    </div>

    </body>
    </html>
    """

    # Write the generated HTML report to the report directory.
    report_path = os.path.join(
        report_dir,
        "report.html"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)