# ThreatLens-v1
A Python project for analyzing authentication and web server logs to detect common security threats.


## About

I built ThreatLens to practice SOC and blue team concepts using Python.

The project reads authentication and web server logs, looks for common attack patterns such as brute-force attacks and SQL injection, assigns a severity, maps detections to the MITRE ATT&CK framework, and generates reports.

The goal wasn't to build a full SIEM, but to better understand how log analysis and rule-based detection work.


## Why I Built It

After learning about SOC operations, I wanted to build something more practical than small Python exercises.

I chose log analysis because it combines Python, networking, Linux, and security concepts in one project.

While building ThreatLens I also learned how authentication logs are structured, how to reduce duplicate alerts, and how MITRE ATT&CK can be used to classify detections.


## Features

- Detects brute-force attacks
- Detects invalid user enumeration
- Detects failed root logins
- Detects suspicious sudo activity
- Detects SQL injection attempts
- Detects XSS attempts
- Extracts IOCs
- Maps detections to MITRE ATT&CK
- Calculates a threat score
- Generates HTML and JSON reports

## How it works

Authentication Log
        │
        ▼
Detection Rules
        │
        ▼
Alerts
        │
        ▼
Threat Score
        │
        ▼
Report


## Current Limitations

This is a rule-based project.

It currently works with sample authentication and Apache logs.

Real-world environments often require additional log formats and more advanced detection logic.


## Future Improvements

For the next version I plan to add:

- Desktop GUI
- CSV and JSON log support
- More detection rules
- Better reporting
- Real-time monitoring
