 # Cloud Security & IAM Audit Utility

## Objective
Developed a Python-based security auditing utility to evaluate IAM user policies, check for Multi-Factor Authentication (MFA) compliance on privileged accounts, and flag stale access keys exceeding industry standards (90 days).

## Tech Stack
* Python (JSON Parsing, Datetime calculations)
* Cloud Security & Identity and Access Management (IAM) Best Practices

## Key Features
* **Privileged Access Enforcement:** Automatically identifies administrator accounts operating without active MFA protection.
* **Credential Hygiene Tracking:** Calculates the age of access keys to spot stale credentials that pose an unauthorized access risk.
