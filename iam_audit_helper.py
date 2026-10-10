import json
from datetime import datetime, timezone

def audit_iam_users(data_file_path):
    """
    Audits IAM users for security best practices:
    1. Checks if MFA is enabled for admin accounts.
    2. Flags inactive access keys or keys older than 90 days.
    """
    try:
        with open(data_file_path, 'r') as file:
            users = json.load(file)
    except FileNotFoundError:
        print(f"Error: The file {data_file_path} was not found.")
        return

    print("--- Starting Cloud IAM Security Audit ---\n")
    
    current_time = datetime.now(timezone.utc)
    findings_count = 0

    for user in users:
        username = user.get("username")
        is_admin = user.get("is_admin", False)
        mfa_active = user.get("mfa_active", False)
        access_key_created_date = user.get("access_key_created_date") # Format: YYYY-MM-DD

        # Rule 1: Admin accounts must have MFA enabled
        if is_admin and not mfa_active:
            print(f"[!] HIGH RISK: Admin user '{username}' does not have MFA enabled!")
            findings_count += 1

        # Rule 2: Check access key age (flag if older than 90 days)
        if access_key_created_date:
            key_date = datetime.strptime(access_key_created_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_in_days = (current_time - key_date).days
            
            if age_in_days > 90:
                print(f"[!] MEDIUM RISK: User '{username}' has an access key that is {age_in_days} days old (Stale Key).")
                findings_count += 1

    print(f"\n--- Audit Complete. Total Security Findings Flagged: {findings_count} ---")

if __name__ == "__main__":
    # Run audit against sample test data
    audit_iam_users("policies/sample_users.json")
