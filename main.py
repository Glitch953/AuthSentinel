from datetime import datetime

failed_count = 0
success_count = 0
total_attempts = 0

failed_users = {}
failed_ips = {}
user_ips = {}
failed_ip_times = {}
alert_count = 0


# Read and analyze the login log file
with open("login_logs.txt", "r") as file:
    for line in file:
        parts = line.strip().split(",")

        if len(parts) == 4:
            username = parts[0]
            status = parts[1]
            ip_address = parts[2]
            timestamp = datetime.strptime(parts[3].strip(), "%Y-%m-%d %H:%M:%S")

            if status not in ("FAILED", "SUCCESS"):
                continue

            total_attempts += 1

            print(
                f"Username: {username}\n"
                f"Status: {status}\n"
                f"IP: {ip_address}\n"
                f"Timestamp: {timestamp}"
            )

            if status == "FAILED":
                failed_ips[ip_address] = failed_ips.get(ip_address, 0) + 1
                failed_users[username] = failed_users.get(username, 0) + 1
                failed_count += 1
                print("Failed Login")

                # Analyze failed login timestamps
                if ip_address in failed_ip_times:
                    previous_timestamp = failed_ip_times[ip_address][-1]
                    difference = timestamp - previous_timestamp
                    seconds = difference.total_seconds()

                    if 0 <= seconds <= 60:
                        alert_count += 1

                    failed_ip_times[ip_address].append(timestamp)

                else:
                    failed_ip_times[ip_address] = [timestamp]

            elif status == "SUCCESS":
                success_count += 1
                print("Success Login")

            # Map usernames to IP addresses
            if username in user_ips:
                user_ips[username].append(ip_address)
            else:
                user_ips[username] = [ip_address]

# Final report
print("\n========== LOGIN ANALYSIS REPORT ==========")

for ip, count in failed_ips.items():
    print(f"IP: {ip} | Failed Attempts: {count}")

for username, count in failed_users.items():
    if count <= 2:
        risk_level = "Low"
    elif count <= 4:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
    print(f"User: {username} | Failed Attempts: {count} | Risk: {risk_level}")

print(f"Total Attempts: {total_attempts}")
print(f"Success Count: {success_count}")
print(f"Failed Count: {failed_count}")
print(f"Failed IPs: {failed_ips}")
print(f"User IPs: {user_ips}")
print(f"Failed Users:{failed_users}")
print(f"Suspicious Activity Alerts: {alert_count}")
