import re
import csv
from collections import Counter, defaultdict

# Configuration
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
CSV_OUTPUT_FILE = "log_analysis_results.csv"


def parse_log_file(file_path):
    """Parse the log file and extract IP counts and endpoint counts."""
    ip_counts = Counter()
    endpoint_counts = Counter()

    with open(file_path, "r") as file:
        for line in file:
            # Extract IP Address
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else None

            # Extract Endpoint
            endpoint_match = re.search(r'"[A-Z]+\s(\/[\w\/]*)\sHTTP', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None

            # Count IP Requests
            if ip:
                ip_counts[ip] += 1

            # Count Endpoint Access
            if endpoint:
                endpoint_counts[endpoint] += 1

    return ip_counts, endpoint_counts


def suslogincounts(file_path):
    """Parse the log file to detect suspicious login attempts."""
    failed_login_attempts = defaultdict(int)
    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "\w+ (?P<endpoint>.*?) HTTP/1\.1" (?P<status>\d{3}) .*? "(?P<message>.*?)"'

    with open(file_path, "r") as file:
        for line in file:
            match = re.search(log_pattern, line)
            if match:
                ip = match.group("ip")
                status = match.group("status")
                message = match.group("message")

                # Debugging: Print each matched line and the status
                print(f"Line: {line.strip()}")  # Print the line that was matched
                print(f"IP: {ip}, Status: {status}, Message: {message}")  # Print the details of the match

                # Count failed logins (401 + invalid credentials)
                if status == '401' and "Invalid credentials" in message:
                    failed_login_attempts[ip] += 1

    # Debugging: Print failed login attempts dictionary
    print(f"Failed login attempts: {failed_login_attempts}")
    return failed_login_attempts


def write_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips):
    """Write the analysis results to a CSV file."""
    with open(CSV_OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write IP counts
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write suspicious IPs
        writer.writerow([])
        writer.writerow(['Suspicious IPs', 'Failed Login Attempts'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def extract_ip_counts_from_log(file_path):
    """Parse the log file and extract counts for each unique IP address."""
    ip_counter = Counter()

    log_pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "\w+ (?P<endpoint>.*?) HTTP/1\.1" (?P<status>\d{3}) .*? "(?P<message>.*?)"'

    with open(file_path, "r") as log_file:
        for line in log_file:
            match = re.search(log_pattern, line)
            if match:
                ip_address = match.group("ip")

                # Increment the count for this IP address
                ip_counter[ip_address] += 1

    return ip_counter


def main():
    print("Processing log file...")

    # Step 1: Parse log file for IP and endpoint analysis
    ip_counts, endpoint_counts = parse_log_file(LOG_FILE)

    # Step 2: Parse log file for suspicious login attempts
    failed_logins = suslogincounts(LOG_FILE)

    # Step 3: Analyze Results
    # Sort IP counts
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

    # Identify most accessed endpoint
    most_accessed_endpoint = endpoint_counts.most_common(1)[0]

    # Detect flagged IPs with suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    # Debugging: Print suspicious IPs
    print(f"Suspicious IPs: {suspicious_ips}")

    # Step 4: Output Results
    print("\nIP Address Request Count:")
    for ip, count in sorted_ip_counts:
        print(f"{ip:<20} {count}")

    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Step 5: Write to CSV
    write_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {CSV_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
