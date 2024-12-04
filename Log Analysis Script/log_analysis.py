import re
import csv
from collections import Counter, defaultdict

#Constants
LOG_FILE = 'sample.log.txt'  #Path to the log file
OUTPUT_CSV = 'log_analysis_results.csv'  #Name of the output CSV file
FAILED_LOGIN_THRESHOLD = 5  #Threshold for detecting suspicious failed login attempts

def parse_log_file(file_path):
    """
    Parse the log file and extract relevant information.

    Args:
        file_path (str): Path to the log file.

    Returns:
        tuple: Counters for IP requests, endpoint requests, and a defaultdict for failed logins.
    """
    ip_requests = Counter()  #Tracks the count of requests per IP address
    endpoint_requests = Counter()  #Tracks the count of requests per endpoint
    failed_logins = defaultdict(int)  #Tracks the number of failed login attempts per IP

    #Open and read the log file line by line
    with open(file_path, 'r') as log_file:
        for line in log_file:
            #Extract the IP address using regex
            ip_match = re.search(r'^\d+\.\d+\.\d+\.\d+', line)
            ip = ip_match.group(0) if ip_match else None

            #Extract the HTTP endpoint (e.g., "/index.html") using regex
            endpoint_match = re.search(r'"(GET|POST|PUT|DELETE) (\S+)', line)
            endpoint = endpoint_match.group(2) if endpoint_match else None

            #Extract the HTTP status code using regex
            status_match = re.search(r'HTTP/1\.\d" (\d+)', line)
            status_code = int(status_match.group(1)) if status_match else None

            #Update the IP request counter
            if ip:
                ip_requests[ip] += 1

            #Update the endpoint request counter
            if endpoint:
                endpoint_requests[endpoint] += 1

            #Increment the failed login attempts counter if the status code is 401
            if ip and status_code == 401:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def analyze_logs(ip_requests, endpoint_requests, failed_logins):
    """
    Analyze the parsed log data to derive insights.

    Args:
        ip_requests (Counter): Counts of requests per IP address.
        endpoint_requests (Counter): Counts of requests per endpoint.
        failed_logins (defaultdict): Failed login attempts per IP address.

    Returns:
        tuple: Sorted list of IP requests, the most accessed endpoint, and suspicious IPs.
    """
    #Sort IPs by the number of requests (most to least)
    sorted_ips = ip_requests.most_common()

    #Identify the most accessed endpoint and its request count
    most_accessed_endpoint, access_count = endpoint_requests.most_common(1)[0]

    #Find IPs with failed login attempts exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

    return sorted_ips, (most_accessed_endpoint, access_count), suspicious_ips

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips, output_file):
    """
    Save the analysis results to a CSV file.

    Args:
        ip_requests (list): Sorted list of IP requests and counts.
        most_accessed_endpoint (tuple): Most accessed endpoint and its count.
        suspicious_ips (dict): Suspicious IPs and their failed login attempt counts.
        output_file (str): Name of the output CSV file.
    """
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        #Write the IP request counts to the CSV
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_requests)
        writer.writerow([])

        #Write the most accessed endpoint to the CSV
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])

        #Write the suspicious activity section to the CSV
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def display_results(ip_requests, most_accessed_endpoint, suspicious_ips):
    """
    Display the analysis results in the terminal.

    Args:
        ip_requests (list): Sorted list of IP requests and counts.
        most_accessed_endpoint (tuple): Most accessed endpoint and its count.
        suspicious_ips (dict): Suspicious IPs and their failed login attempt counts.
    """
    #Display IP request counts
    print("IP Address Request Counts:")
    print(f"{'IP Address':<20}{'Request Count'}")
    for ip, count in ip_requests:
        print(f"{ip:<20}{count}")
    print("\n")

    #Display the most accessed endpoint
    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\n")

    #Display suspicious activity (if any)
    print("Suspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts'}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")
    print("\n")

def main():
    """
    Main function to execute the log analysis workflow.
    """
    #Parse the log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)

    #Analyze the parsed log data
    sorted_ips, most_accessed_endpoint, suspicious_ips = analyze_logs(ip_requests, endpoint_requests, failed_logins)

    #Display the results in the terminal
    display_results(sorted_ips, most_accessed_endpoint, suspicious_ips)

    #Save the results to a CSV file
    save_to_csv(sorted_ips, most_accessed_endpoint, suspicious_ips, OUTPUT_CSV)

#Execute the main function if the script is run directly
if __name__ == "__main__":
    main()
