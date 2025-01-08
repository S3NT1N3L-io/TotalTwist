import os
import subprocess
import requests
import time
import socket

# VirusTotal API Key (Replace with your key)
VIRUSTOTAL_API_KEY = "[YOUR_VIRUSTOTAL_API_KEY]"

# Target domain (Replace with your target domain)
domain = "[TARGET_DOMAIN]"

# Output file for results
output_file = "dns_ip_results.txt"

# Remove output file if it exists
if os.path.exists(output_file):
    os.remove(output_file)

# Function to get the origin IP of the target domain using socket
def get_origin_ip(domain):
    try:
        origin_ip = socket.gethostbyname(domain)
        print(f"Origin IP for {domain}: {origin_ip}")
        return origin_ip
    except Exception as e:
        print(f"Error getting origin IP for {domain}: {e}")
        return None

# Function to query VirusTotal for an IP
def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious > 0:
                return "malicious"
            else:
                return "suspicious"
        elif response.status_code == 429:
            print("Rate limit exceeded. Waiting 15 seconds...")
            time.sleep(15)
            return query_virustotal(ip)  # Retry after waiting
        else:
            print(f"Error querying VirusTotal for {ip}: {response.status_code}")
            return "unknown"
    except Exception as e:
        print(f"Exception querying VirusTotal for {ip}: {e}")
        return "unknown"

# Run DNSTwist for the target domain and exclude the origin IP
def run_dnstwist(domain, origin_ip):
    ip_list = set()  # Collect all unique IPs
    try:
        print("Executing DNSTwist...")
        result = subprocess.run(
            ["dnstwist", "--format", "csv", "--registered", domain],
            capture_output=True,
            text=True,
            timeout=300  # Timeout after 5 minutes
        )
        
        print("DNSTwist completed.")
        dnstwist_output = result.stdout
        print("Raw DNSTwist Output:")
        print(dnstwist_output)  # Print the raw output for debugging
        
        # Process the output
        for line in dnstwist_output.splitlines():
            # Skip the header row
            if "fuzzer,domain,dns_a,dns_aaaa,dns_mx,dns_ns" in line:
                continue
            
            parts = line.split(',')
            if len(parts) > 2:  # Ensure there are enough columns
                ip = parts[2].strip()  # Extract the `dns_a` field
                if ip and ip != origin_ip and ip.count('.') == 3:  # Check valid IP and exclude origin
                    ip_list.add(ip)
    except subprocess.TimeoutExpired:
        print(f"DNSTwist timed out for {domain}.")
    except Exception as e:
        print(f"Error running DNSTwist for {domain}: {e}")
    return ip_list

# Main function
def main():
    # Get the origin IP of the target domain
    origin_ip = get_origin_ip(domain)
    if not origin_ip:
        print("Could not get origin IP. Exiting...")
        return

    # Run DNSTwist and collect all typosquatting IPs
    print("Running DNSTwist...")
    typosquatting_ips = run_dnstwist(domain, origin_ip)
    print(f"Collected {len(typosquatting_ips)} IPs (excluding origin IP).")

    if not typosquatting_ips:
        print("No typosquatting IPs found. Exiting...")
        return

    # Classify IPs using VirusTotal
    confirmed_malicious = []
    suspicious = []

    print("Querying VirusTotal for IPs...")
    for ip in typosquatting_ips:
        print(f"Checking IP: {ip}")
        classification = query_virustotal(ip)
        print(f"VirusTotal Classification for {ip}: {classification}")
        if classification == "malicious":
            confirmed_malicious.append(ip)
        else:
            suspicious.append(ip)

        # Handle VirusTotal rate limit (4 requests per minute for free API)
        time.sleep(15)

    # Write results to file
    with open(output_file, "w") as f:
        f.write("Confirmed Malicious (VirusTotal):\n")
        for ip in confirmed_malicious:
            print(f"Writing malicious IP: {ip}")
            f.write(f"{ip}\n")
        
        f.write("\nSuspicious (all remaining without results):\n")
        for ip in suspicious:
            print(f"Writing suspicious IP: {ip}")
            f.write(f"{ip}\n")

    print(f"Analysis completed. Results saved to {os.path.abspath(output_file)}.")

if __name__ == "__main__":
    main()
