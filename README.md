# TotalTwist-Lite

## Overview
**TotalTwist** is a Python tool for detecting typosquatting domains and classifying them using VirusTotal. It leverages the **DNSTwist** tool to identify potential typosquatting domains and analyze their associated IPs to detect malicious activity.

## Features
- **Domain Typosquatting Detection**: Uses DNSTwist to generate and check variants of the target domain.
- **Malicious IP Classification**: Queries VirusTotal to classify IPs as malicious or suspicious.
- **Detailed Results**: Outputs results to a file, categorizing IPs based on VirusTotal analysis.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/TotalTwist.git
   cd TotalTwist
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Ensure DNSTwist is installed on your system:
   ```bash
   sudo apt install dnstwist
   ```

## Usage
1. Replace the placeholders in the script:
   - `[YOUR_VIRUSTOTAL_API_KEY]`: Add your VirusTotal API key.
   - `[TARGET_DOMAIN]`: Specify the domain to analyze.

2. Run the script:
   ```bash
   python TotalTwist.py
   ```

## Output
Results are saved to `dns_ip_results.txt`, categorized as:
- **Confirmed Malicious**: IPs classified as malicious by VirusTotal.
- **Suspicious**: IPs with no malicious classification.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
