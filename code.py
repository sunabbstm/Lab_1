import re
import json
import csv
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from collections import defaultdict

# File paths
LOG_FILE = "server_logs.txt"
FAILED_LOGINS_FILE = "failed_logins.json"
LOG_ANALYSIS_FILE = "log_analysis.txt"
LOG_ANALYSIS_CSV = "log_analysis.csv"
THREAT_IPS_FILE = "threat_ips.json"
COMBINED_SECURITY_DATA_FILE = "combined_security_data.json"

# Addım 1: Jurnalları təhlil et
def parse_logs(file_path):
    try:
        with open(file_path, 'r') as file:
            parsed_data = [
                {
                    "ip": match.group(1),
                    "date": match.group(2),
                    "method": match.group(3),
                    "status": match.group(4)
                }
                for line in file
                if (match := re.search(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(\w+) .*? HTTP/.*?\" (\d+)', line))
            ]
        print(f"Parsed {len(parsed_data)} log entries.")
        return parsed_data
    except Exception as e:
        print(f"Error parsing logs: {e}")
        return []

# Addım 2: Uğursuz girmələri təhlil et
def analyze_failed_logins(parsed_data):
    failed_attempts = defaultdict(int)
    for log in parsed_data:
        if log["status"].startswith("40"):
            failed_attempts[log["ip"]] += 1
    return {ip: count for ip, count in failed_attempts.items() if count >= 5}

# Addım 3: Uğursuz girmələri saxlamaq
def save_failed_logins(failed_logins):
    try:
        with open(FAILED_LOGINS_FILE, 'w') as json_file:
            json.dump(failed_logins, json_file, indent=4)
        print(f"Failed logins saved to {FAILED_LOGINS_FILE}.")

        with open(LOG_ANALYSIS_FILE, 'w') as txt_file:
            for ip, count in failed_logins.items():
                txt_file.write(f"{ip}: {count} failed attempts\n")
        print(f"Log analysis saved to {LOG_ANALYSIS_FILE}.")
    except Exception as e:
        print(f"Error saving failed logins: {e}")

# Addım 4: CSV faylına yazmaq
def write_to_csv(parsed_data):
    try:
        with open(LOG_ANALYSIS_CSV, 'w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=["ip", "date", "method", "status"])
            writer.writeheader()
            writer.writerows(parsed_data)
        print(f"Log data written to {LOG_ANALYSIS_CSV}.")
    except Exception as e:
        print(f"Error writing to CSV: {e}")

# Addım 5: Təhlükə məlumatlarını yığmaq
def scrape_threat_intelligence(url):
    try:
        driver = webdriver.Chrome()
        driver.get(url)
        time.sleep(1.5)
        rows = driver.find_elements(By.XPATH, "//table//tr")
        threat_ips = {
            row.find_elements(By.TAG_NAME, "td")[0].text.strip(): row.find_elements(By.TAG_NAME, "td")[1].text.strip()
            for row in rows[1:]
            if len(row.find_elements(By.TAG_NAME, "td")) >= 2
        }
        driver.quit()
        print(f"Scraped {len(threat_ips)} threat IPs.")
        return threat_ips
    except Exception as e:
        print(f"Error scraping threat intelligence: {e}")
        return {}

# Addım 6: Logları təhlükə məlumatları ilə müqayisə et
def match_threat_ips(parsed_data, threat_ips):
    return [
        {"ip": log["ip"], **log, "description": threat_ips[log["ip"]]}
        for log in parsed_data if log["ip"] in threat_ips
    ]

# Addım 7: Məlumatları birləşdirmək
def combine_data(failed_logins, matched_threats):
    combined_data = {
        "failed_logins": failed_logins,
        "matched_threats": matched_threats
    }
    try:
        with open(COMBINED_SECURITY_DATA_FILE, 'w') as json_file:
            json.dump(combined_data, json_file, indent=4)
        print(f"Combined data saved to {COMBINED_SECURITY_DATA_FILE}.")
    except Exception as e:
        print(f"Error saving combined data: {e}")

# Əsas funksiya
def main():
    parsed_data = parse_logs(LOG_FILE)
    if not parsed_data:
        print("No log data parsed. Exiting.")
        return

    # Uğursuz girmələri təhlil et
    failed_logins = analyze_failed_logins(parsed_data)
    if failed_logins:
        save_failed_logins(failed_logins)
    else:
        print("No IPs with more than 5 failed attempts found.")

    ## Log məlumatlarını CSV faylına yaz
    write_to_csv(parsed_data)

    # Təhlükə məlumatlarını yığ
    threat_intelligence_url = "http://127.0.0.1:8000/"
    threat_ips = scrape_threat_intelligence(threat_intelligence_url)
    if threat_ips:
        with open(THREAT_IPS_FILE, 'w') as json_file:
            json.dump(threat_ips, json_file, indent=4)
        print(f"Threat intelligence data saved to {THREAT_IPS_FILE}.")

    # Logları təhlükə məlumatları ilə müqayisə et
    matched_threats = match_threat_ips(parsed_data, threat_ips)
    if matched_threats:
        combine_data(failed_logins, matched_threats)
    else:
        print("No matches between logs and threat intelligence data.")

if __name__ == "__main__":
    main()