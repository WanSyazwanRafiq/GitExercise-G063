# detector.py

import requests
import validators
from datetime import datetime
import time

API_KEY = "0bf96eb9a08d1bdc13173064bca11c510f0c39ed5e61cadd1b760f0251ba61a1"

def calculate_risk_level(score):
    if score >= 30:
        return "HIGH"
    elif score >= 10:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "CLEAN"


def detect_phishing(url):
    # Validate URL
    if not validators.url(url):
        return {
            "error": "Invalid URL",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    endpoint = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "x-apikey": API_KEY
    }

    try:
        # Submit URL
        response = requests.post(
            endpoint,
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            return {
                "error": f"VirusTotal API Error: {response.status_code}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        analysis_id = response.json()["data"]["id"]

        # Wait for analysis to complete (VirusTotal is async)
        time.sleep(5)  # Give time for analysis
        
        # Get report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        report_response = requests.get(
            report_url,
            headers=headers
        )

        if report_response.status_code != 200:
            return {
                "error": "Failed to get analysis results",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        report_data = report_response.json()

        stats = report_data["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total = malicious + suspicious + harmless + undetected
        
        if total == 0:
            total = 1  # Prevent division by zero

        risk_score = round(
            ((malicious * 10 + suspicious * 5) / (total * 10)) * 100,
            2
        )

        risk_level = calculate_risk_level(risk_score)

        return {
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_phishing": malicious >= 3 or (malicious >= 1 and risk_score >= 30),
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "recommendation": (
                "Avoid visiting this website"
                if malicious > 0
                else "Website appears safe"
            )
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Network error: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }