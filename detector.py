# detector.py

import requests
import validators

API_KEY = "0bf96eb9a08d1bdc13173064bca11c510f0c39ed5e61cadd1b760f0251ba61a1"

def calculate_risk_level(score):
    if score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "CLEAN"


def detect_phishing(url):

    # Validate URL
    if not validators.url(url):
        return {
            "error": "Invalid URL"
        }

    endpoint = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "x-apikey": API_KEY
    }

    # Submit URL
    response = requests.post(
        endpoint,
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return {
            "error": "VirusTotal API Error"
        }

    analysis_id = response.json()["data"]["id"]

    # Get report
    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    report_response = requests.get(
        report_url,
        headers=headers
    )

    report_data = report_response.json()

    stats = report_data["data"]["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    total = malicious + suspicious + harmless + undetected

    risk_score = round(
        ((malicious * 2 + suspicious) / (total * 2)) * 100,
        2
    )

    risk_level = calculate_risk_level(risk_score)

    return {
        "url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "is_phishing": malicious > 0,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "total_engines": total,
        "recommendation": (
            "Avoid visiting this website"
            if malicious > 0
            else "Website appears safe"
        )
    }