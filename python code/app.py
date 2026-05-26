from flask import Flask, render_template, request, jsonify
from detector import detect_phishing
from data_consistency import SafeRecordWriter
from admin_panel import AdminPanel
import os
import json
from datetime import datetime

app = Flask(__name__)

# Initialize components
writer = SafeRecordWriter("scan_records.json")
admin = AdminPanel("scan_records.json")

@app.route("/")
def home():
    """Main page"""
    # Get latest scans
    latest_scans = []
    if os.path.exists("scan_records.json"):
        try:
            with open("scan_records.json", 'r') as f:
                records = json.load(f)
                latest_scans = sorted(
                    records,
                    key=lambda x: x.get("timestamp", ""),
                    reverse=True
                )[:10]
        except:
            pass
    
    # Get statistics
    try:
        stats = admin.get_summary_counts()
    except:
        stats = {"total_links_checked": 0, "safe_links": 0, "suspicious_links": 0, "phishing_links": 0}
    
    return render_template("index.html", latest_scans=latest_scans, stats=stats)

@app.route("/scan", methods=["POST"])
def scan():
    """Handle URL scanning"""
    url = request.form.get("url", "").strip()
    
    if not url:
        return render_template("index.html", error="Please enter a URL", result=None)
    
    # Add https:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Scan URL
    detection_result = detect_phishing(url)
    
    # Check for error
    if "error" in detection_result:
        return render_template("index.html", error=detection_result["error"], result=None, scanned_url=url)
    
    # Save to records
    writer.add_record_safely(url, detection_result)
    
    return render_template("index.html", result=detection_result, error=None, scanned_url=url)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """API endpoint for AJAX scanning"""
    data = request.get_json() if request.is_json else {}
    url = data.get("url", request.form.get("url", ""))
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    detection_result = detect_phishing(url)
    
    if "error" not in detection_result:
        writer.add_record_safely(url, detection_result)
    
    return jsonify(detection_result)

@app.route("/dashboard")
def dashboard():
    """Admin dashboard page"""
    dashboard_data = admin.generate_dashboard()
    stats = admin.get_summary_counts()
    
    # Get all records for the table
    records = []
    if os.path.exists("scan_records.json"):
        try:
            with open("scan_records.json", 'r') as f:
                records = json.load(f)
        except:
            pass
    
    return render_template("dashboard.html", dashboard=dashboard_data, stats=stats, records=records)

@app.route("/api/stats")
def api_stats():
    """API for statistics"""
    try:
        stats = admin.get_summary_counts()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # Create templates folder if needed
    if not os.path.exists("templates"):
        os.makedirs("templates")
    
    print("\n" + "="*50)
    print("🛡️  Phishing Detector Web App")
    print("="*50)
    print(f"🌐 Main Page: http://localhost:5000")
    print(f"📊 Dashboard: http://localhost:5000/dashboard")
    print("="*50 + "\n")
    
    app.run(debug=True, host="0.0.0.0", port=5000)