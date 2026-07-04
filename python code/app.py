from flask import Flask, render_template, request, jsonify
from detector import detect_phishing
from database import Database
from data_consistency import SafeRecordWriter
from admin_panel import AdminPanel
import os
import json
from datetime import datetime

app = Flask(__name__)

writer = SafeRecordWriter("scan_records.json")
admin = AdminPanel("scan_records.json")
db = Database("phishing_detector.db")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    email = request.form.get("email", "").strip()
    
    if not url:
        return jsonify({"error": "Please enter a URL"}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    detection_result = detect_phishing(url)
    
    if "error" in detection_result:
        return jsonify({"error": detection_result["error"]}), 400
    
    # Add email to result
    detection_result["email"] = email
    
    writer.add_record_safely(url, detection_result)
    db.add_scan(url, detection_result, email)
    
    return jsonify(detection_result)

@app.route("/api/stats")
def api_stats():
    try:
        stats = admin.get_summary_counts()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history")
def api_history():
    try:
        if os.path.exists("scan_records.json"):
            with open("scan_records.json", 'r') as f:
                records = json.load(f)
            return jsonify(records)
        return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")
    
if __name__ == "__main__":
    if not os.path.exists("templates"):
        os.makedirs("templates")
    
    print("\n" + "="*50)
    print("🛡️  Phishing Detector Web App")
    print("="*50)
    print(f"🌐 Main Page: http://localhost:5000")
    print(f"📊 Dashboard: http://localhost:5000/dashboard")
    print("="*50 + "\n")
    
    app.run(debug=True, host="0.0.0.0", port=5000)