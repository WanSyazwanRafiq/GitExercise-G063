from flask import Flask, render_template, request
from detector import detect_phishing
from data_consistency import SafeRecordWriter
from admin_panel import AdminPanel

app = Flask(__name__)

writer = SafeRecordWriter()
admin = AdminPanel()

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form["url"]
    
    detection_result = detect_phishing(url)
    
    # Check if there was an error
    if "error" in detection_result:
        return render_template(
            "index.html",
            error=detection_result["error"],
            result=None
        )
    
    # Save safely
    writer.add_record_safely(url, detection_result)
    
    return render_template(
        "index.html",
        result=detection_result,
        error=None
    )


@app.route("/dashboard")
def dashboard():
    dashboard_data = admin.generate_dashboard()
    
    return render_template(
        "dashboard.html",
        dashboard=dashboard_data
    )


if __name__ == "__main__":
    app.run(debug=True)