import json
import csv
from datetime import datetime, timedelta
from collections import Counter
import os

class AdminPanel:
    def __init__(self, records_file="scan_records.json"):
        """
        Initialize Admin Panel for data processing and summaries
        
        Args:
            records_file: Path to the scan records file
        """
        self.records_file = records_file
        self.records = []
        self.load_records()
    
    def load_records(self):
        """Load all scan records from file"""
        try:
            with open(self.records_file, 'r') as f:
                self.records = json.load(f)
            print(f"✅ Loaded {len(self.records)} scan records")
        except FileNotFoundError:
            print("⚠️  No records file found. Starting with empty data.")
            self.records = []
        except json.JSONDecodeError:
            print("❌ Error reading records file.")
            self.records = []
    
    def get_total_scans(self):
        """Get total number of links checked"""
        return len(self.records)
    
    def get_safe_links(self):
        """Get all safe links (CLEAN or LOW risk)"""
        return [r for r in self.records if r.get("risk_level") in ["CLEAN", "LOW"]]
    
    def get_suspicious_links(self):
        """Get all suspicious links (MEDIUM risk)"""
        return [r for r in self.records if r.get("risk_level") == "MEDIUM"]
    
    def get_phishing_links(self):
        """Get all detected phishing links (HIGH risk or marked as phishing)"""
        return [r for r in self.records if r.get("is_phishing") == True or r.get("risk_level") == "HIGH"]
    
    def get_summary_counts(self):
        """Get basic counts summary"""
        safe_count = len(self.get_safe_links())
        suspicious_count = len(self.get_suspicious_links())
        phishing_count = len(self.get_phishing_links())
        total = self.get_total_scans()
        
        return {
            "total_links_checked": total,
            "safe_links": safe_count,
            "suspicious_links": suspicious_count,
            "phishing_links": phishing_count,
            "safe_percentage": round((safe_count / total * 100), 2) if total > 0 else 0,
            "suspicious_percentage": round((suspicious_count / total * 100), 2) if total > 0 else 0,
            "phishing_percentage": round((phishing_count / total * 100), 2) if total > 0 else 0
        }
    
    def get_daily_summary(self):
        """Get summary grouped by date"""
        daily_data = {}
        
        for record in self.records:
            date = record.get("timestamp", "")[:10]  # Get YYYY-MM-DD
            if date not in daily_data:
                daily_data[date] = {
                    "total": 0,
                    "safe": 0,
                    "suspicious": 0,
                    "phishing": 0
                }
            
            daily_data[date]["total"] += 1
            
            risk_level = record.get("risk_level", "UNKNOWN")
            if risk_level in ["CLEAN", "LOW"]:
                daily_data[date]["safe"] += 1
            elif risk_level == "MEDIUM":
                daily_data[date]["suspicious"] += 1
            elif risk_level == "HIGH":
                daily_data[date]["phishing"] += 1
        
        return daily_data
    
    def get_weekly_summary(self):
        """Get summary for last 7 days"""
        today = datetime.now()
        week_ago = today - timedelta(days=7)
        
        weekly_records = []
        for record in self.records:
            try:
                record_date = datetime.strptime(record.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
                if record_date >= week_ago:
                    weekly_records.append(record)
            except:
                pass
        
        safe = len([r for r in weekly_records if r.get("risk_level") in ["CLEAN", "LOW"]])
        suspicious = len([r for r in weekly_records if r.get("risk_level") == "MEDIUM"])
        phishing = len([r for r in weekly_records if r.get("is_phishing") == True or r.get("risk_level") == "HIGH"])
        total = len(weekly_records)
        
        return {
            "period": f"{week_ago.strftime('%Y-%m-%d')} to {today.strftime('%Y-%m-%d')}",
            "total_scans": total,
            "safe": safe,
            "suspicious": suspicious,
            "phishing": phishing
        }
    
    def get_top_malicious_engines(self):
        """Find which security engines detect the most phishing"""
        engine_detections = Counter()
        
        for record in self.records:
            if record.get("is_phishing"):
                # Note: This requires raw response data
                # Simplified version using malicious count
                pass
        
        return "Engine details available with full API response data"
    
    def get_risk_distribution_chart(self):
        """Create ASCII chart of risk distribution"""
        summary = self.get_summary_counts()
        total = summary["total_links_checked"]
        
        if total == 0:
            return "No data to display"
        
        # Calculate bar lengths
        max_bar_length = 40
        safe_bar = int((summary["safe_links"] / total) * max_bar_length)
        suspicious_bar = int((summary["suspicious_links"] / total) * max_bar_length)
        phishing_bar = int((summary["phishing_links"] / total) * max_bar_length)
        
        chart = f"""

              RISK DISTRIBUTION CHART                      

                                                          
  ✅ SAFE:        {summary['safe_links']:>4} ({summary['safe_percentage']:>5.1f}%)  {'█' * safe_bar}
                                                          
  ⚠️  SUSPICIOUS:  {summary['suspicious_links']:>4} ({summary['suspicious_percentage']:>5.1f}%)  {'█' * suspicious_bar}
                                                          
  🚨 PHISHING:    {summary['phishing_links']:>4} ({summary['phishing_percentage']:>5.1f}%)  {'█' * phishing_bar}
                                                          

        """
        return chart
    
    def generate_dashboard(self):
        """Generate complete admin dashboard"""
        summary = self.get_summary_counts()
        weekly = self.get_weekly_summary()
        
        dashboard = f"""
{'='*60}
                    ADMIN DASHBOARD
{'='*60}

📊 OVERALL SUMMARY
{'─'*60}
  Total Links Checked:    {summary['total_links_checked']}
  
  ✅ Safe Links:           {summary['safe_links']} ({summary['safe_percentage']}%)
  ⚠️  Suspicious Links:     {summary['suspicious_links']} ({summary['suspicious_percentage']}%)
  🚨 Phishing Links:       {summary['phishing_links']} ({summary['phishing_percentage']}%)

📅 WEEKLY REPORT ({weekly['period']})
{'─'*60}
  Scans This Week:         {weekly['total_scans']}
  Safe:                    {weekly['safe']}
  Suspicious:              {weekly['suspicious']}
  Phishing Detected:       {weekly['phishing']}

{self.get_risk_distribution_chart()}

📈 DAILY BREAKDOWN
{'─'*60}
"""
        
        daily = self.get_daily_summary()
        for date in sorted(daily.keys(), reverse=True)[:7]:  # Last 7 days
            data = daily[date]
            dashboard += f"""
  📅 {date}
     Total: {data['total']} | Safe: {data['safe']} | Suspicious: {data['suspicious']} | Phishing: {data['phishing']}
"""
        
        dashboard += f"\n{'='*60}\n"
        return dashboard
    
    def export_dashboard_report(self, filename="admin_dashboard_report.txt"):
        """Export dashboard to a text file"""
        dashboard = self.generate_dashboard()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(dashboard)
            f.write(f"\nReport Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        return f"✅ Dashboard report saved as '{filename}'"
    
    def export_to_excel(self, filename="scan_data_summary.csv"):
        """Export summary data to CSV (opens in Excel)"""
        summary = self.get_summary_counts()
        weekly = self.get_weekly_summary()
        daily = self.get_daily_summary()
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write summary section
            writer.writerow(["ADMIN PANEL SUMMARY"])
            writer.writerow(["Metric", "Count", "Percentage"])
            writer.writerow(["Total Links Checked", summary['total_links_checked'], "100%"])
            writer.writerow(["Safe Links", summary['safe_links'], f"{summary['safe_percentage']}%"])
            writer.writerow(["Suspicious Links", summary['suspicious_links'], f"{summary['suspicious_percentage']}%"])
            writer.writerow(["Phishing Links", summary['phishing_links'], f"{summary['phishing_percentage']}%"])
            
            writer.writerow([])  # Empty row
            writer.writerow(["DAILY BREAKDOWN"])
            writer.writerow(["Date", "Total", "Safe", "Suspicious", "Phishing"])
            
            for date in sorted(daily.keys()):
                data = daily[date]
                writer.writerow([date, data['total'], data['safe'], data['suspicious'], data['phishing']])
        
        return f"✅ Excel-compatible file saved as '{filename}'"
    
    def search_records(self, search_term):
        """Search through all records"""
        results = []
        for record in self.records:
            if (search_term.lower() in record.get("url", "").lower() or
                search_term.lower() in record.get("risk_level", "").lower() or
                search_term.lower() in record.get("recommendation", "").lower()):
                results.append(record)
        
        return results
    
    def get_latest_scans(self, limit=10):
        """Get the most recent scans"""
        sorted_records = sorted(self.records, 
                               key=lambda x: x.get("timestamp", ""), 
                               reverse=True)
        return sorted_records[:limit]
    
    def get_highest_risk_scans(self):
        """Get scans with highest risk scores"""
        return sorted(self.records, 
                     key=lambda x: x.get("risk_score", 0), 
                     reverse=True)[:10]


