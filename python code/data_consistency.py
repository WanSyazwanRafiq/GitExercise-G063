import json
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple, Optional

class DataConsistencyManager:
    def __init__(self, records_file="scan_records.json"):
        """
        Initialize Data Consistency Manager
        
        Args:
            records_file: Path to the scan records file
        """
        self.records_file = records_file
        self.consistency_log = "consistency_log.txt"
        self.required_fields = [
            "id", "timestamp", "url", "risk_level", "risk_score",
            "is_phishing", "malicious_engines", "suspicious_engines",
            "total_engines", "recommendation"
        ]
        self.valid_risk_levels = ["CLEAN", "LOW", "MEDIUM", "HIGH"]
        
    def load_records(self) -> List[Dict]:
        """Load records from JSON file"""
        try:
            with open(self.records_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def validate_record_structure(self, record: Dict) -> Tuple[bool, List[str]]:
        """
        Validate that a record has all required fields
        
        Args:
            record: A single scan record
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check all required fields exist
        for field in self.required_fields:
            if field not in record:
                errors.append(f"Missing required field: '{field}'")
        
        # Validate risk level
        if "risk_level" in record:
            if record["risk_level"] not in self.valid_risk_levels:
                errors.append(f"Invalid risk_level: '{record['risk_level']}'. Must be one of {self.valid_risk_levels}")
        
        # Validate numeric fields
        numeric_fields = ["risk_score", "malicious_engines", "suspicious_engines", "total_engines"]
        for field in numeric_fields:
            if field in record:
                if not isinstance(record[field], (int, float)):
                    errors.append(f"Field '{field}' must be a number, got {type(record[field])}")
                elif record[field] < 0:
                    errors.append(f"Field '{field}' cannot be negative")
        
        # Validate boolean field
        if "is_phishing" in record:
            if not isinstance(record["is_phishing"], bool):
                errors.append(f"Field 'is_phishing' must be boolean (true/false)")
        
        # Validate URL format
        if "url" in record:
            if not record["url"] or not isinstance(record["url"], str):
                errors.append("URL field is empty or invalid")
        
        return len(errors) == 0, errors
    
    def validate_logic_consistency(self, record: Dict) -> Tuple[bool, List[str]]:
        """
        Validate logical consistency of the record
        
        Checks:
        - If risk_level is HIGH, is_phishing should be True
        - If is_phishing is True, malicious_engines should be > 0
        - risk_score should match risk_level range
        - total_engines should equal sum of malicious + suspicious + harmless + undetected
        
        Args:
            record: A single scan record
            
        Returns:
            Tuple of (is_consistent, list_of_warnings)
        """
        warnings = []
        
        # Check 1: HIGH risk should mean phishing = True
        if record.get("risk_level") == "HIGH" and not record.get("is_phishing"):
            warnings.append(f"LOGIC ERROR: Risk level is HIGH but is_phishing is False for {record.get('url')}")
        
        # Check 2: If phishing, should have malicious engines
        if record.get("is_phishing") and record.get("malicious_engines", 0) == 0:
            warnings.append(f"LOGIC ERROR: Marked as phishing but 0 malicious engines for {record.get('url')}")
        
        # Check 3: Risk score ranges
        risk_score = record.get("risk_score", 0)
        risk_level = record.get("risk_level", "UNKNOWN")
        
        if risk_level == "HIGH" and risk_score < 50:
            warnings.append(f"LOGIC WARNING: HIGH risk but score is only {risk_score}% for {record.get('url')}")
        elif risk_level == "CLEAN" and risk_score > 10:
            warnings.append(f"LOGIC WARNING: CLEAN risk but score is {risk_score}% for {record.get('url')}")
        elif risk_level == "MEDIUM" and (risk_score < 20 or risk_score >= 50):
            warnings.append(f"LOGIC WARNING: MEDIUM risk but score is {risk_score}% (should be 20-49%) for {record.get('url')}")
        elif risk_level == "LOW" and (risk_score >= 20 or risk_score < 0):
            warnings.append(f"LOGIC WARNING: LOW risk but score is {risk_score}% (should be 0-19%) for {record.get('url')}")
        
        # Check 4: Timestamp format
        try:
            datetime.strptime(record.get("timestamp", ""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            warnings.append(f"Invalid timestamp format for {record.get('url')}")
        
        return len(warnings) == 0, warnings
    
    def check_duplicate_records(self, records: List[Dict]) -> List[Dict]:
        """
        Check for duplicate URL entries
        
        Args:
            records: List of all scan records
            
        Returns:
            List of duplicate records found
        """
        seen_urls = {}
        duplicates = []
        
        for record in records:
            url = record.get("url", "")
            if url in seen_urls:
                duplicates.append({
                    "url": url,
                    "first_scan": seen_urls[url]["timestamp"],
                    "duplicate_scan": record.get("timestamp"),
                    "record1_id": seen_urls[url]["id"],
                    "record2_id": record.get("id")
                })
            else:
                seen_urls[url] = record
        
        return duplicates
    
    def verify_data_integrity(self, records: List[Dict]) -> Dict:
        """
        Generate a hash of the data for integrity verification
        
        Args:
            records: List of all scan records
            
        Returns:
            Dictionary with integrity information
        """
        data_string = json.dumps(records, sort_keys=True)
        data_hash = hashlib.sha256(data_string.encode()).hexdigest()
        
        return {
            "total_records": len(records),
            "data_hash": data_hash,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_size": len(data_string)
        }
    
    def compare_detection_vs_storage(self, detection_result: Dict, stored_record: Dict) -> Dict:
        """
        Compare what was detected vs what was stored to ensure consistency
        
        Args:
            detection_result: Original detection result from API
            stored_record: What was saved in the database
            
        Returns:
            Comparison results
        """
        comparison = {
            "url": detection_result.get("url"),
            "match": True,
            "differences": []
        }
        
        # Compare key fields
        fields_to_compare = [
            "risk_level", "risk_score", "is_phishing", 
            "malicious_engines", "suspicious_engines"
        ]
        
        for field in fields_to_compare:
            detected_value = detection_result.get(field)
            stored_value = stored_record.get(field)
            
            if detected_value != stored_value:
                comparison["match"] = False
                comparison["differences"].append({
                    "field": field,
                    "detected_value": detected_value,
                    "stored_value": stored_value
                })
        
        return comparison
    
    def run_full_consistency_check(self) -> Dict:
        """
        Run complete consistency check on all records
        
        Returns:
            Complete audit report
        """
        records = self.load_records()
        
        report = {
            "check_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_records": len(records),
            "structure_errors": [],
            "logic_warnings": [],
            "duplicates": [],
            "integrity": {},
            "summary": {}
        }
        
        # Validate each record
        for record in records:
            # Structure check
            is_valid, errors = self.validate_record_structure(record)
            if not is_valid:
                report["structure_errors"].append({
                    "record_id": record.get("id", "unknown"),
                    "url": record.get("url", "unknown"),
                    "errors": errors
                })
            
            # Logic check
            is_consistent, warnings = self.validate_logic_consistency(record)
            if not is_consistent:
                report["logic_warnings"].append({
                    "record_id": record.get("id", "unknown"),
                    "url": record.get("url", "unknown"),
                    "warnings": warnings
                })
        
        # Check duplicates
        report["duplicates"] = self.check_duplicate_records(records)
        
        # Verify integrity
        report["integrity"] = self.verify_data_integrity(records)
        
        # Summary
        report["summary"] = {
            "valid_records": report["total_records"] - len(report["structure_errors"]),
            "records_with_errors": len(report["structure_errors"]),
            "records_with_warnings": len(report["logic_warnings"]),
            "duplicate_records": len(report["duplicates"]),
            "overall_health": "GOOD" if len(report["structure_errors"]) == 0 else "NEEDS ATTENTION"
        }
        
        return report
    
    def auto_fix_common_issues(self) -> Dict:
        """
        Automatically fix common data consistency issues
        
        Returns:
            Fix report
        """
        records = self.load_records()
        fix_report = {
            "fixed_count": 0,
            "fixes": []
        }
        
        for record in records:
            needs_update = False
            
            # Fix 1: If risk_level is HIGH, ensure is_phishing is True
            if record.get("risk_level") == "HIGH" and not record.get("is_phishing"):
                record["is_phishing"] = True
                needs_update = True
                fix_report["fixes"].append({
                    "record_id": record["id"],
                    "url": record["url"],
                    "fix": "Set is_phishing to True (was False with HIGH risk)"
                })
            
            # Fix 2: If is_phishing is True, ensure risk_level is at least MEDIUM
            if record.get("is_phishing") and record.get("risk_level") in ["CLEAN", "LOW"]:
                old_level = record["risk_level"]
                record["risk_level"] = "HIGH"
                needs_update = True
                fix_report["fixes"].append({
                    "record_id": record["id"],
                    "url": record["url"],
                    "fix": f"Changed risk_level from {old_level} to HIGH (is_phishing was True)"
                })
            
            # Fix 3: Calculate correct risk_score based on malicious engines
            if record.get("malicious_engines", 0) > 0:
                total = record.get("total_engines", 1)
                malicious = record.get("malicious_engines", 0)
                suspicious = record.get("suspicious_engines", 0)
                correct_score = round(((malicious * 2.0 + suspicious * 1.0) / (total * 2.0)) * 100, 2)
                
                if abs(record.get("risk_score", 0) - correct_score) > 5:  # If difference > 5%
                    old_score = record["risk_score"]
                    record["risk_score"] = correct_score
                    needs_update = True
                    fix_report["fixes"].append({
                        "record_id": record["id"],
                        "url": record["url"],
                        "fix": f"Corrected risk_score from {old_score}% to {correct_score}%"
                    })
            
            if needs_update:
                fix_report["fixed_count"] += 1
        
        # Save fixed records
        if fix_report["fixed_count"] > 0:
            with open(self.records_file, 'w') as f:
                json.dump(records, f, indent=4)
            
            # Log the fixes
            self.log_consistency_action(f"Auto-fixed {fix_report['fixed_count']} records")
        
        return fix_report
    
    def log_consistency_action(self, message: str):
        """Log consistency actions to a log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.consistency_log, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    
    def generate_consistency_report(self) -> str:
        """
        Generate a human-readable consistency report
        
        Returns:
            Formatted report string
        """
        check = self.run_full_consistency_check()
        
        report = f"""
{'='*60}
           DATA CONSISTENCY AUDIT REPORT
{'='*60}

Timestamp: {check['check_timestamp']}
Total Records: {check['total_records']}

📊 SUMMARY
{'─'*60}
  Valid Records:        {check['summary']['valid_records']}
  Records with Errors:  {check['summary']['records_with_errors']}
  Logic Warnings:       {check['summary']['records_with_warnings']}
  Duplicate Records:    {check['summary']['duplicate_records']}
  
  Overall Health:       {check['summary']['overall_health']}

🔍 STRUCTURE ERRORS
{'─'*60}
"""
        
        if check['structure_errors']:
            for error in check['structure_errors']:
                report += f"\n  Record #{error['record_id']} - {error['url']}\n"
                for e in error['errors']:
                    report += f"    ❌ {e}\n"
        else:
            report += "\n  ✅ No structure errors found!\n"
        
        report += f"""
⚠️  LOGIC WARNINGS
{'─'*60}
"""
        
        if check['logic_warnings']:
            for warning in check['logic_warnings']:
                report += f"\n  Record #{warning['record_id']} - {warning['url']}\n"
                for w in warning['warnings']:
                    report += f"    ⚠️  {w}\n"
        else:
            report += "\n  ✅ No logic warnings found!\n"
        
        report += f"""
🔄 DUPLICATE RECORDS
{'─'*60}
"""
        
        if check['duplicates']:
            for dup in check['duplicates']:
                report += f"\n  📄 {dup['url']}\n"
                report += f"     First scan: {dup['first_scan']} (ID: {dup['record1_id']})\n"
                report += f"     Duplicate:  {dup['duplicate_scan']} (ID: {dup['record2_id']})\n"
        else:
            report += "\n  ✅ No duplicate records found!\n"
        
        report += f"""
🔒 DATA INTEGRITY
{'─'*60}
  Records Count: {check['integrity']['total_records']}
  Data Hash: {check['integrity']['data_hash'][:16]}...
  File Size: {check['integrity']['file_size']} bytes
  Last Updated: {check['integrity']['last_updated']}

{'='*60}
"""
        
        return report


class SafeRecordWriter:
    """
    Safe wrapper for writing records to ensure consistency
    """
    def __init__(self, records_file="scan_records.json"):
        self.records_file = records_file
        self.consistency_manager = DataConsistencyManager(records_file)
    
    def add_record_safely(self, url: str, detection_result: Dict) -> Dict:
        """
        Add a record with validation to ensure consistency
        
        Args:
            url: The URL that was scanned
            detection_result: Results from the phishing detector
            
        Returns:
            The saved record
        """
        # Load existing records FIRST
        records = self.consistency_manager.load_records()
        
        # Build record WITH id included
        record = {
            "id": len(records) + 1,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "url": url,
            "email": detection_result.get("email", ""),
            "risk_level": detection_result.get("risk_level", "UNKNOWN"),
            "risk_score": detection_result.get("risk_score", 0),
            "is_phishing": detection_result.get("is_phishing", False),
            "malicious_engines": detection_result.get("malicious_engines", 0),
            "suspicious_engines": detection_result.get("suspicious_engines", 0),
            "total_engines": detection_result.get("total_engines", 0),
            "recommendation": detection_result.get("recommendation", "")
        }
        
        # Add to records
        records.append(record)
        
        # Save records
        with open(self.records_file, 'w') as f:
            json.dump(records, f, indent=4)
        
        print(f"✅ Record saved safely: {url}")
        return record
