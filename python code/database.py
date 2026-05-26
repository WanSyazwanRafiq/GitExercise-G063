# database.py

import json
import os

RECORDS_FILE = "scan_records.json"

def load_records():

    if not os.path.exists(RECORDS_FILE):
        return []

    with open(RECORDS_FILE, "r") as f:
        return json.load(f)


def save_record(record):

    records = load_records()

    records.append(record)

    with open(RECORDS_FILE, "w") as f:
        json.dump(records, f, indent=4)