import csv
import os
import uuid
from datetime import datetime

FILE = "forensic/evidence.csv"


def record_incident(threat, risk, risk_score, confidence, evidence):

    incident_id = "INC-" + str(uuid.uuid4())[:8].upper()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    file_exists = os.path.exists(FILE)

    with open(FILE, "a", newline="") as f:

        writer = csv.writer(f)

        if not file_exists or os.path.getsize(FILE) == 0:
            writer.writerow([
                "Incident_ID",
                "Timestamp",
                "Threat",
                "Risk",
                "Risk_Score",
                "Confidence",
                "Evidence"
            ])

        writer.writerow([
            incident_id,
            timestamp,
            threat,
            risk,
            risk_score,
            confidence,
            evidence
        ])

    return incident_id