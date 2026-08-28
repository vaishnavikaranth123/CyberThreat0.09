import hashlib
import os

EVIDENCE_FILE = "forensic/evidence.csv"
HASH_FILE = "forensic/evidence_hash.txt"


def create_evidence_hash():

    if not os.path.exists(EVIDENCE_FILE):
        print("Evidence file not found.")
        return None

    with open(EVIDENCE_FILE, "rb") as f:
        evidence_data = f.read()

    sha256_hash = hashlib.sha256(
        evidence_data
    ).hexdigest()

    with open(HASH_FILE, "w") as f:
        f.write(sha256_hash)

    print("Evidence integrity hash created.")
    print(sha256_hash)

    return sha256_hash


if __name__ == "__main__":
    create_evidence_hash()