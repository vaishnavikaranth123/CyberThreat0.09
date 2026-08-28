import joblib
import pandas as pd


# =========================================================
# FEATURES
# =========================================================

FEATURES = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "packets_per_second",
    "bytes_per_second",
    "destination_port_count",
    "connection_count",
    "protocol"
]


# =========================================================
# LOAD MODEL
# =========================================================

model = joblib.load(
    "models/threat_model.pkl"
)

encoder = joblib.load(
    "models/label_encoder.pkl"
)


# =========================================================
# THREAT DETECTION
# =========================================================

def detect_threat(flow):

    # -----------------------------------------------------
    # Prepare live flow for AI model
    # -----------------------------------------------------

    data = pd.DataFrame([
        {
            feature: flow[feature]
            for feature in FEATURES
        }
    ])


    # -----------------------------------------------------
    # AI prediction
    # -----------------------------------------------------

    prediction = model.predict(data)

    probabilities = model.predict_proba(data)[0]


    # Convert encoded class to threat name
    threat = encoder.inverse_transform(
        prediction
    )[0]


    confidence = max(
        probabilities
    ) * 100


    # =====================================================
    # EVIDENCE GENERATION
    # =====================================================

    evidence = []


    # -----------------------------------------------------
    # DDoS / Flooding indicator
    # -----------------------------------------------------

    if (
        flow["packets_per_second"] > 100
        and flow["packet_count"] >= 10
    ):

        evidence.append(
            "Abnormally high packet rate"
        )


    # -----------------------------------------------------
    # Port scanning indicator
    # -----------------------------------------------------

    if (
        flow["destination_port_count"] > 50
    ):

        evidence.append(
            "Large number of destination ports contacted"
        )


    # -----------------------------------------------------
    # High connection frequency
    # -----------------------------------------------------

    if (
        flow["connection_count"] > 50
        and flow["packet_count"] >= 10
    ):

        evidence.append(
            "Unusually high connection frequency"
        )


    # -----------------------------------------------------
    # C2-like repeated communication
    # -----------------------------------------------------

    if (
        flow["flow_duration"] > 30
        and flow["connection_count"] > 30
    ):

        evidence.append(
            "Repeated communication pattern"
        )


    # =====================================================
    # AI-BASED EVIDENCE FALLBACK
    # =====================================================

    # If the statistical rules did not generate evidence,
    # use the AI classification to provide an explanation.

    if not evidence:

        if threat == "DDOS":

            evidence.append(
                "AI detected abnormal flooding behavior"
            )

        elif threat == "PORT_SCAN":

            evidence.append(
                "AI detected port scanning behavior"
            )

        elif threat == "C2_BEACON":

            evidence.append(
                "AI detected beacon-like communication behavior"
            )

        else:

            evidence.append(
                "Traffic behavior within normal range"
            )


    # =====================================================
    # RISK CALCULATION
    # =====================================================

    if threat == "DDOS":

        risk = "CRITICAL"

        risk_score = min(
            100,
            int(60 + confidence * 0.4)
        )


    elif threat == "PORT_SCAN":

        risk = "HIGH"

        risk_score = min(
            100,
            int(50 + confidence * 0.4)
        )


    elif threat == "C2_BEACON":

        risk = "HIGH"

        risk_score = min(
            100,
            int(50 + confidence * 0.4)
        )


    else:

        risk = "LOW"

        risk_score = int(
            confidence * 0.2
        )


    # =====================================================
    # RETURN RESULT
    # =====================================================

    return {

        "threat": threat,

        "confidence": round(
            confidence,
            2
        ),

        "risk": risk,

        "risk_score": risk_score,

        "evidence": evidence
    }