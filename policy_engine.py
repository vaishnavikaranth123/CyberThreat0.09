def get_response(risk_score):

    if risk_score < 40:
        return "MONITOR"

    elif risk_score < 70:
        return "INCREASED MONITORING"

    elif risk_score < 90:
        return "RESTRICT ACCESS"

    else:
        return "SIMULATED ISOLATION"