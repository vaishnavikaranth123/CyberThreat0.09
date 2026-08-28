import sys
import os

# =========================================================
# PROJECT PATH
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if PROJECT_ROOT not in sys.path:

    sys.path.insert(
        0,
        PROJECT_ROOT
    )


# =========================================================
# IMPORTS
# =========================================================

import streamlit as st
import pandas as pd

from datetime import datetime

from streamlit_autorefresh import (
    st_autorefresh
)

from detection.traffic_capture import (
    capture_flows
)

from detection.detect_threat import (
    detect_threat
)

from forensic.record_incident import (
    record_incident
)


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(

    page_title="AI Cyber Security SOC",

    page_icon="🛡️",

    layout="wide"
)


# =========================================================
# TITLE
# =========================================================

st.title(
    "🛡️ AI Cyber Security SOC"
)

st.caption(
    "LIVE • Passive / Unidirectional "
    "IP Traffic Monitoring"
)

st.divider()


# =========================================================
# SESSION STATE
# =========================================================

if "flows" not in st.session_state:

    st.session_state.flows = []


if "incidents" not in st.session_state:

    st.session_state.incidents = []


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.header(
    "⚙️ Monitoring"
)


capture_time = st.sidebar.slider(

    "Capture interval (seconds)",

    min_value=3,

    max_value=10,

    value=5
)


live_mode = st.sidebar.checkbox(

    "🔴 Enable Live Monitoring"
)


if st.sidebar.button(
    "🗑️ Clear Dashboard"
):

    st.session_state.flows = []

    st.session_state.incidents = []

    st.rerun()


# =========================================================
# ANALYZE TRAFFIC
# =========================================================

def analyze_traffic():

    with st.spinner(

        f"📡 Capturing traffic "
        f"for {capture_time} seconds..."
    ):

        flows = capture_flows(
            capture_time
        )


    new_flows = []

    new_incidents = []


    # =====================================================
    # PROCESS EACH FLOW
    # =====================================================

    for flow in flows:

        try:

            # ---------------------------------------------
            # AI DETECTION
            # ---------------------------------------------

            result = detect_threat(
                flow
            )


            detection_time = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )


            # ---------------------------------------------
            # FLOW RECORD
            # ---------------------------------------------

            flow_record = {

                "Time":
                    detection_time,

                "Source IP":
                    flow["source_ip"],

                "Destination IP":
                    flow["destination_ip"],

                "Protocol":
                    flow["protocol"],

                "Destination Port":
                    flow["destination_port"],

                "Packets":
                    flow["packet_count"],

                "Bytes":
                    flow["byte_count"],

                "Duration (s)":
                    flow["flow_duration"],

                "Packets/sec":
                    flow["packets_per_second"],

                "Bytes/sec":
                    flow["bytes_per_second"],

                "Destination Ports":
                    flow["destination_port_count"],

                "Connections":
                    flow["connection_count"],

                "Threat":
                    result["threat"],

                "Risk":
                    result["risk"],

                "Risk Score":
                    result["risk_score"],

                "Confidence %":
                    result["confidence"],

                "Evidence":
                    "; ".join(
                        result["evidence"]
                    )
            }


            new_flows.append(
                flow_record
            )


            # =============================================
            # INCIDENT RECORDING
            # =============================================

            if result["threat"] != "NORMAL":

                incident_id = (
                    record_incident(

                        result["threat"],

                        result["risk"],

                        result["risk_score"],

                        result["confidence"],

                        result["evidence"]
                    )
                )


                incident = {

                    "Incident ID":
                        incident_id,

                    "Incident Time":
                        detection_time,

                    "Source IP":
                        flow["source_ip"],

                    "Destination IP":
                        flow["destination_ip"],

                    "Threat":
                        result["threat"],

                    "Risk":
                        result["risk"],

                    "Risk Score":
                        result["risk_score"],

                    "Confidence %":
                        result["confidence"],

                    "Evidence":
                        "; ".join(
                            result["evidence"]
                        ),

                    "Status":
                        "INVESTIGATION"
                }


                new_incidents.append(
                    incident
                )


        except Exception as e:

            st.error(
                f"Detection error: {e}"
            )


    return (
        new_flows,
        new_incidents
    )


# =========================================================
# LIVE MONITORING
# =========================================================

if live_mode:

    st_autorefresh(

        interval=5000,

        key="live_monitor_refresh"
    )


    st.success(
        "🔴 LIVE MONITORING ACTIVE"
    )


    new_flows, new_incidents = (
        analyze_traffic()
    )


    st.session_state.flows.extend(
        new_flows
    )


    st.session_state.incidents.extend(
        new_incidents
    )


# =========================================================
# MANUAL CAPTURE
# =========================================================

if not live_mode:

    if st.button(

        "🔍 Capture & Analyze Traffic",

        type="primary"
    ):

        new_flows, new_incidents = (
            analyze_traffic()
        )


        st.session_state.flows.extend(
            new_flows
        )


        st.session_state.incidents.extend(
            new_incidents
        )


        if new_flows:

            st.success(

                f"Captured "
                f"{len(new_flows)} "
                f"unidirectional flows."
            )

        else:

            st.warning(
                "No IPv4 traffic captured."
            )


# =========================================================
# DATAFRAME
# =========================================================

flow_df = pd.DataFrame(
    st.session_state.flows
)


# =========================================================
# SOC OVERVIEW
# =========================================================

st.header(
    "📊 SOC Overview"
)


if not flow_df.empty:

    normal_count = len(

        flow_df[
            flow_df["Threat"]
            == "NORMAL"
        ]
    )


    suspicious_count = len(

        flow_df[
            flow_df["Threat"]
            != "NORMAL"
        ]
    )


    high_count = len(

        flow_df[
            flow_df["Risk"]
            == "HIGH"
        ]
    )


    critical_count = len(

        flow_df[
            flow_df["Risk"]
            == "CRITICAL"
        ]
    )

else:

    normal_count = 0

    suspicious_count = 0

    high_count = 0

    critical_count = 0


col1, col2, col3, col4 = (
    st.columns(4)
)


col1.metric(
    "🟢 Normal",
    normal_count
)


col2.metric(
    "🟡 Suspicious",
    suspicious_count
)


col3.metric(
    "🔴 High Risk",
    high_count
)


col4.metric(
    "🚨 Critical",
    critical_count
)


st.divider()


# =========================================================
# LIVE NETWORK FLOWS
# =========================================================

st.header(
    "📡 Live Unidirectional Network Flows"
)


if not flow_df.empty:

    st.dataframe(

        flow_df.tail(100),

        use_container_width=True,

        hide_index=True
    )

else:

    st.info(
        "Waiting for live network traffic..."
    )


st.divider()


# =========================================================
# AI THREAT DETECTION
# =========================================================

st.header(
    "🤖 AI Threat Detection"
)


if not flow_df.empty:

    threat_df = flow_df[
        flow_df["Threat"] != "NORMAL"
    ]


    if not threat_df.empty:

        st.dataframe(

            threat_df.tail(50),

            use_container_width=True,

            hide_index=True
        )

    else:

        st.success(
            "🟢 No threats detected."
        )

else:

    st.info(
        "AI results will appear "
        "when traffic is captured."
    )


st.divider()


# =========================================================
# INCIDENT TIMELINE
# =========================================================

st.header(
    "🕒 Live Incident Timeline"
)


incident_df = pd.DataFrame(
    st.session_state.incidents
)


if not incident_df.empty:

    st.dataframe(

        incident_df.iloc[::-1].head(50),

        use_container_width=True,

        hide_index=True
    )

else:

    st.info(
        "No incidents detected yet."
    )


st.divider()


# =========================================================
# LATEST INCIDENT
# =========================================================

st.header(
    "🚨 Latest Incident"
)


if not incident_df.empty:

    latest = incident_df.iloc[-1]


    col1, col2, col3 = (
        st.columns(3)
    )


    col1.metric(
        "Threat",
        latest["Threat"]
    )


    col2.metric(
        "Risk Score",
        f"{latest['Risk Score']}/100"
    )


    col3.metric(
        "Confidence",
        f"{latest['Confidence %']}%"
    )


    st.write(
        f"**Incident ID:** "
        f"{latest['Incident ID']}"
    )


    st.write(
        f"**Incident Time:** "
        f"{latest['Incident Time']}"
    )


    st.write(
        f"**Direction:** "
        f"{latest['Source IP']} → "
        f"{latest['Destination IP']}"
    )


    st.write(
        f"**Risk:** "
        f"{latest['Risk']}"
    )


    st.write(
        f"**Evidence:** "
        f"{latest['Evidence']}"
    )


    st.write(
        f"**Status:** "
        f"{latest['Status']}"
    )

else:

    st.info(
        "No security incident recorded."
    )


st.divider()


# =========================================================
# FORENSIC SUMMARY
# =========================================================

st.header(
    "🔎 Forensic Investigation"
)


col1, col2, col3 = (
    st.columns(3)
)


col1.metric(
    "Flows Observed",
    len(
        st.session_state.flows
    )
)


col2.metric(
    "Incidents Recorded",
    len(
        st.session_state.incidents
    )
)


col3.metric(

    "Monitoring Status",

    "LIVE"
    if live_mode
    else "OFF"
)


st.caption(
    "Threat incidents are automatically "
    "recorded in forensic/evidence.csv."
)