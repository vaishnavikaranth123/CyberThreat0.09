from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time


def capture_flows(duration=5):

    flows = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "timestamps": [],
        "destination_ports": set()
    })

    def process_packet(packet):

        # Only IPv4 traffic
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        source_ip = ip.src
        destination_ip = ip.dst

        # Identify protocol and destination port
        if packet.haslayer(TCP):

            protocol = 6
            destination_port = int(
                packet[TCP].dport
            )

        elif packet.haslayer(UDP):

            protocol = 17
            destination_port = int(
                packet[UDP].dport
            )

        else:

            protocol = int(ip.proto)
            destination_port = 0

        # -------------------------------------------------
        # UNIDIRECTIONAL FLOW
        # Source → Destination is kept separate from
        # Destination → Source
        # -------------------------------------------------

        flow_key = (
            source_ip,
            destination_ip,
            protocol
        )

        flow = flows[flow_key]

        flow["packet_count"] += 1

        flow["byte_count"] += len(packet)

        flow["timestamps"].append(
            time.time()
        )

        # Store destination ports
        if destination_port != 0:

            flow["destination_ports"].add(
                destination_port
            )

    # -----------------------------------------------------
    # START CAPTURE
    # -----------------------------------------------------

    print(
        f"Capturing LIVE unidirectional traffic "
        f"for {duration} seconds..."
    )

    sniff(
        prn=process_packet,
        timeout=duration,
        store=False
    )

    # -----------------------------------------------------
    # CONVERT FLOWS TO ML FEATURES
    # -----------------------------------------------------

    results = []

    for (
        source_ip,
        destination_ip,
        protocol
    ), flow in flows.items():

        timestamps = flow["timestamps"]

        packet_count = flow["packet_count"]

        byte_count = flow["byte_count"]

        # -------------------------------------------------
        # FLOW DURATION
        # -------------------------------------------------

        if len(timestamps) > 1:

            flow_duration = (
                max(timestamps)
                - min(timestamps)
            )

            flow_duration = max(
                flow_duration,
                0.001
            )

        else:

            flow_duration = 0.001

        # -------------------------------------------------
        # RATES
        # -------------------------------------------------

        packets_per_second = (
            packet_count /
            flow_duration
        )

        bytes_per_second = (
            byte_count /
            flow_duration
        )

        # -------------------------------------------------
        # DESTINATION PORTS
        # -------------------------------------------------

        ports = flow[
            "destination_ports"
        ]

        if ports:

            destination_port = min(ports)

        else:

            destination_port = 0

        # -------------------------------------------------
        # FINAL FLOW
        # -------------------------------------------------

        results.append({

            "source_ip":
                source_ip,

            "destination_ip":
                destination_ip,

            "packet_count":
                packet_count,

            "byte_count":
                byte_count,

            "flow_duration":
                round(
                    flow_duration,
                    3
                ),

            "packets_per_second":
                round(
                    packets_per_second,
                    3
                ),

            "bytes_per_second":
                round(
                    bytes_per_second,
                    3
                ),

            "destination_port_count":
                len(ports),

            "connection_count":
                packet_count,

            "protocol":
                protocol,

            "destination_port":
                destination_port
        })

    print(
        f"Captured {len(results)} "
        f"unidirectional flows."
    )

    return results