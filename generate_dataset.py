import pandas as pd
import random

random.seed(42)

data = []

# NORMAL traffic
for _ in range(1000):
    data.append([
        random.randint(10, 80),
        random.randint(500, 8000),
        random.randint(5, 60),
        random.uniform(0.5, 8),
        random.uniform(50, 1000),
        random.randint(1, 5),
        random.randint(1, 10),
        6,
        "NORMAL"
    ])

# DDOS traffic
for _ in range(500):
    data.append([
        random.randint(3000, 10000),
        random.randint(500000, 10000000),
        random.randint(3, 15),
        random.uniform(300, 1500),
        random.uniform(50000, 1500000),
        random.randint(1, 5),
        random.randint(1000, 10000),
        6,
        "DDOS"
    ])

# PORT SCAN
for _ in range(500):
    data.append([
        random.randint(100, 800),
        random.randint(5000, 50000),
        random.randint(5, 30),
        random.uniform(5, 40),
        random.uniform(500, 3000),
        random.randint(50, 300),
        random.randint(50, 300),
        6,
        "PORT_SCAN"
    ])

# C2 BEACON
for _ in range(500):
    data.append([
        random.randint(20, 80),
        random.randint(1000, 8000),
        random.randint(30, 120),
        random.uniform(0.5, 3),
        random.uniform(50, 500),
        random.randint(1, 3),
        random.randint(20, 100),
        6,
        "C2_BEACON"
    ])

columns = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "packets_per_second",
    "bytes_per_second",
    "destination_port_count",
    "connection_count",
    "protocol",
    "label"
]

df = pd.DataFrame(data, columns=columns)

df = df.sample(frac=1, random_state=42)

df.to_csv("../data/traffic.csv", index=False)

print("Dataset created successfully!")
print("Total records:", len(df))
print(df["label"].value_counts())