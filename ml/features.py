"""학습·추론·C++ 센서가 공유하는 특징 계약.

이 목록의 '순서'가 곧 특징 벡터의 순서다 — 어긋나면 전부 틀어지므로 한 곳에서만 정의한다.
정확한 CICIDS2017 컬럼 철자는 실제 CSV 헤더를 받아 대조해 확정한다 (docs/design/ai_training.md 4장).
"""

# C++ 센서의 방향별 통계(flow_features.md)에서 뽑을 수 있는 것만 골랐다.
FEATURE_SCHEMA_VERSION = 1

FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
]

LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"
