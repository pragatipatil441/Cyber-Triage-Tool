from sklearn.ensemble import IsolationForest


# ---------------------------------------------------
# CREATE ML MODEL
# ---------------------------------------------------

model = IsolationForest(
    contamination=0.2,
    random_state=42
)


# ---------------------------------------------------
# TRAIN MODEL
# ---------------------------------------------------

def train_model():

    training_data = [

        # Normal investigation
        [0, 0, 0, 0],

        [1, 0, 0, 1],

        [1, 1, 0, 1],

        [0, 1, 0, 0],

        # Suspicious investigation
        [2, 2, 1, 3],

        [3, 2, 1, 4],

        [3, 3, 2, 4],

        [4, 3, 2, 5],

        # Highly suspicious
        [5, 5, 3, 6],

        [6, 4, 4, 7]

    ]

    model.fit(training_data)


# Train when module loads
train_model()


# ---------------------------------------------------
# DETECT ANOMALY
# ---------------------------------------------------

def detect_anomaly(
    ips,
    urls,
    hashes,
    suspicious_keywords
):

    features = [[

        len(ips),

        len(urls),

        len(hashes),

        len(suspicious_keywords)

    ]]


    prediction = model.predict(
        features
    )[0]


    # Isolation Forest:
    # 1  = Normal
    # -1 = Anomaly

    if prediction == -1:

        anomaly = True

    else:

        anomaly = False


    # Calculate anomaly score

    score = model.decision_function(
        features
    )[0]


    if anomaly:

        status = "Anomalous"

    else:

        status = "Normal"


    return {

        "anomaly": anomaly,

        "status": status,

        "score": round(
            float(score),
            4
        )

    }