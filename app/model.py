import joblib

model = joblib.load("model/model.pkl")


def predict(data):
    return model.predict([data]).tolist()