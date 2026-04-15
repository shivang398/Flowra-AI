from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import load_iris
import joblib
import os

X, y = load_iris(return_X_y=True)

model = RandomForestClassifier()
model.fit(X, y)

os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/model.pkl")

print("✅ Model saved")