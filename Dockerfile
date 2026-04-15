FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-train the model on start if not already trained
CMD ["sh", "-c", "python train_model.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
