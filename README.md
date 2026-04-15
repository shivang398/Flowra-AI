# 🛡️ Flowra AI — Adaptive Security & Alignment Layer for AI Systems

 Flowra AI is a real-time, behavior-aware security and control layer for AI inference systems. It combines unsupervised anomaly detection, behavioral fingerprinting, natural language prompt injection checks, and a live reinforcement-learning feedback loop to protect AI APIs from abuse while maintaining performance and efficiency.

---

## 🚀 Overview

Modern AI APIs face critical challenges:
- 🚨 **API abuse and request flooding**
- 💸 **Increased operational cost**
- ⚠️ **Performance degradation under load**
- 🤖 **Prompt injection and jailbreaks from malicious actors**

Sentinel AI introduces an **adaptive intelligence layer** that learns user behavior and dynamically controls system usage in real time, securely bridging the gap between raw ML inference and production availability.

---

## 🧩 System Architecture

```text
User → Auth → Feature Extraction → Fingerprinting → Injection Scan → Anomaly Detection → Decision → Inference
                                                                                           |
                                              Interactive UI Dashboard ← Structured Logs ← ┘
                                                       |
          Persistent Redis Bayesian Tuning Thresholds ←┘
```

---

## 🧠 Core Security Layers

### 1️⃣ Behavioral Fingerprinting 🧬
Builds mathematical, user-specific profiles mapping exact request speeds and payload sizes over time, seamlessly matching current payloads against historical context saved in **Redis** cache.

### 2️⃣ Anomaly Detection 🧠
Trains a synthetic `IsolationForest` (unsupervised ML) parameter space over expected traffic distributions to flag entirely unheard-of traffic patterns instantly.

### 3️⃣ LLM Prompt Injection Detection 🛡️
Utilizes rigorous Regex filtering coupled inherently with a zero-temperature **OpenAI API** semantic check. Safe from outages due to native architectural uncertainty fallbacks (`LLM_API_OFFLINE_UNCERTAIN`).

### 4️⃣ The Bayesian Decision Engine 🚦
Aggregates all four distinct threat vectors contextually, rather than rigidly. Maps the final security confidence score to a live tuning threshold yielding:
* 🟢 **Allow** → Executes inference securely.
* 🟡 **Throttle** → Introduces artificial Token-Bucket delays.
* 🔴 **Block** → Hard rejects and caches IP to block registries.

---

## 📊 Live Observability & Reinforcement

Sentinel AI doesn't just passively read logs. It implements a fully automated tuning feedback loop explicitly tailored to its traffic.
- **The Dashboard:** Visit `GET /dashboard` to render a modern Tailwind/Chart.js user interface parsing AI decisions in real-time.
- **The Reinforcement Loop:** Administrators can explicitly correct the API's decisions via one-click **Valid Action** or **False Pos** buttons natively inside the dashboard log trail. 
- **Learning Retained:** Modifying the rules structurally pushes Bayesian nudges out to your persistence engine (`Redis`), guaranteeing that the exact AI strictness thresholds scale seamlessly without wiping on container restages.

---

## 🛠️ Tech Stack & Structure

Sentinel AI reflects an enterprise-grade architectural layout:
* **Backend:** FastAPI (Modular routes and scoped domain engines)
* **ML Engines:** scikit-learn (`app/ml/`, `IsolationForest`)
* **Persistence:** Redis (`docker-compose` deployed)
* **Observability:** Jinja2, TailwindCSS, Chart.js
* **Testing:** Pytest native environment (`tests/`)

---

## 📦 Installation & Deployment

Deploying Sentinel AI leverages internal `docker-compose` logic to establish both the core Python engine and Redis memory instances seamlessly.

```bash
git clone https://github.com/your-username/sentinel-ai.git
cd sentinel-ai

# Set your environmental keys securely
cp .env.example .env
# Edit .env with your OPENAI_API_KEY and a SENTINEL_ADMIN_KEY

# Spin up the infrastructure
docker-compose up -d
```

> If testing locally without Docker:
> ```bash
> pip install -r requirements.txt
> uvicorn app.main:app --reload
> ```

---

## 📡 Usage

### 1. Request a Token
```bash
curl -X GET "http://127.0.0.1:8000/token"
# Copies demo JWT
```

### 2. Post an Inference
```bash
curl -X POST "http://127.0.0.1:8000/secure-predict" \
     -H "Authorization: Bearer <your_token>" \
     -H "Content-Type: application/json" \
     -d '{"data": [5.1, 3.5, 1.4, 0.2]}'
```

### 3. Open the Dashboard
Navigate your browser directly to:
**http://127.0.0.1:8000/dashboard**

---

## 🧪 Testing Suite Coverage

We utilize a comprehensive, module-extracted testing framework natively hooking into the FastAPI `TestClient`. Over 14 test vectors check token-absences, ML isolation metrics, and API bounds seamlessly.

```bash
# From the root directory:
pytest tests/ -v
```

---

## ⚖️ Toward AI Alignment

Sentinel AI contributes to **system-level AI alignment** by enforcing safe system behavior, halting prompt-injection models before executing expensive compute pipelines, and permitting explicitly guided Reinforcement Learning bounds tailored strictly to authentic traffic streams.

⭐ Star this repo if you found it useful!
