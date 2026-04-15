# Contributing to Flowra AI

Thank you for your interest in contributing to Flowra AI! This project serves as an adaptive security framework bridging the gap between raw ML inference architectures and production reliability.

## Setting Up Locally

To get started, spin up the local environment and the exact dependency stack using `docker-compose`:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/shivang398/Flowra-AI.git
   cd Flowra-AI
   ```

2. **Configure your Variables:**
   ```bash
   cp .env.example .env
   # Make sure to securely enter your OPENAI_API_KEY inside the .env
   ```

3. **Spin up the stack:**
   ```bash
   docker-compose up -d
   ```
   This will cleanly boot both the Redis cache for Bayesian threshold persistence and the FastAPI core instances natively. You can now access `127.0.0.1:8000/dashboard`.

## Running the Architecture Tests

All logic is thoroughly evaluated using standard `pytest`:
```bash
# If running locally out of docker:
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```
**Important:** Do NOT commit any heavy `.pkl` binaries generated out from the model folder into your pull requests. This breaks standard version control systems. They are explicitly ignored in `.gitignore`.

Any improvements to the Machine Learning logic directly beneath `app/ml/` should provide comparative matrix bounds testing evaluating new behaviors.

Thanks again for contributing!
