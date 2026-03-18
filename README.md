# Model Armor Interactive Demo

Interactive web app demonstrating [Google Cloud Model Armor](https://cloud.google.com/security/products/model-armor) — a GCP service that screens LLM prompts and responses for safety risks including prompt injection, jailbreaks, PII leakage, malicious URLs, and responsible AI violations.

## Prerequisites

- Python 3.10+
- A GCP project
- Authenticated with `gcloud auth application-default login`

## Setup

```bash
# 1. Enable the required APIs
gcloud services enable modelarmor.googleapis.com --project=YOUR_PROJECT_ID
gcloud services enable dlp.googleapis.com --project=YOUR_PROJECT_ID

# 2. Install dependencies
python3 -m pip install -r requirements.txt --index-url https://pypi.org/simple/

# 3. Configure environment
cp .env.example .env
# Edit .env with your GCP project ID and region
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GCP_PROJECT_ID` | Your GCP project ID | — |
| `GCP_REGION` | Region where Model Armor is enabled | `us-central1` |
| `MODEL_ARMOR_TEMPLATE_ID` | Template name for the demo | `demo-template` |
| `PORT` | Server port | `5610` |

### Create the template

Run the setup script to create a Cloud DLP inspect template and a Model Armor template with all filters enabled:

```bash
python3 setup_template.py
```

This creates:
1. A **Cloud DLP inspect template** for PII detection (Australian TFN, Medicare, drivers licence, passport, plus universal PII and credentials)
2. A **Model Armor template** with the following filters at `MEDIUM_AND_ABOVE` confidence:
   - Prompt Injection & Jailbreak detection
   - Malicious URI filtering (via Google Safe Browsing)
   - Responsible AI filters (hate speech, harassment, sexually explicit, dangerous)
   - Sensitive Data Protection via Cloud DLP (advanced mode)

The script is idempotent — if the template already exists, it verifies the configuration and moves on.

You can also create the template from the web UI by clicking the **Setup Template** button on first load.

## Running

```bash
python3 server.py
```

Open http://localhost:5610 in your browser.

## Demo scenarios

The app includes pre-built attack scenarios you can trigger with one click:

| Scenario | What it tests | Expected result |
|----------|--------------|-----------------|
| **Prompt Injection** | Attempts to override system instructions | Blocked by PI & Jailbreak filter |
| **Jailbreak** | DAN-style role-play bypass | Blocked by PI & Jailbreak filter |
| **PII / Sensitive Data** | Australian TFN, Medicare, credit cards, API keys | Blocked by SDP filter |
| **Malicious URLs** | Known phishing/malware test URLs | Blocked by Malicious URI filter |
| **Hate Speech** | Content targeting protected groups | Blocked by RAI filter |
| **Safe Prompt (Control)** | Normal productivity question | Passes all filters |

## Features

- **Sanitize Prompt** — screens user input before it reaches your LLM
- **Sanitize Response** — screens model output before it reaches the user
- **Custom text** — type any prompt to test beyond the built-in scenarios
- **Configuration panel** — adjust confidence thresholds and toggle filters
- **Raw JSON view** — inspect the full API response for technical deep-dives

---

*Last updated: March 2026*

Questions or feedback? Reach out to [gvoz@google.com](mailto:gvoz@google.com).
