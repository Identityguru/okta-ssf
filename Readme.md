# SSF Event Transmitter for Okta

A simple Python script that generates Shared Signals Framework (SSF) security events, signs them with RSA keys, and transmits them to Okta's Security Events API.

## Prerequisites

- Python 3.7+
- RSA keypair in JSON format (see `rsa-keypair.json` for structure)
- Okta tenant with Security Events Provider configured

## Quick Start

### 1. Create Virtual Environment
```bash
python -m venv ssf-env
source ssf-env/bin/activate  # On Windows: ssf-env\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Script
```bash
python transmit-okta-event.py
```