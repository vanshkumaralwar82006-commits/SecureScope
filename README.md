# SecureScope — Automated Web Security Scanner

**Internship topic alignment:** Automated Web Scanner — a Python script to audit websites for secure headers and basic CORS behavior.

SecureScope is an educational defensive prototype. It makes ordinary HTTP requests and checks a limited set of visible response settings. It does not exploit vulnerabilities, crawl the site, scan ports, bypass authentication, or prove that a website is secure.

## Features
- HTTPS check after redirects
- Selected HTTP security-header checks
- Basic CORS response observation using a harmless test Origin
- Explainable findings and recommendations
- Dashboard score and Plotly chart
- HTML and CSV report downloads
- Educational notes and demo cases

## Requirements
- Windows 10/11
- Python 3.10 or later recommended
- Internet access for scanning an authorized website

## Run on Windows
1. Extract the ZIP file to a folder, for example `C:\Users\YourName\Desktop\SecureScope`.
2. Open that folder in File Explorer.
3. Click the address bar, type `cmd`, and press Enter.
4. Create a virtual environment:

   ```bat
   py -m venv .venv
   ```

5. Activate it:

   ```bat
   .venv\Scripts\activate
   ```

6. Install packages:

   ```bat
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

7. Start the app:

   ```bat
   python -m streamlit run app.py
   ```

8. The terminal will show a local address, usually `http://localhost:8501`. Open it in your browser.
9. Enter a website only if you own it or have explicit permission to assess it.

## Troubleshooting
- **`py` not recognized:** install Python from the official Python website and enable “Add Python to PATH”, then reopen Command Prompt.
- **`ModuleNotFoundError`:** activate `.venv` and run `pip install -r requirements.txt`.
- **Timeout / connection error:** check internet, URL spelling, firewall, and whether the authorized test website is available.
- **TLS error:** do not disable certificate verification. Check the target's certificate and URL.
- **Port 8501 already in use:** stop the other Streamlit process or run `python -m streamlit run app.py --server.port 8502`.

## How the score works
The score starts at 100 and deducts fixed points for selected findings. It is a simple educational indicator, not a recognized certification or validated risk model. Header absence alone is not necessarily an exploitable vulnerability.

## Responsible use
Only scan systems you own or have explicit authorization to assess. Do not use this tool on private or sensitive systems without permission. Do not enter credentials, tokens, or private URLs.

## Project structure
```text
SecureScope/
├── app.py
├── scanner.py
├── requirements.txt
├── README.md
├── PROJECT_REPORT.md
├── CONCEPT_NOTE.md
├── PRESENTATION_OUTLINE.md
├── DEMO_SCRIPT.md
└── sample_data/
    └── sample_findings.csv
```
