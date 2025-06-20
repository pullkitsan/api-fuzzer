# 🛡️ API Fuzzer Toolkit

A flexible and customizable CLI tool to fuzz API endpoints based on Swagger/OpenAPI specifications. Supports advanced modes like combo fuzzing, HTML reporting, regex-based response filtering, and proxy integration.

---

## 🔧 Features

- Fuzz REST APIs using wordlists with `<<FUZZ_param>>` placeholders
- Swagger/OpenAPI support with interactive param selection
- Combo Mode (Cluster Bomb style multi-param fuzzing)
- HTML report generation (side-by-side request/response)
- Regex-based filtering on response body (case-insensitive)
- Proxy support for routing traffic through tools like Burp Suite / mitmproxy
- Auth header injection (`--auth-header`)
- Optional request/response logging
- Baseline response comparison
- Static-only mode (no fuzzing) if no parameters selected

---

## 🚀 Getting Started

### 1. Clone the Repo

```bash
git clone https://github.com/pullkitsan/api-fuzzer.git
cd api-fuzzer
```

### 2. Install Dependencies

Install Python dependencies with:

```bash
pip3 install -r requirements.txt
```

### 3. Run the Tool

#### Swagger-based Interactive Flow

```bash
python3 api_fuzzer.py --swagger-file openapi.json --base-url http://localhost:5000
```

### Dry run - Shows the parsed endpoints from api spec file 

```bash
python3 api_fuzzer.py --swagger-file openapi.json --base-url http://localhost:5000 --dry-run
```

#### CLI Manual Mode

```bash
python3 api_fuzzer.py \
  --url http://localhost:5000/api/users/userId \
  --method POST \
  --body '{"username": "<<FUZZ_username>>", "email": “<<FUZZ_email>>”}' \
  --params userId,email \
  --combo \
  --wordlist list.txt \
  --proxy http://127.0.0.1:8080 \
  --report report.html
```

#### CLI Swagger Mode

```bash
python3 api_fuzzer.py \
  --base-url http://localhost:5000 \
  --swagger-file <API_SPEC_FILE> \
  --report <REPORT_NAME> \
  --proxy http://127.0.0.1:8080 \
  --combo
```

## 📄 Arguments

| Argument              | Description |
|-----------------------|-------------|
| `--swagger-file`      | Path to Swagger/OpenAPI JSON |
| `--base-url`          | Base URL to prefix all endpoints( used with api spec file)  |
| `--url`               | Full URL (manual mode and not used with api spec file) |
| `--method`            | HTTP method (GET, POST, PUT...) |
| `--body`              | Request body with `<<FUZZ_param>>` placeholders |
| `--params`            | Comma-separated list of params to fuzz |
| `--wordlist`          | Wordlist path |
| `--combo`             | Enable combo mode |
| `--delay`             | Delay between requests |
| `--auth-header`       | Authorization header |
| `--proxy`             | HTTP/HTTPS proxy (e.g., Burp Suite) |
| `--include-regex`     | Case-insensitive regex to match response body |
| `--save-request`      | Save all requests to file( results/requests.txt ) |
| `--save-response`     | Save all responses to file ( results/responses.txt)|
| `--report`            | Generate HTML report |
| `--dry-run`           | Shows parsed api endpoints with parameters to fuzz |
| `--help`              | Displays all the available arguments |

---

## 📦 Requirements

Install dependencies via:

```bash
pip3 install -r requirements.txt
```
---

## 📊 Report Example

The tool generates a clean HTML report that shows:

- Request URL, headers, and body on the left
- Response headers and body on the right
- Color-coded status and lengths
- Only interesting or filtered responses (if regex is used)

---

## ✅ TODO / Roadmap

- [x] Proxy routing
- [x] Swagger integration
- [x] Auth header support
- [x] HTML report generation
- [x] Combo fuzzing
- [x] Regex filter
- [ ] gRPC support
- [ ] Learning mode from proxied traffic

---
