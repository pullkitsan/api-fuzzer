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
git clone https://github.com/yourusername/api-fuzzer-toolkit.git
cd api-fuzzer-toolkit
```

### 2. Install Dependencies

Install Python dependencies with:

```bash
pip install -r requirements.txt
```

### 3. Run the Tool

#### Swagger-based Interactive Flow

```bash
python api_fuzzer.py --swagger-file openapi.json --base-url http://localhost:5000
```

### Dry run - Shows the parsed endpoints from api spec file 

```bash
python api_fuzzer.py --swagger-file openapi.json --base-url http://localhost:5000 --dry-run
```

#### CLI Manual Mode

```bash
python api_fuzzer.py \
  --url http://localhost:5000/api/users/<<FUZZ_userId>> \
  --method POST \
  --body '{"username": "<<FUZZ_username>>", "email": "abc@example.com"}' \
  --params userId,username \
  --wordlist wordlists/names.txt \
  --delay 0.1 \
  --combo \
  --proxy http://127.0.0.1:8080 \
  --auth-header "Bearer <token>" \
  --include-regex "admin|token" \
  --report report.html
```

---

## 📄 Arguments

| Argument              | Description |
|-----------------------|-------------|
| `--swagger-file`      | Path to Swagger/OpenAPI JSON |
| `--base-url`          | Base URL to prefix all endpoints |
| `--url`               | Full URL (manual mode) |
| `--method`            | HTTP method (GET, POST, PUT...) |
| `--body`              | Request body with `<<FUZZ_param>>` placeholders |
| `--params`            | Comma-separated list of params to fuzz |
| `--wordlist`          | Wordlist path |
| `--combo`             | Enable combo mode |
| `--delay`             | Delay between requests |
| `--auth-header`       | Authorization header |
| `--proxy`             | HTTP/HTTPS proxy (e.g., Burp Suite) |
| `--include-regex`     | Case-insensitive regex to match response body |
| `--save-request`      | Save all requests to file |
| `--save-response`     | Save all responses to file |
| `--report`            | Generate HTML report |
| `--dry-run`           | Shows parsed api endpoints with parameters to fuzz |

---

## 📦 Requirements

Install dependencies via:

```bash
pip install -r requirements.txt
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
