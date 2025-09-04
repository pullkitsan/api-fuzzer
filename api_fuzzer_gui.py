#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import json
import os
import threading
from fuzzer_engine import run_fuzzer
from swagger_parser import parse_swagger
import sys
from io import StringIO

class APIFuzzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("API Fuzzer GUI")
        self.root.geometry("900x700")
        
        # Variables
        self.mode_var = tk.StringVar(value="manual")
        self.method_var = tk.StringVar(value="POST")
        self.combo_var = tk.BooleanVar()
        self.save_request_var = tk.BooleanVar()
        self.save_response_var = tk.BooleanVar()
        
        # Swagger variables
        self.swagger_endpoints = []
        self.selected_endpoint = None
        
        # Fuzzing control variables
        self.fuzzing_active = False
        self.fuzzing_thread = None
        self.stop_event = threading.Event()
        
        self.create_widgets()
        self.toggle_mode()
        self.validate_fields()  # Initial validation
        
    def create_widgets(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main Configuration Tab
        main_frame = ttk.Frame(self.notebook)
        self.notebook.add(main_frame, text="Configuration")
        
        # Mode Selection
        mode_frame = ttk.LabelFrame(main_frame, text="Mode", padding=10)
        mode_frame.pack(fill=tk.X, pady=5)
        
        ttk.Radiobutton(mode_frame, text="Manual Mode", variable=self.mode_var, 
                       value="manual", command=self.toggle_mode).pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="Swagger Mode", variable=self.mode_var, 
                       value="swagger", command=self.toggle_mode).pack(side=tk.LEFT)
        
        # Requirements info
        requirements_text = ttk.Label(mode_frame, text="* = Required fields", 
                                    font=('TkDefaultFont', 9))
        requirements_text.pack(side=tk.RIGHT, padx=10)
        
        # Manual Mode Frame
        self.manual_frame = ttk.LabelFrame(main_frame, text="Manual Configuration", padding=10)
        self.manual_frame.pack(fill=tk.X, pady=5)
        
        # URL
        self.url_label = ttk.Label(self.manual_frame, text="URL: *")
        self.url_label.grid(row=0, column=0, sticky=tk.W, pady=2)
        self.url_entry = ttk.Entry(self.manual_frame, width=70)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, padx=5)
        self.url_entry.insert(0, "http://localhost:5000/api/users/<<FUZZ_userId>>")
        self.url_entry.bind('<KeyRelease>', self.validate_fields)
        
        # Method
        self.method_label = ttk.Label(self.manual_frame, text="Method: *")
        self.method_label.grid(row=1, column=0, sticky=tk.W, pady=2)
        method_combo = ttk.Combobox(self.manual_frame, textvariable=self.method_var, 
                                   values=["GET", "POST", "PUT", "DELETE", "PATCH"])
        method_combo.grid(row=1, column=1, sticky=tk.W, padx=5)
        method_combo.bind('<<ComboboxSelected>>', self.validate_fields)
        
        # Request Body
        self.body_label = ttk.Label(self.manual_frame, text="Request Body: *")
        self.body_label.grid(row=2, column=0, sticky=tk.NW, pady=2)
        self.body_text = scrolledtext.ScrolledText(self.manual_frame, height=4, width=60)
        self.body_text.grid(row=2, column=1, columnspan=2, sticky=tk.EW, padx=5)
        self.body_text.insert(tk.END, '{"username": "<<FUZZ_username>>", "email": "<<FUZZ_email>>"}')
        self.body_text.bind('<KeyRelease>', self.validate_fields)
        
        # Parameters
        self.params_label = ttk.Label(self.manual_frame, text="Parameters: *")
        self.params_label.grid(row=3, column=0, sticky=tk.W, pady=2)
        self.params_entry = ttk.Entry(self.manual_frame, width=40)
        self.params_entry.grid(row=3, column=1, sticky=tk.EW, padx=5)
        self.params_entry.insert(0, "username,email")
        self.params_entry.bind('<KeyRelease>', self.validate_fields)
        
        # Swagger Mode Frame
        self.swagger_frame = ttk.LabelFrame(main_frame, text="Swagger Configuration", padding=10)
        self.swagger_frame.pack(fill=tk.X, pady=5)
        
        # Swagger File
        self.swagger_label = ttk.Label(self.swagger_frame, text="Swagger File: *")
        self.swagger_label.grid(row=0, column=0, sticky=tk.W, pady=2)
        self.swagger_entry = ttk.Entry(self.swagger_frame, width=50)
        self.swagger_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        self.swagger_entry.bind('<KeyRelease>', self.validate_fields)
        ttk.Button(self.swagger_frame, text="Browse", 
                  command=self.browse_swagger_file).grid(row=0, column=2, padx=5)
        ttk.Button(self.swagger_frame, text="Load", 
                  command=self.load_swagger).grid(row=0, column=3, padx=5)
        
        # Base URL
        self.base_url_label = ttk.Label(self.swagger_frame, text="Base URL: *")
        self.base_url_label.grid(row=1, column=0, sticky=tk.W, pady=2)
        self.base_url_entry = ttk.Entry(self.swagger_frame, width=50)
        self.base_url_entry.grid(row=1, column=1, columnspan=2, sticky=tk.EW, padx=5)
        self.base_url_entry.insert(0, "http://localhost:5000")
        self.base_url_entry.bind('<KeyRelease>', self.validate_fields)
        
        # Endpoints Listbox
        self.endpoints_label = ttk.Label(self.swagger_frame, text="Endpoints: *")
        self.endpoints_label.grid(row=2, column=0, sticky=tk.NW, pady=2)
        self.endpoints_listbox = tk.Listbox(self.swagger_frame, height=5)
        self.endpoints_listbox.grid(row=2, column=1, columnspan=2, sticky=tk.EW, padx=5)
        self.endpoints_listbox.bind('<<ListboxSelect>>', self.on_endpoint_select)
        
        # Parameter Selection for swagger mode
        self.param_selection_label = ttk.Label(self.swagger_frame, text="Select Parameters to Fuzz: *")
        self.param_selection_label.grid(row=3, column=0, sticky=tk.NW, pady=2)
        
        # Frame for parameter checkboxes
        self.param_checkboxes_frame = ttk.Frame(self.swagger_frame)
        self.param_checkboxes_frame.grid(row=3, column=1, columnspan=2, sticky=tk.EW, padx=5)
        
        # Dictionary to store parameter checkbox variables
        self.param_vars = {}
        self.param_checkboxes = {}
        
        # Parameters display (read-only info)
        ttk.Label(self.swagger_frame, text="Available Parameters:").grid(row=4, column=0, sticky=tk.NW, pady=2)
        self.params_display = tk.Text(self.swagger_frame, height=4, width=50, state=tk.DISABLED)
        self.params_display.grid(row=4, column=1, columnspan=2, sticky=tk.EW, padx=5)
        
        # Common Options Frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding=10)
        options_frame.pack(fill=tk.X, pady=5)
        
        # Wordlist
        self.wordlist_label = ttk.Label(options_frame, text="Wordlist: *")
        self.wordlist_label.grid(row=0, column=0, sticky=tk.W, pady=2)
        self.wordlist_entry = ttk.Entry(options_frame, width=40)
        self.wordlist_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        self.wordlist_entry.bind('<KeyRelease>', self.validate_fields)
        ttk.Button(options_frame, text="Browse", 
                  command=self.browse_wordlist).grid(row=0, column=2, padx=5)
        
        # Delay
        ttk.Label(options_frame, text="Delay (seconds):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.delay_entry = ttk.Entry(options_frame, width=10)
        self.delay_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        self.delay_entry.insert(0, "0.1")
        
        # Checkboxes
        combo_check = ttk.Checkbutton(options_frame, text="Combo Mode", 
                                     variable=self.combo_var, command=self.validate_fields)
        combo_check.grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Save Requests", 
                       variable=self.save_request_var).grid(row=2, column=1, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Save Responses", 
                       variable=self.save_response_var).grid(row=2, column=2, sticky=tk.W, pady=2)
        
        # Advanced Tab
        advanced_frame = ttk.Frame(self.notebook)
        self.notebook.add(advanced_frame, text="Advanced")
        
        # Proxy
        proxy_frame = ttk.LabelFrame(advanced_frame, text="Proxy Settings", padding=10)
        proxy_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(proxy_frame, text="Proxy URL:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.proxy_entry = ttk.Entry(proxy_frame, width=40)
        self.proxy_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        self.proxy_entry.insert(0, "http://127.0.0.1:8080")
        
        # Headers
        headers_frame = ttk.LabelFrame(advanced_frame, text="Headers", padding=10)
        headers_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(headers_frame, text="Authorization Header:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.auth_entry = ttk.Entry(headers_frame, width=50)
        self.auth_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, padx=5)
        
        # Custom Headers with dynamic rows
        ttk.Label(headers_frame, text="Custom Headers:").grid(row=1, column=0, sticky=tk.NW, pady=2)
        
        # Frame to hold header rows
        self.headers_container = ttk.Frame(headers_frame)
        self.headers_container.grid(row=1, column=1, columnspan=2, sticky=tk.EW, padx=5)
        
        # List to store header entry widgets
        self.header_rows = []
        
        # Add button
        add_header_btn = ttk.Button(headers_frame, text="+ Add Header", 
                                   command=self.add_header_row)
        add_header_btn.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Add initial header row
        self.add_header_row("Content-Type", "application/json")
        
        # Filtering
        filter_frame = ttk.LabelFrame(advanced_frame, text="Response Filtering", padding=10)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Include Regex:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.regex_entry = ttk.Entry(filter_frame, width=40)
        self.regex_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        
        ttk.Label(filter_frame, text="Filter Status Codes:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.filter_status_entry = ttk.Entry(filter_frame, width=20)
        self.filter_status_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(filter_frame, text="Hide Status Codes:").grid(row=1, column=2, sticky=tk.W, pady=2)
        self.hide_status_entry = ttk.Entry(filter_frame, width=20)
        self.hide_status_entry.grid(row=1, column=3, sticky=tk.W, padx=5)
        
        # Report
        report_frame = ttk.LabelFrame(advanced_frame, text="Reporting", padding=10)
        report_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(report_frame, text="Report File:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.report_entry = ttk.Entry(report_frame, width=40)
        self.report_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        ttk.Button(report_frame, text="Browse", 
                  command=self.browse_report_file).grid(row=0, column=2, padx=5)
        
        # Output Tab
        self.output_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.output_frame, text="Output")
        
        # Output text area
        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Help Tab
        help_frame = ttk.Frame(self.notebook)
        self.notebook.add(help_frame, text="Help")
        
        # Create help content with scrollable text
        help_text = scrolledtext.ScrolledText(help_frame, wrap=tk.WORD, font=('Courier', 10))
        help_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        help_content = """🛡️ API Fuzzer Toolkit - Help & Examples

OVERVIEW:
A flexible and customizable tool to fuzz API endpoints based on Swagger/OpenAPI specifications. 
Supports advanced modes like combo fuzzing, HTML reporting, regex-based response filtering, and proxy integration.

═══════════════════════════════════════════════════════════════════════════════

🔧 FEATURES:
• Fuzz REST APIs using wordlists with <<FUZZ_param>> placeholders
• Swagger/OpenAPI support with interactive param selection
• Combo Mode (Cluster Bomb style multi-param fuzzing)
• HTML report generation (side-by-side request/response)
• Regex-based filtering on response body (case-insensitive)
• Proxy support for routing traffic through tools like Burp Suite / mitmproxy
• Auth header injection
• Optional request/response logging
• Baseline response comparison
• Static-only mode (no fuzzing) if no parameters selected

═══════════════════════════════════════════════════════════════════════════════

📄 ALL AVAILABLE ARGUMENTS:

CORE ARGUMENTS:
| Argument              | Description                                                   | Required |
|-----------------------|---------------------------------------------------------------|----------|
| --url                 | Target URL with <<FUZZ_param>> placeholders                 | Manual   |
| --method              | HTTP method (POST, PUT for manual mode)                     | Manual   |
| --body                | Request body with <<FUZZ_param>> placeholders               | Manual   |
| --params              | Comma-separated list of param names to fuzz                 | Manual   |
| --wordlist            | Path to wordlist file                                        | Always   |

SWAGGER/OPENAPI ARGUMENTS:
| Argument              | Description                                                   | Required |
|-----------------------|---------------------------------------------------------------|----------|
| --swagger-file        | Path to Swagger/OpenAPI JSON file                           | Swagger  |
| --base-url            | Base URL to prepend to endpoint path                        | Swagger  |
| --dry-run             | List endpoints/params/body and exit (no fuzzing, swagger only) | No    |

FUZZING CONTROL:
| Argument              | Description                                                   | Default  |
|-----------------------|---------------------------------------------------------------|----------|
| --combo               | Enable combo mode (multi-param Cluster Bomb style)         | False    |
| --delay               | Delay between requests (seconds)                            | 0.1      |

OUTPUT & LOGGING:
| Argument              | Description                                                   | Default  |
|-----------------------|---------------------------------------------------------------|----------|
| --save                | Save interesting responses to separate files                 | False    |
| --save-request        | Save all HTTP requests to results/requests.txt              | False    |
| --save-response       | Save all HTTP responses to results/responses.txt            | False    |
| --report              | Path to HTML report output (e.g. results/report.html)       | None     |

FILTERING:
| Argument              | Description                                                   | Default  |
|-----------------------|---------------------------------------------------------------|----------|
| --filter-status-codes | Comma-separated list of status codes to show (whitelist)    | None     |
| --hide-status-codes   | Comma-separated list of status codes to hide (blacklist)    | None     |
| --include-regex       | Regex pattern to match in response body before saving       | None     |

AUTHENTICATION & HEADERS:
| Argument              | Description                                                   | Example  |
|-----------------------|---------------------------------------------------------------|----------|
| --auth-header         | Authorization header value                                   | Bearer xyz |
| --headers             | Custom headers as JSON string                                | See below |

PROXY & NETWORK:
| Argument              | Description                                                   | Example  |
|-----------------------|---------------------------------------------------------------|----------|
| --proxy               | Proxy to route HTTP requests through                        | http://127.0.0.1:8080 |

VALIDATION RULES:
• Parameters MUST exist as <<FUZZ_param>> in URL or body
• Single parameter: Don't use --combo
• Multiple parameters: MUST use --combo
• Manual mode: Requires url, method, body, params, wordlist
• Swagger mode: Requires swagger-file, base-url, wordlist

═══════════════════════════════════════════════════════════════════════════════

🚀 CLI COMMAND EXAMPLES (for reference):

1. SWAGGER-BASED INTERACTIVE FLOW:
   python api_fuzzer.py --swagger-file openapi.json --base-url http://localhost:5000

2. SWAGGER DRY RUN - Shows parsed endpoints from API spec file:
   python api_fuzzer.py --swagger-file openapi.json --base-url http://localhost:5000 --dry-run

3. CLI MANUAL MODE:
   python api_fuzzer.py \\
     --url 'http://localhost:5000/api/users/userId' \\
     --method POST \\
     --body '{"username": "<<FUZZ_username>>", "email": "<<FUZZ_email>>"}' \\
     --params username,email \\
     --combo \\
     --wordlist list.txt \\
     --proxy http://127.0.0.1:8080 \\
     --report report.html

4. CLI MANUAL MODE WITH CUSTOM HEADERS:
   python api_fuzzer.py \\
     --url 'http://localhost:5000/api/users/userId' \\
     --method POST \\
     --body '{"username": "<<FUZZ_username>>", "email": "<<FUZZ_email>>"}' \\
     --params username,email \\
     --combo \\
     --wordlist list.txt \\
     --headers '{"Authorization": "Bearer abc123", "X-Env": "staging"}' \\
     --proxy http://127.0.0.1:8080 \\
     --report report.html

6. ADVANCED FILTERING EXAMPLE:
   python api_fuzzer.py \\
     --url 'http://api.example.com/search?q=<<FUZZ_query>>' \\
     --method GET \\
     --body '' \\
     --params query \\
     --wordlist search_terms.txt \\
     --filter-status-codes 200,201,403 \\
     --include-regex "error|admin|secret" \\
     --delay 0.5 \\
     --save-request \\
     --save-response

7. AUTHENTICATION TESTING:
   python api_fuzzer.py \\
     --url 'http://api.example.com/admin/<<FUZZ_action>>' \\
     --method POST \\
     --body '{"token": "<<FUZZ_token>>"}' \\
     --params action,token \\
     --combo \\
     --wordlist actions.txt \\
     --auth-header 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' \\
     --hide-status-codes 404,500

5. CLI SWAGGER MODE:
   python api_fuzzer.py \\
     --base-url http://localhost:5000 \\
     --swagger-file <API_SPEC_FILE> \\
     --report <REPORT_NAME> \\
     --proxy http://127.0.0.1:8080 \\
     --combo

═══════════════════════════════════════════════════════════════════════════════

📝 GUI USAGE GUIDE:

MANUAL MODE:
1. Select "Manual Mode" radio button
2. Enter target URL with <<FUZZ_param>> placeholders
   Example: http://localhost:5000/api/users/<<FUZZ_userId>>
3. Choose HTTP method (GET, POST, PUT, DELETE, PATCH)
4. Add request body with FUZZ placeholders (for POST/PUT requests)
   Example: {"username": "<<FUZZ_username>>", "email": "<<FUZZ_email>>"}
5. Specify parameters to fuzz (comma-separated)
   Example: userId,username,email
6. Select wordlist file
7. Configure options and click "Start Fuzzing"

SWAGGER MODE:
1. Select "Swagger Mode" radio button
2. Browse and select your Swagger/OpenAPI JSON file
3. Enter base URL (e.g., http://localhost:5000)
4. Click "Load" to parse endpoints
5. Select endpoint from the list
6. Configure options and click "Start Fuzzing"

═══════════════════════════════════════════════════════════════════════════════

🧪 TEST COMMANDS & EXAMPLES:

BASIC FUZZING TEST:
• URL: http://httpbin.org/post
• Method: POST
• Body: {"name": "<<FUZZ_name>>", "value": "<<FUZZ_value>>"}
• Params: name,value
• Wordlist: Create a simple wordlist with values like: admin, test, user, guest

PATH PARAMETER FUZZING:
• URL: http://jsonplaceholder.typicode.com/posts/<<FUZZ_id>>
• Method: GET
• Params: id
• Wordlist: Numbers 1-100

QUERY PARAMETER FUZZING:
• URL: http://httpbin.org/get?search=<<FUZZ_search>>&limit=<<FUZZ_limit>>
• Method: GET
• Params: search,limit
• Enable Combo Mode for multiple parameters

AUTHENTICATION TESTING:
• Use Authorization header: Bearer <<token>>
• Or custom headers: {"X-API-Key": "test123", "Authorization": "Bearer xyz"}

PROXY TESTING:
• Set proxy to: http://127.0.0.1:8080 (for Burp Suite)
• Or: http://127.0.0.1:8081 (for mitmproxy)

═══════════════════════════════════════════════════════════════════════════════

📋 DETAILED ARGUMENT REFERENCE:

--url: Target URL with FUZZ placeholders
  Example: 'http://api.com/users/<<FUZZ_id>>/posts/<<FUZZ_postid>>'
  Note: Must contain at least one <<FUZZ_param>> placeholder

--method: HTTP method for requests
  Options: GET, POST, PUT, DELETE, PATCH (CLI supports POST, PUT only)
  Default: POST

--body: Request body with FUZZ placeholders
  Example: '{"user": "<<FUZZ_user>>", "pass": "<<FUZZ_pass>>"}'
  Note: Can be empty string for GET requests

--params: Parameters to fuzz (comma-separated)
  Example: 'username,password,role'
  Note: Each param must have corresponding <<FUZZ_param>> in URL/body

--wordlist: Path to wordlist file
  Format: One value per line
  Example: /path/to/wordlist.txt
  Content: admin\ntest\nguest\n...

--combo: Enable Cluster Bomb fuzzing
  Usage: Required for multiple parameters
  Behavior: Tests all combinations of parameter values

--delay: Seconds between requests
  Range: 0.0 to any positive float
  Purpose: Avoid rate limiting, be respectful to servers
  Recommended: 0.1-1.0 for production APIs

--save-request: Save all requests to file
  Output: results/requests.txt
  Format: Full HTTP request including headers

--save-response: Save all responses to file
  Output: results/responses.txt  
  Format: Full HTTP response including headers

--filter-status-codes: Whitelist status codes
  Example: '200,201,403'
  Behavior: Only show responses with these codes

--hide-status-codes: Blacklist status codes
  Example: '404,500'
  Behavior: Hide responses with these codes

--include-regex: Filter responses by content
  Example: 'admin|error|secret'
  Behavior: Only show responses matching regex pattern
  Options: Case-insensitive matching

--auth-header: Authorization header
  Example: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
  Example: 'Basic YWRtaW46cGFzc3dvcmQ='
  Usage: Added to all requests

--headers: Custom headers (JSON format)
  Example: '{"X-API-Key": "abc123", "Content-Type": "application/xml"}'
  Usage: Merged with default headers

--proxy: HTTP/HTTPS proxy server
  Example: 'http://127.0.0.1:8080' (Burp Suite)
  Example: 'http://127.0.0.1:8081' (mitmproxy)
  Usage: Route all traffic through proxy

--report: HTML report output path
  Example: 'results/fuzzing_report.html'
  Content: Side-by-side request/response view
  Features: Color-coded status, searchable, timestamps

--swagger-file: OpenAPI/Swagger specification
  Formats: JSON (.json), YAML (.yaml/.yml)
  Example: 'openapi.json'
  Usage: Parses endpoints and parameters automatically

--base-url: Base URL for Swagger endpoints
  Example: 'http://localhost:5000'
  Usage: Prepended to all endpoint paths from spec

--dry-run: Preview mode for Swagger files only (no actual requests)
  Behavior: Shows parsed endpoints and exits (Swagger mode only)
  Usage: Validate Swagger parsing before fuzzing
  Note: Not available in manual mode

═══════════════════════════════════════════════════════════════════════════════

⚙️ ADVANCED OPTIONS:

COMBO MODE:
• Enable for multi-parameter fuzzing (Cluster Bomb style)
• Tests all combinations of parameter values
• Use only when fuzzing multiple parameters

DELAY:
• Add delay between requests to avoid rate limiting
• Recommended: 0.1-1.0 seconds for production APIs

FILTERING:
• Include Regex: Only show responses matching pattern
• Filter Status Codes: Show only specific status codes (200,201,404)
• Hide Status Codes: Hide specific status codes (404,500)

REPORTING:
• HTML reports show side-by-side request/response
• Automatically saves to specified file
• Color-coded status codes and response lengths

═══════════════════════════════════════════════════════════════════════════════

🎯 COMMON USE CASES:

1. API PARAMETER DISCOVERY:
   • Use common parameter wordlists
   • Enable response filtering to find interesting responses

2. AUTHENTICATION BYPASS:
   • Fuzz authentication parameters
   • Test different user roles and permissions

3. INPUT VALIDATION TESTING:
   • Test SQL injection, XSS payloads
   • Use specialized wordlists for security testing

4. API ENUMERATION:
   • Discover hidden endpoints
   • Test different HTTP methods

5. RATE LIMIT TESTING:
   • Adjust delay settings
   • Monitor response codes for rate limiting

═══════════════════════════════════════════════════════════════════════════════

⚠️ IMPORTANT NOTES:

• Always test against your own applications or with proper authorization
• Start with small wordlists to avoid overwhelming target servers
• Use appropriate delays to be respectful to target systems
• Monitor proxy tools (Burp Suite, mitmproxy) for detailed request analysis
• Review generated HTML reports for comprehensive analysis
• Backup your configurations before testing

═══════════════════════════════════════════════════════════════════════════════

🔗 SAMPLE WORDLISTS:

Create text files with one value per line:

common_params.txt:
admin
user
test
guest
api
key
token
id

numbers.txt:
1
2
3
...
100

sql_injection.txt:
' OR 1=1--
admin'--
' UNION SELECT NULL--

═══════════════════════════════════════════════════════════════════════════════

For more information and updates, visit the project repository.
"""
        
        help_text.insert(tk.END, help_content)
        help_text.config(state=tk.DISABLED)  # Make read-only
        
        # Status Frame
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        # Status Label
        self.status_label = ttk.Label(status_frame, text="", foreground="red")
        self.status_label.pack(side=tk.LEFT)
        
        # Validation Status
        self.validation_label = ttk.Label(status_frame, text="Ready", foreground="green")
        self.validation_label.pack(side=tk.RIGHT)
        
        # Buttons Frame
        buttons_frame = ttk.Frame(self.root)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_button = ttk.Button(buttons_frame, text="Start Fuzzing", 
                                      command=self.start_fuzzing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop Fuzzing", 
                                     command=self.stop_fuzzing, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Clear Output", 
                  command=self.clear_output).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Exit", 
                  command=self.root.quit).pack(side=tk.RIGHT, padx=5)
        
        # Configure grid weights for responsive design
        for i in range(3):
            self.manual_frame.grid_columnconfigure(i, weight=1)
            self.swagger_frame.grid_columnconfigure(i, weight=1)
        
    def toggle_mode(self):
        if self.mode_var.get() == "manual":
            self.manual_frame.pack(fill=tk.X, pady=5)
            self.swagger_frame.pack_forget()
        else:
            self.manual_frame.pack_forget()
            self.swagger_frame.pack(fill=tk.X, pady=5)
        
        # Clear status and revalidate when mode changes
        self.status_label.config(text="")
        self.selected_endpoint = None
        
        # Clear parameter selections
        if hasattr(self, 'param_vars'):
            self.param_vars.clear()
        if hasattr(self, 'param_checkboxes'):
            self.param_checkboxes.clear()
        if hasattr(self, 'param_checkboxes_frame'):
            for widget in self.param_checkboxes_frame.winfo_children():
                widget.destroy()
        
        self.validate_fields()
    
    def browse_swagger_file(self):
        filename = filedialog.askopenfilename(
            title="Select Swagger File",
            filetypes=[("JSON files", "*.json"), ("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        if filename:
            # Clear all swagger-related fields when browsing for new file
            self.clear_swagger_fields()
            
            self.swagger_entry.delete(0, tk.END)
            self.swagger_entry.insert(0, filename)
            self.validate_fields()
    
    def clear_swagger_fields(self):
        """Clear all swagger-related UI fields"""
        # Clear endpoints listbox
        self.endpoints_listbox.delete(0, tk.END)
        
        # Clear parameter checkboxes
        for widget in self.param_checkboxes_frame.winfo_children():
            widget.destroy()
        self.param_vars.clear()
        self.param_checkboxes.clear()
        
        # Clear parameters display
        self.params_display.config(state=tk.NORMAL)
        self.params_display.delete(1.0, tk.END)
        self.params_display.config(state=tk.DISABLED)
        
        # Reset selected endpoint
        self.selected_endpoint = None
        
        # Clear endpoints data
        self.swagger_endpoints = []
    
    def browse_wordlist(self):
        filename = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, filename)
            self.validate_fields()
    
    def browse_report_file(self):
        filename = filedialog.asksaveasfilename(
            title="Save Report As",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        if filename:
            self.report_entry.delete(0, tk.END)
            self.report_entry.insert(0, filename)
    
    def load_swagger(self):
        swagger_file = self.swagger_entry.get().strip()
        if not swagger_file:
            messagebox.showerror("Error", "Please select a Swagger file")
            return
        
        try:
            self.swagger_endpoints = parse_swagger(swagger_file)
            self.endpoints_listbox.delete(0, tk.END)
            
            for i, endpoint in enumerate(self.swagger_endpoints):
                self.endpoints_listbox.insert(i, f"{endpoint['method']} {endpoint['url']}")
            
            self.output_text.insert(tk.END, f"Loaded {len(self.swagger_endpoints)} endpoints from {swagger_file}\n")
            self.output_text.see(tk.END)
            self.validate_fields()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load Swagger file: {str(e)}")
    
    def on_endpoint_select(self, event):
        selection = self.endpoints_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_endpoint = self.swagger_endpoints[index]
            
            # Clear previous parameter checkboxes
            for widget in self.param_checkboxes_frame.winfo_children():
                widget.destroy()
            self.param_vars.clear()
            self.param_checkboxes.clear()
            
            # Create parameter checkboxes
            if self.selected_endpoint and self.selected_endpoint.get("params"):
                row = 0
                col = 0
                for param in self.selected_endpoint["params"]:
                    param_name = param['name']
                    var = tk.BooleanVar()
                    self.param_vars[param_name] = var
                    
                    checkbox_text = f"{param_name} ({param['location']})"
                    if param.get("enum"):
                        checkbox_text += f" [enum]"
                    
                    checkbox = ttk.Checkbutton(
                        self.param_checkboxes_frame, 
                        text=checkbox_text, 
                        variable=var,
                        command=self.validate_fields
                    )
                    checkbox.grid(row=row, column=col, sticky=tk.W, padx=5, pady=2)
                    self.param_checkboxes[param_name] = checkbox
                    
                    # Arrange checkboxes in columns
                    col += 1
                    if col > 2:  # 3 columns max
                        col = 0
                        row += 1
            
            # Display parameters info for selected endpoint
            self.params_display.config(state=tk.NORMAL)
            self.params_display.delete(1.0, tk.END)
            
            if self.selected_endpoint and self.selected_endpoint.get("params"):
                params_text = "Parameter Details:\n"
                for param in self.selected_endpoint["params"]:
                    param_info = f"• {param['name']} ({param['location']})"
                    if param.get("enum"):
                        param_info += f" [enum: {', '.join(param['enum'])}]"
                    params_text += param_info + "\n"
                
                params_text += f"\nBody template:\n{self.selected_endpoint.get('body_template', 'N/A')}"
            else:
                params_text = "No parameters available for this endpoint."
            
            self.params_display.insert(1.0, params_text)
            self.params_display.config(state=tk.DISABLED)
            
            self.validate_fields()
    
    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
    
    def add_header_row(self, key="", value=""):
        """Add a new header key-value row"""
        row_frame = ttk.Frame(self.headers_container)
        row_frame.pack(fill=tk.X, pady=2)
        
        # Header key entry
        key_entry = ttk.Entry(row_frame, width=20)
        key_entry.pack(side=tk.LEFT, padx=(0, 5))
        key_entry.insert(0, key)
        
        # Colon label
        ttk.Label(row_frame, text=":").pack(side=tk.LEFT, padx=2)
        
        # Header value entry
        value_entry = ttk.Entry(row_frame, width=30)
        value_entry.pack(side=tk.LEFT, padx=(5, 10))
        value_entry.insert(0, value)
        
        # Delete button
        delete_btn = ttk.Button(row_frame, text="×", width=3,
                               command=lambda: self.remove_header_row(row_frame))
        delete_btn.pack(side=tk.LEFT)
        
        # Store references
        header_row = {
            'frame': row_frame,
            'key_entry': key_entry,
            'value_entry': value_entry,
            'delete_btn': delete_btn
        }
        self.header_rows.append(header_row)
    
    def remove_header_row(self, row_frame):
        """Remove a header row"""
        # Find and remove from list
        self.header_rows = [row for row in self.header_rows if row['frame'] != row_frame]
        # Destroy the frame
        row_frame.destroy()
    
    def get_custom_headers(self):
        """Get all custom headers as a dictionary"""
        headers = {}
        for row in self.header_rows:
            key = row['key_entry'].get().strip()
            value = row['value_entry'].get().strip()
            if key and value:  # Only include non-empty headers
                headers[key] = value
        return headers
    
    def validate_fields(self, event=None):
        """Validate required fields and update UI accordingly"""
        missing_fields = []
        
        # Reset all label colors to default
        if hasattr(self, 'url_label'):
            self.url_label.config(foreground="black")
        if hasattr(self, 'method_label'):
            self.method_label.config(foreground="black")
        if hasattr(self, 'body_label'):
            self.body_label.config(foreground="black")
        if hasattr(self, 'params_label'):
            self.params_label.config(foreground="black")
        if hasattr(self, 'swagger_label'):
            self.swagger_label.config(foreground="black")
        if hasattr(self, 'base_url_label'):
            self.base_url_label.config(foreground="black")
        if hasattr(self, 'endpoints_label'):
            self.endpoints_label.config(foreground="black")
        if hasattr(self, 'wordlist_label'):
            self.wordlist_label.config(foreground="black")
        if hasattr(self, 'param_selection_label'):
            self.param_selection_label.config(foreground="black")
        
        if self.mode_var.get() == "manual":
            # Manual mode validation - all 5 required fields from api_fuzzer.py line 268
            if not self.url_entry.get().strip():
                missing_fields.append("URL")
                self.url_label.config(foreground="red")
            
            if not self.method_var.get():
                missing_fields.append("Method")
                self.method_label.config(foreground="red")
                
            if not self.body_text.get(1.0, tk.END).strip():
                missing_fields.append("Request Body")
                self.body_label.config(foreground="red")
                
            if not self.params_entry.get().strip():
                missing_fields.append("Parameters")
                self.params_label.config(foreground="red")
                
            # Additional manual mode validation rules from api_fuzzer.py
            params_text = self.params_entry.get().strip()
            if params_text and not missing_fields:  # Only check if basic fields are filled
                params = [p.strip() for p in params_text.split(",") if p.strip()]
                url_text = self.url_entry.get()
                body_text = self.body_text.get(1.0, tk.END)
                
                # Check if parameters are used in URL or body
                unused_params = []
                for param in params:
                    if f"<<FUZZ_{param}>>" not in url_text and f"<<FUZZ_{param}>>" not in body_text:
                        unused_params.append(param)
                
                if unused_params:
                    self.status_label.config(text=f"Parameters not used in URL/body: {', '.join(unused_params)}", 
                                           foreground="red")
                    missing_fields.append("Fix parameter usage")
                
                # Check combo mode validation rules
                elif len(params) == 1 and self.combo_var.get():
                    self.status_label.config(text="Only use --combo for fuzzing multiple parameters", 
                                           foreground="orange")
                    missing_fields.append("Disable combo mode")
                
                elif len(params) > 1 and not self.combo_var.get():
                    self.status_label.config(text="Multiple parameters detected. Enable combo mode for multi-parameter fuzzing", 
                                           foreground="orange")
                    missing_fields.append("Enable combo mode")
                
                else:
                    self.status_label.config(text="")
        else:
            # Swagger mode validation
            if not self.swagger_entry.get().strip():
                missing_fields.append("Swagger File")
                self.swagger_label.config(foreground="red")
                
            if not self.base_url_entry.get().strip():
                missing_fields.append("Base URL")
                self.base_url_label.config(foreground="red")
                
            if not self.selected_endpoint:
                missing_fields.append("Endpoint Selection")
                self.endpoints_label.config(foreground="red")
            
            # Check if parameters are selected for fuzzing
            if self.selected_endpoint:
                selected_params = [name for name, var in self.param_vars.items() if var.get()]
                if not selected_params:
                    missing_fields.append("Parameter Selection")
                    self.param_selection_label.config(foreground="red")
                else:
                    # Check combo mode validation for swagger mode
                    if len(selected_params) == 1 and self.combo_var.get():
                        self.status_label.config(text="Only use combo mode for fuzzing multiple parameters", 
                                               foreground="orange")
                        missing_fields.append("Disable combo mode")
                    elif len(selected_params) > 1 and not self.combo_var.get():
                        self.status_label.config(text="Multiple parameters selected. Enable combo mode for multi-parameter fuzzing", 
                                               foreground="orange")
                        missing_fields.append("Enable combo mode")
                    elif not missing_fields:
                        self.status_label.config(text="")
        
        # Common validation
        if not self.wordlist_entry.get().strip():
            missing_fields.append("Wordlist")
            self.wordlist_label.config(foreground="red")
        
        # Update validation status
        if missing_fields:
            self.validation_label.config(text=f"Missing: {', '.join(missing_fields)}", 
                                       foreground="red")
            self.start_button.config(state="disabled")
        else:
            if not self.status_label.cget("text"):  # Only update if no other status message
                self.validation_label.config(text="All required fields complete", 
                                           foreground="green")
            else:
                self.validation_label.config(text="Check parameter usage", 
                                           foreground="orange")
            self.start_button.config(state="normal")
    
    def check_parameter_usage(self):
        """Check if parameters are properly used in URL or body"""
        if self.mode_var.get() != "manual":
            return True
            
        params_text = self.params_entry.get().strip()
        if not params_text:
            return True
            
        params = [p.strip() for p in params_text.split(",") if p.strip()]
        url_text = self.url_entry.get()
        body_text = self.body_text.get(1.0, tk.END)
        
        for param in params:
            if f"<<FUZZ_{param}>>" not in url_text and f"<<FUZZ_{param}>>" not in body_text:
                return False
        return True
    
    def redirect_output(self):
        class OutputRedirector:
            def __init__(self, text_widget):
                self.text_widget = text_widget
                
            def write(self, text):
                self.text_widget.insert(tk.END, text)
                self.text_widget.see(tk.END)
                self.text_widget.update()
                
            def flush(self):
                pass
        
        sys.stdout = OutputRedirector(self.output_text)
        sys.stderr = OutputRedirector(self.output_text)
    
    def restore_output(self):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
    
    def validate_inputs(self):
        if self.mode_var.get() == "manual":
            if not self.url_entry.get().strip():
                messagebox.showerror("Error", "URL is required")
                return False
            if not self.params_entry.get().strip():
                messagebox.showerror("Error", "Parameters are required")
                return False
        else:
            if not self.swagger_entry.get().strip():
                messagebox.showerror("Error", "Swagger file is required")
                return False
            if not self.base_url_entry.get().strip():
                messagebox.showerror("Error", "Base URL is required")
                return False
            if not self.selected_endpoint:
                messagebox.showerror("Error", "Please select an endpoint")
                return False
        
        if not self.wordlist_entry.get().strip():
            messagebox.showerror("Error", "Wordlist is required")
            return False
        
        return True
    
    def create_args_object(self):
        class Args:
            pass
        
        args = Args()
        
        if self.mode_var.get() == "manual":
            args.url = self.url_entry.get().strip()
            args.method = self.method_var.get()
            args.body = self.body_text.get(1.0, tk.END).strip()
            args.params = [p.strip() for p in self.params_entry.get().split(",") if p.strip()]
        else:
            # Swagger mode - use selected parameters only
            endpoint = self.selected_endpoint
            selected_params = [name for name, var in self.param_vars.items() if var.get()]
            
            # Separate parameters by location
            path_params = [p["name"] for p in endpoint.get("params", []) if p["location"] == "path"]
            query_params = [p["name"] for p in endpoint.get("params", []) if p["location"] == "query"]
            
            # Build URL with proper FUZZ placeholder replacement
            full_url = self.base_url_entry.get().rstrip("/") + endpoint["url"]
            
            # Replace path parameters with FUZZ placeholders if selected
            for param in path_params:
                if param in selected_params:
                    full_url = full_url.replace(f"{{{param}}}", f"<<FUZZ_{param}>>")
                else:
                    # For non-selected path params, we need a default value
                    # This is a limitation - path params typically need values
                    full_url = full_url.replace(f"{{{param}}}", f"default_{param}")
            
            # Add query parameters with FUZZ placeholders if selected
            selected_query_params = [p for p in selected_params if p in query_params]
            if selected_query_params:
                query_string = "&".join([f"{param}=<<FUZZ_{param}>>" for param in selected_query_params])
                full_url = full_url + "?" + query_string
            
            args.url = full_url
            args.method = endpoint["method"]
            args.body = endpoint.get("body_template", "")
            args.params = selected_params
        
        args.wordlist = self.wordlist_entry.get().strip()
        args.delay = float(self.delay_entry.get() or "0.1")
        args.combo = self.combo_var.get()
        args.save_request = self.save_request_var.get()
        args.save_response = self.save_response_var.get()
        args.save = False
        
        # Advanced options
        args.proxy = self.proxy_entry.get().strip() or None
        args.auth_header = self.auth_entry.get().strip() or None
        
        # Get custom headers from dynamic interface
        custom_headers = self.get_custom_headers()
        args.headers = json.dumps(custom_headers) if custom_headers else ""
        
        args.include_regex = self.regex_entry.get().strip() or None
        args.filter_status_codes = self.filter_status_entry.get().strip()
        args.hide_status_codes = self.hide_status_entry.get().strip()
        args.report = self.report_entry.get().strip() or None
        
        return args
    
    def start_fuzzing(self):
        if not self.validate_inputs():
            return
        
        args = self.create_args_object()
        
        # Switch to Output tab automatically
        self.notebook.select(self.output_frame)
        
        # Reset and set up stop event
        self.stop_event.clear()
        
        # Update UI state
        self.fuzzing_active = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        
        self.output_text.insert(tk.END, "Starting API Fuzzer...\n")
        self.output_text.see(tk.END)
        
        def run_fuzzing():
            try:
                self.redirect_output()
                # Run fuzzer with stop event
                self.run_interruptible_fuzzer(args, args.params)
                if self.fuzzing_active and not self.stop_event.is_set():
                    self.output_text.insert(tk.END, "\nFuzzing completed!\n")
                elif self.stop_event.is_set():
                    self.output_text.insert(tk.END, "\nFuzzing stopped by user.\n")
            except Exception as e:
                if self.fuzzing_active:
                    self.output_text.insert(tk.END, f"\nError: {str(e)}\n")
            finally:
                self.restore_output()
                # Reset UI state
                self.fuzzing_active = False
                self.start_button.config(state="normal")
                self.stop_button.config(state="disabled")
                self.fuzzing_thread = None
        
        # Run fuzzing in a separate thread to prevent GUI freezing
        self.fuzzing_thread = threading.Thread(target=run_fuzzing, daemon=True)
        self.fuzzing_thread.start()
    
    def stop_fuzzing(self):
        """Stop the currently running fuzzing operation"""
        if self.fuzzing_active and self.fuzzing_thread:
            self.fuzzing_active = False
            self.stop_event.set()  # Signal the fuzzer to stop
            self.output_text.insert(tk.END, "\n[STOPPING] Stopping fuzzing...\n")
            self.output_text.see(tk.END)
            
            # Reset UI state immediately for responsiveness
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
    
    def run_interruptible_fuzzer(self, args, params):
        """Run fuzzer with interruption support - custom implementation"""
        import itertools
        import requests
        import time
        import re
        from request_utils import prepare_and_send_request
        from baseline_analyzer import is_interesting
        from report_generator import generate_html_report
        
        try:
            # Read wordlist
            if not os.path.exists(args.wordlist):
                raise FileNotFoundError(f"Wordlist not found: {args.wordlist}")
                
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                payloads = [line.strip() for line in f if line.strip()]
            
            if not payloads:
                print("[red][-] No payloads found in wordlist[/red]")
                return
                
            # Setup headers
            headers = {"Content-Type": "application/json"}
            if args.auth_header:
                headers["Authorization"] = args.auth_header
            if args.headers:
                try:
                    custom_headers = json.loads(args.headers)
                    headers.update(custom_headers)
                except json.JSONDecodeError:
                    pass
            
            # Setup proxies
            proxies = None
            if args.proxy:
                proxies = {"http": args.proxy, "https": args.proxy}
            
            # Setup regex filter
            include_regex = args.include_regex if hasattr(args, 'include_regex') else None
            
            responses = []
            
            if args.combo and len(params) > 1:
                # Combo mode fuzzing
                param_payload_lists = {param: payloads for param in params}
                all_combos = list(itertools.product(*param_payload_lists.values()))
                param_order = list(param_payload_lists.keys())
                total_combos = len(all_combos)
                
                for current_combo_num, combo in enumerate(all_combos, 1):
                    # Check for stop signal
                    if self.stop_event.is_set():
                        print(f"\n[STOPPING] Fuzzing interrupted at combo {current_combo_num}/{total_combos}")
                        break
                    
                    # Build fuzzed body and URL
                    fuzzed_body = args.body
                    fuzzed_url = args.url
                    
                    for i, param in enumerate(param_order):
                        placeholder = f"<<FUZZ_{param}>>"
                        fuzzed_body = fuzzed_body.replace(placeholder, combo[i])
                        fuzzed_url = fuzzed_url.replace(placeholder, combo[i])
                    
                    # Status update
                    status_line = f"[*] Combo {current_combo_num}/{total_combos} | Param Values: {dict(zip(param_order, combo))}"
                    print(f"\r{status_line}", end="", flush=True)
                    
                    # Send request
                    try:
                        prepared, response = prepare_and_send_request(
                            args.method, fuzzed_url, data=fuzzed_body, 
                            headers=headers, proxies=proxies
                        )
                        
                        # Apply regex filter if specified
                        if include_regex and not re.search(include_regex, response.text, re.IGNORECASE):
                            continue
                            
                        responses.append((prepared, response))
                        
                        # Show response info
                        print(f"\n[{response.status_code}] Length: {len(response.text)}")
                        
                    except Exception as e:
                        print(f"\n[red][-] Error sending request: {e}[/red]")
                    
                    # Delay between requests
                    if args.delay > 0:
                        time.sleep(args.delay)
            else:
                # Single parameter fuzzing
                param = params[0]
                total_payloads = len(payloads)
                
                for current_num, payload in enumerate(payloads, 1):
                    # Check for stop signal
                    if self.stop_event.is_set():
                        print(f"\n[STOPPING] Fuzzing interrupted at payload {current_num}/{total_payloads}")
                        break
                    
                    # Build fuzzed body and URL
                    placeholder = f"<<FUZZ_{param}>>"
                    fuzzed_body = args.body.replace(placeholder, payload)
                    fuzzed_url = args.url.replace(placeholder, payload)
                    
                    # Status update
                    print(f"\r[*] {current_num}/{total_payloads} | Payload: {payload[:50]}", end="", flush=True)
                    
                    # Send request
                    try:
                        prepared, response = prepare_and_send_request(
                            args.method, fuzzed_url, data=fuzzed_body, 
                            headers=headers, proxies=proxies
                        )
                        
                        # Apply regex filter if specified
                        if include_regex and not re.search(include_regex, response.text, re.IGNORECASE):
                            continue
                            
                        responses.append((prepared, response))
                        
                        # Show response info
                        print(f"\n[{response.status_code}] Length: {len(response.text)}")
                        
                    except Exception as e:
                        print(f"\n[red][-] Error sending request: {e}[/red]")
                    
                    # Delay between requests
                    if args.delay > 0:
                        time.sleep(args.delay)
            
            # Generate report if specified
            if args.report and responses:
                generate_html_report(responses, args.report)
                print(f"\n[green][+] HTML report generated: {args.report}[/green]")
            
            if not self.stop_event.is_set():
                print(f"\n[green][+] Fuzzing completed! Total responses: {len(responses)}[/green]")
                
        except Exception as e:
            raise e

def main():
    root = tk.Tk()
    app = APIFuzzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()