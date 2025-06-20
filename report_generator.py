import os
from datetime import datetime

def generate_html_report(findings, output_path):
    html = f"""
    <html>
    <head>
        <title>API Fuzzing Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f8f8f8;
                padding: 20px;
            }}
            h1 {{
                color: #333;
            }}
            .finding {{
                background-color: #fff;
                padding: 15px;
                margin-bottom: 20px;
                border-left: 5px solid #007acc;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            .req-resp {{
                display: flex;
                gap: 20px;
                margin-top: 10px;
            }}
            .column {{
                flex: 1;
                background-color: #f0f0f0;
                padding: 10px;
                border-radius: 5px;
                font-family: monospace;
                font-size: 13px;
                overflow-x: auto;
                max-height: 500px;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            code {{
                background-color: #eee;
                padding: 2px 4px;
                border-radius: 3px;
            }}
        </style>
    </head>
    <body>
        <h1>API Fuzzing Report</h1>
        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    """

    for i, item in enumerate(findings, 1):
        html += f"""
        <div class='finding'>
            <h2>Packet {i}</h2>
            <p><strong>URL:</strong> {item['url']}</p>
            <p><strong>Method:</strong> {item['method']}</p>
            <p><strong>Param:</strong> {item['param']}</p>
            <p><strong>Payload:</strong> <code>{item['payload']}</code></p>
            <p><strong>Status:</strong> {item['status']} {item['reason']}</p>
            <p><strong>Length:</strong> {item['length']}</p>
            <div class="req-resp">
                <div class="column">
                    <h3>Request</h3>
                    <pre>{item.get('method', '')} {item.get('url', '')}</pre>
                    <p><strong>Headers:</strong></p>
                    <pre>{item.get('request_headers', '')}</pre>
                    <p><strong>Body:</strong></p>
                    <pre>{item.get('request_body', '')}</pre>
                </div>
                <div class="column">
                    <h3>Response</h3>
                    <p><strong>Headers:</strong></p>
                    <pre>{item.get('response_headers', '')}</pre>
                    <p><strong>Body:</strong></p>
                    <pre>{item.get('response_body', '')}</pre>
                </div>
            </div>
        </div>
        """

    html += """
    </body>
    </html>
    """

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
