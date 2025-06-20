import requests
import time
import os
import sys
import itertools
from baseline_analyzer import is_interesting
from rich import print
from report_generator import generate_html_report
from request_utils import prepare_and_send_request
import re
#from file_fuzzer import run_file_fuzzer


def run_fuzzer(args, param_list):

    #Ensures param validation logic like len(args.params) behaves correctly
    if isinstance(args.params, str):
        args.params = [p.strip() for p in args.params.split(",") if p.strip()]


    #Combo mode usage sanity checks
    if args.combo and len(args.params) == 1:
        print("[yellow][!] Only one parameter specified. Remove --combo for single-param fuzzing.[/yellow]")
        sys.exit(1)

    if not args.combo and len(args.params) > 1:
        print("[yellow][!] Multiple parameters specified. Use --combo for multi-param fuzzing.[/yellow]")
        sys.exit(1)



    #Regexing
    include_regex = args.include_regex if hasattr(args, "include_regex") else None

    #Declare findings for report
    findings = []


    # Load wordlist
    with open(args.wordlist, "r") as f:
        payloads = [line.strip() for line in f if line.strip()]

    headers = {"Content-Type": "application/json"}

    if hasattr(args, "auth_header") and args.auth_header:
        headers["Authorization"] = args.auth_header
    
    # Add headers from Swagger-required header prompt
    if hasattr(args, "headers") and isinstance(args.headers, dict):
        headers.update(args.headers)


    # Setup proxy if provided
    proxies = None
    if hasattr(args, "proxy") and args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
    }
    print(f"[cyan][*] Using proxy: {args.proxy}[/cyan]")

    # Send baseline request
    print("[cyan][*] Sending baseline request...[/cyan]")
    prepared,baseline_response = prepare_and_send_request(args.method, args.url, data=args.body, headers=headers,proxies=proxies)
    baseline_status = baseline_response.status_code
    baseline_text = baseline_response.text

    print(f"[cyan][*] Baseline status: {baseline_status}, length: {len(baseline_text)}[/cyan]\n")

    # Prepare results dir
    result_dir = "results"
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)

    # Open request/response logs if needed
    requests_log = None
    responses_log = None
    if args.save_request:
        requests_log = open(os.path.join(result_dir, "requests.txt"), "a")
    if args.save_response:
        responses_log = open(os.path.join(result_dir, "responses.txt"), "a")

    request_counter = 1  # For request/response numbering

    # Parse status code filters
    show_status_codes = set()
    hide_status_codes = set()

    if args.filter_status_codes:
        show_status_codes = set(int(x.strip()) for x in args.filter_status_codes.split(",") if x.strip())

    if args.hide_status_codes:
        hide_status_codes = set(int(x.strip()) for x in args.hide_status_codes.split(",") if x.strip())
    # Detect combo mode
    combo_mode = hasattr(args, "combo") and args.combo

    if combo_mode:
        # === COMBO MODE ===

        print(f"[cyan][*] Running in COMBO mode (Cluster Bomb style)[/cyan]\n")

        # Build param → payload list
        param_payload_lists = {param: payloads for param in param_list}

        # Build all combinations
        all_combos = list(itertools.product(*param_payload_lists.values()))
        param_order = list(param_payload_lists.keys())

        total_combos = len(all_combos)
        current_combo_num = 1

        for combo in all_combos:
            # Build fuzzed body
            fuzzed_body = args.body
            for i, param in enumerate(param_order):
                placeholder = f"<<FUZZ_{param}>>"
                fuzzed_body = fuzzed_body.replace(placeholder, combo[i])

            # Build fuzzed URL
            fuzzed_url = args.url
            for i, param in enumerate(param_order):
                fuzzed_url = fuzzed_url.replace(f"<<FUZZ_{param}>>", combo[i])

            # Live status line
            status_line = f"[*] Combo {current_combo_num}/{total_combos} | Param Values: {dict(zip(param_order, combo))}"
            sys.stdout.write(f"\r{status_line.ljust(120)}")
            sys.stdout.flush()

            # Send request
            try:
                prepared,response = prepare_and_send_request(args.method, fuzzed_url, data=fuzzed_body, headers=headers, proxies=proxies)
                if include_regex:
                          if not re.search(include_regex, response.text, re.IGNORECASE):
                              current_request_num += 1
                              continue
            except Exception as e:
                sys.stdout.write(f"\r[red][-] Error sending request Combo {current_combo_num}/{total_combos}: {e}[/red]\n")
                sys.stdout.flush()
                current_combo_num += 1
                continue

            resp_status = response.status_code

            # Skip unwanted responses
            if show_status_codes and resp_status not in show_status_codes:
                current_combo_num += 1
                continue

            if hide_status_codes and resp_status in hide_status_codes:
                current_combo_num += 1
                continue

            # Save request/response → only matching responses reach this point!
            if requests_log:
                requests_log.write(f"==== REQUEST {request_counter} ====\n")
                requests_log.write(f"{args.method} {fuzzed_url} HTTP/1.1\n")
                for header, value in headers.items():
                    requests_log.write(f"{header}: {value}\n")
                requests_log.write("\n")
                requests_log.write(fuzzed_body + "\n\n")

            if responses_log:
                responses_log.write(f"==== RESPONSE {request_counter} ====\n")
                responses_log.write(f"HTTP/1.1 {response.status_code} {response.reason}\n")
                for header, value in response.headers.items():
                    responses_log.write(f"{header}: {value}\n")
                responses_log.write("\n")
                responses_log.write(response.text + "\n\n")

            request_counter += 1

            # Update status line after response
            status_line = f"[*] Combo {current_combo_num}/{total_combos} | Status: {resp_status} | Length: {len(response.text)} | Param Values: {dict(zip(param_order, combo))}"
            sys.stdout.write(f"\r{status_line.ljust(120)}")
            sys.stdout.flush()

            # If status matches filter-status-codes → print response permanently
            if show_status_codes and resp_status in show_status_codes:
                print()
                print(f"[cyan][*] Response Status: {response.status_code}[/cyan]")
                print(f"[cyan][*] Response Length: {len(response.text)}[/cyan]")
                print(f"[dim]{response.text}[/dim]\n")

            # Baseline diffing
            status_changed, body_changed = is_interesting(
                baseline_status, baseline_text,
                response.status_code, response.text,
                current_param=None
            )

            if status_changed or body_changed:
                print()
                print(f"[green][+] Interesting COMBO response | Param Values: {dict(zip(param_order, combo))}[/green]")
                print(f"    Status: {response.status_code}, Length: {len(response.text)}\n")

                if args.save:
                    combo_name = "_".join(combo).replace("/", "_").replace("\\", "_").replace(" ", "_")
                    filename = os.path.join(result_dir, f"combo_{combo_name}.txt")
                    with open(filename, "w") as out:
                        out.write(f"HTTP/1.1 {response.status_code} {response.reason}\n")
                        for header, value in response.headers.items():
                            out.write(f"{header}: {value}\n")
                        out.write("\n")
                        out.write(response.text)
            findings.append({
                            "url": prepared.url,
                            "method": prepared.method,
                            "param": " & ".join(param_order),
                            "payload": str(combo),
                            "status": response.status_code,
                            "reason": response.reason,
                            "length": len(response.text),
                            "request_headers": "\n".join([f"{k}: {v}" for k, v in prepared.headers.items()]),
                            "request_body": prepared.body.decode() if isinstance(prepared.body, bytes) else prepared.body,
                            "response_headers": "\n".join([f"{k}: {v}" for k, v in response.headers.items()]),
                            "response_body": response.text[:1000]
                            })

            current_combo_num += 1
            time.sleep(args.delay)

    else:
        # === INDEPENDENT PARAM FUZZING ===


        total_requests = len(payloads) * len(param_list)
        current_request_num = 1

        for param in param_list:
            placeholder = f"<<FUZZ_{param}>>"

            for payload in payloads:
                fuzzed_body = args.body.replace(placeholder, payload)
                for other_param in param_list:
                    if other_param != param:
                        fuzzed_body = fuzzed_body.replace(f"<<FUZZ_{other_param}>>", "BASELINE_VALUE")

                fuzzed_url = args.url.replace(f"<<FUZZ_{param}>>", payload)
                for other_param in param_list:
                    if other_param != param:
                        fuzzed_url = fuzzed_url.replace(f"<<FUZZ_{other_param}>>", "BASELINE_VALUE")

                pre_status_line = f"[*] Request {current_request_num}/{total_requests} | Param: {param} | Payload: '{payload}'"
                sys.stdout.write(f"\r{pre_status_line.ljust(120)}")
                sys.stdout.flush()

                try:
                    prepared,response = prepare_and_send_request(args.method, fuzzed_url, data=fuzzed_body, headers=headers, proxies=proxies)
                    if include_regex:
                          if not re.search(include_regex, response.text, re.IGNORECASE):
                              current_request_num += 1
                              continue
                except Exception as e:
                    sys.stdout.write(f"\r[red][-] Error sending request {current_request_num}/{total_requests} payload '{payload}': {e}[/red]\n")
                    sys.stdout.flush()
                    current_request_num += 1
                    continue

                resp_status = response.status_code

                # Skip unwanted responses
                if show_status_codes and resp_status not in show_status_codes:
                    current_request_num += 1
                    continue

                if hide_status_codes and resp_status in hide_status_codes:
                    current_request_num += 1
                    continue

                # Save request/response → only matching responses reach this point!
                if requests_log:
                    requests_log.write(f"==== REQUEST {request_counter} ====\n")
                    requests_log.write(f"{args.method} {fuzzed_url} HTTP/1.1\n")
                    for header, value in headers.items():
                        requests_log.write(f"{header}: {value}\n")
                    requests_log.write("\n")
                    requests_log.write(fuzzed_body + "\n\n")

                if responses_log:
                    responses_log.write(f"==== RESPONSE {request_counter} ====\n")
                    responses_log.write(f"HTTP/1.1 {response.status_code} {response.reason}\n")
                    for header, value in response.headers.items():
                        responses_log.write(f"{header}: {value}\n")
                    responses_log.write("\n")
                    responses_log.write(response.text + "\n\n")

                request_counter += 1

                status_line = f"[*] Request {current_request_num}/{total_requests} | Status: {resp_status} | Length: {len(response.text)} | Param: {param} | Payload: '{payload}'"
                sys.stdout.write(f"\r{status_line.ljust(120)}")
                sys.stdout.flush()

                if show_status_codes and resp_status in show_status_codes:
                    print()
                    print(f"[cyan][*] Response Status: {response.status_code}[/cyan]")
                    print(f"[cyan][*] Response Length: {len(response.text)}[/cyan]")
                    print(f"[dim]{response.text}[/dim]\n")

                status_changed, body_changed = is_interesting(
                    baseline_status, baseline_text,
                    response.status_code, response.text,
                    current_param=param
                )

                if status_changed or body_changed:
                    print()
                    print(f"[green][+] Interesting response for param '{param}' payload '{payload}'[/green]")
                    print(f"    Status: {response.status_code}, Length: {len(response.text)}\n")

                    if args.save:
                        safe_payload = payload.replace("/", "_").replace("\\", "_").replace(" ", "_")
                        filename = os.path.join(result_dir, f"{param}_{safe_payload}.txt")
                        with open(filename, "w") as out:
                            out.write(f"HTTP/1.1 {response.status_code} {response.reason}\n")
                            for header, value in response.headers.items():
                                out.write(f"{header}: {value}\n")
                            out.write("\n")
                            out.write(response.text)

                findings.append({
                            "url": prepared.url,
                            "method": prepared.method,
                            "param": param,
                            "payload": payload,
                            "status": response.status_code,
                            "reason": response.reason,
                            "length": len(response.text),
                            "request_headers": "\n".join([f"{k}: {v}" for k, v in prepared.headers.items()]),
                            "request_body": prepared.body.decode() if isinstance(prepared.body, bytes) else prepared.body,
                            "response_headers": "\n".join([f"{k}: {v}" for k, v in response.headers.items()]),
                            "response_body": response.text[:1000]
                            })

                current_request_num += 1
                time.sleep(args.delay)

    if hasattr(args, "report") and args.report and findings:
        generate_html_report(findings, os.path.join("results", args.report))


    # Close logs
    if requests_log:
        requests_log.close()
    if responses_log:
        responses_log.close()
