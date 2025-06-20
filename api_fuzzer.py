import argparse
from fuzzer_engine import run_fuzzer
from swagger_parser import parse_swagger
from rich import print as rprint
import sys


# Simple in-memory Swagger cache
swagger_cache = {}

def parse_swagger_cached(swagger_file):
    if swagger_file in swagger_cache:
        return swagger_cache[swagger_file]

    endpoints = parse_swagger(swagger_file)
    swagger_cache[swagger_file] = endpoints
    return endpoints

def main():
    parser = argparse.ArgumentParser(description="API Param Fuzzer CLI")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--method", choices=["POST", "PUT"], help="HTTP method")
    parser.add_argument("--body", help="Request body with <<FUZZ_param>> placeholders")
    parser.add_argument("--params", help="Comma-separated list of param names to fuzz")
    parser.add_argument("--wordlist", help="Path to wordlist file")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests (seconds)")
    parser.add_argument("--save", action="store_true", help="Save interesting responses to separate files")
    parser.add_argument("--save-request", action="store_true", help="Save all HTTP requests to results/requests.txt")
    parser.add_argument("--save-response", action="store_true", help="Save all HTTP responses to results/responses.txt")
    parser.add_argument("--filter-status-codes", help="Comma-separated list of status codes to show (whitelist)")
    parser.add_argument("--hide-status-codes", help="Comma-separated list of status codes to hide (blacklist)")
    parser.add_argument("--swagger-file", help="Path to Swagger file")
    parser.add_argument("--base-url", help="Base URL to prepend to endpoint path when using --swagger-file")
    parser.add_argument("--dry-run", action="store_true", help="List endpoints/params/body and exit (no fuzzing)")
    parser.add_argument("--combo", action="store_true", help="Enable combo mode (multi-param Cluster Bomb style)")
    parser.add_argument('--proxy', help="Proxy to route HTTP requests through (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--report", help="Path to HTML report output (e.g. results/report.html)")
    parser.add_argument("--auth-header", help="Authorization header value (e.g. 'Bearer <token>')")
    parser.add_argument("--include-regex", help="Regex pattern to match in response body before displaying/saving")

    args = parser.parse_args()

    # Normalize comma-separated --params into a list
    if args.params:
        args.params = [p.strip() for p in args.params.split(",") if p.strip()]


    if args.params and args.swagger_file:
        rprint(f"[yellow][!] No parameters are explicitly required if swagger file is used.[/yellow]")
        sys.exit(1)
    
    if args.swagger_file and args.url:
        rprint("[yellow][!] Use --url only if no swagger file is used.[/yellow]")
        sys.exit(1)
    
    if args.params:

        unused_params = [p for p in args.params if f"<<FUZZ_{p}>>" not in args.url and f"<<FUZZ_{p}>>" not in args.body]
        if unused_params:
            rprint(f"[red][-] The following parameters are not used in URL or body and cannot be fuzzed: {', '.join(unused_params)}[/red]")
            sys.exit(1)

        if len(args.params) == 1 and args.combo:
            rprint(f"[yellow][!] Only Use --combo for fuzzing multiple parameters.[/yellow]")
            sys.exit(1)

        if len(args.params) > 1 and not args.combo:
            rprint(f"[yellow][!] Multiple parameters detected. Use --combo for fuzzing multiple parameters.[/yellow]")
            sys.exit(1)

        

    # If Swagger mode is used → run interactive flow
    if args.swagger_file:
        if not args.base_url:
            rprint("[red][-] When using --swagger-file you must also provide --base-url.[/red]")
            exit(1)

        endpoints = parse_swagger_cached(args.swagger_file)

        if not endpoints:
            rprint("[red][-] No suitable endpoints found in Swagger file.[/red]")
            exit(1)

        # --dry-run → just list and exit
        if args.dry_run:
            print("\nAvailable endpoints:")
            for idx, ep in enumerate(endpoints):
                print(f"[{idx+1}] {ep['method']} {ep['url']}")
                print("  Params:")
                for p in ep["params"]:
                    if "enum" in p:
                        print(f"    - {p['name']} ({p['location']}) [enum: {', '.join(p['enum'])}]")
                    else:
                        print(f"    - {p['name']} ({p['location']})")
                print(f"  Body template: {ep['body_template']}")
                if ep.get("headers"):
                        print("  Required headers:")
                        for k, v in ep["headers"].items():
                            print(f"    - {k}: {v}")

            rprint("\n[cyan][*] Dry run complete. Exiting.[/cyan]\n")
            exit(0)

        # Show endpoints
        print("\nSelect endpoint to fuzz:")
        for idx, ep in enumerate(endpoints):
            print(f"[{idx+1}] {ep['method']} {ep['url']}")

        ep_choice = int(input("Enter endpoint number: ")) - 1
        selected_ep = endpoints[ep_choice]

        # Split params by location
        path_params = [p["name"] for p in selected_ep["params"] if p["location"] == "path"]
        query_params = [p["name"] for p in selected_ep["params"] if p["location"] == "query"]
        body_params  = [p["name"] for p in selected_ep["params"] if p["location"] == "body"]

        # Show params
        def print_param_list_with_enum(param_names, param_type_label, all_param_metadata):
            print(f"{param_type_label}:")
            for name in param_names:
                enum_vals = next((p.get("enum") for p in all_param_metadata if p["name"] == name and "enum" in p), None)
                if enum_vals:
                    print(f"  - {name} [enum: {', '.join(enum_vals)}]")
                else:
                    print(f"  - {name}")

        print()
        print_param_list_with_enum(path_params, "Path params", selected_ep["params"])
        print_param_list_with_enum(query_params, "Query params", selected_ep["params"])
        print_param_list_with_enum(body_params, "Body params", selected_ep["params"])

        # Let user select params to fuzz
        selected_params_input = input("\nEnter param(s) to fuzz (comma-separated): ").strip()
        selected_params = [p.strip() for p in selected_params_input.split(",") if p.strip()]

        # Validate selected parameters
        all_params = path_params + query_params + body_params
        invalid_params = [p for p in selected_params if p and p not in all_params]

        if invalid_params:
            rprint(f"[red][-] Invalid parameter(s) selected for fuzzing: {', '.join(invalid_params)}[/red]")
            rprint(f"[cyan][*] Valid parameters are: {', '.join(all_params)}[/cyan]")
            exit(1)

        if len([p for p in selected_params if p]) > 1 and not args.combo:
            rprint("[red][-] Multiple parameters selected for fuzzing, but --combo flag is not set.[/red]")
            rprint("[cyan][*] Use --combo to enable multi-parameter fuzzing.[/cyan]")
            exit(1)

        # Determine non-fuzzed params
        all_params = path_params + query_params + body_params
        non_fuzzed_params = [p for p in all_params if p not in selected_params]

        # Ask user to input values for non-fuzzed params
        non_fuzzed_values = {}
        for param in non_fuzzed_params:
            value = input(f"Enter static value for non-fuzzed param '{param}': ").strip()
            non_fuzzed_values[param] = value
        
        if selected_ep.get("headers"):
            print("\nRequired headers found:")
            resolved_headers = {}
            for key, placeholder in selected_ep["headers"].items():
                if "<<" in placeholder and ">>" in placeholder:
                    value = input(f"  → Enter value for header '{key}': ").strip()
                    resolved_headers[key] = value
                else:
                    resolved_headers[key] = placeholder
            selected_ep["headers"] = resolved_headers

        if not selected_params:
            rprint("[yellow][*] No parameters selected for fuzzing. Sending one request with provided values.[/yellow]")

            # Compose full URL using static values
            full_url = args.base_url.rstrip("/") + selected_ep["url"]
            for param in path_params:
                full_url = full_url.replace(f"{{{param}}}", non_fuzzed_values[param])

            if query_params:
                query_string = "&".join([f"{param}={non_fuzzed_values[param]}" for param in query_params])
                full_url += "?" + query_string

            # Inject values into body
            body_template = selected_ep["body_template"]
            for param, value in non_fuzzed_values.items():
                body_template = body_template.replace(f"<<FUZZ_{param}>>", value)

            import requests
            headers = {"Content-Type": "application/json"}
            proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None

            response = requests.request(
                method=selected_ep["method"],
                url=full_url,
                headers=headers,
                data=body_template,
                proxies=proxies
            )

            rprint(f"\n[cyan][*] Status: {response.status_code}[/cyan]")
            rprint(f"[cyan][*] Length: {len(response.text)}[/cyan]")
            rprint(f"[dim]{response.text}[/dim]")
            exit(0)


        # Compose full URL → replace path params with <<FUZZ_param>> or static value
        full_url = args.base_url.rstrip("/") + selected_ep["url"]
        for param in path_params:
            if param in selected_params:
                full_url = full_url.replace(f"{{{param}}}", f"<<FUZZ_{param}>>")
            else:
                full_url = full_url.replace(f"{{{param}}}", non_fuzzed_values[param])

        # Add query params with placeholders if selected
        selected_query_params = [p for p in selected_params if p in query_params]
        if selected_query_params:
            query_string = "&".join([f"{param}=<<FUZZ_{param}>>" for param in selected_query_params])
            full_url = full_url + "?" + query_string

        # Add static query params if not fuzzed
        static_query_params = [p for p in query_params if p in non_fuzzed_values]
        if static_query_params:
            query_string = "&".join([f"{param}={non_fuzzed_values[param]}" for param in static_query_params])
            if "?" in full_url:
                full_url += "&" + query_string
            else:
                full_url += "?" + query_string

        # Build body template and inject non-fuzzed values
        body_template = selected_ep["body_template"]
        for param in non_fuzzed_values:
            if f"<<FUZZ_{param}>>" in body_template:
                body_template = body_template.replace(f"<<FUZZ_{param}>>", non_fuzzed_values[param])


        # Build args for run_fuzzer
        class SwaggerArgs:
            url = full_url
            method = selected_ep["method"]
            body = body_template
            params = selected_params
            wordlist = input("Enter path to wordlist: ").strip()
            delay = args.delay
            save = args.save
            filter_status_codes = args.filter_status_codes if args.filter_status_codes else ""
            hide_status_codes = args.hide_status_codes if args.hide_status_codes else ""
            combo = args.combo
            save_request = args.save_request
            save_response = args.save_response
            proxy=args.proxy
            report=args.report
            auth_header = args.auth_header
            include_regex = args.include_regex if args.include_regex else ""
            headers = selected_ep.get("headers", {})


        # Now run your fuzzer
        rprint(f"\n[cyan][*] Starting fuzzer on {SwaggerArgs.method} {SwaggerArgs.url} with params {selected_params}[/cyan]\n")

        run_fuzzer(SwaggerArgs, selected_params)

        exit(0)  # Exit after Swagger flow

    # === Original CLI flow ===
    if not all([args.url, args.method, args.body, args.params, args.wordlist]):
        parser.error("Missing required arguments when not using --swagger-file.")

    #param_list = [param.strip() for param in args.params.split(",")]
    param_list = args.params
    if not hasattr(args, "combo"):
        args.combo = args.combo  # ensure combo always exists

    run_fuzzer(args, param_list)

if __name__ == "__main__":
    main()
