import yaml
import json

def parse_swagger(swagger_file):
    with open(swagger_file, "r") as f:
        if swagger_file.endswith(".yaml") or swagger_file.endswith(".yml"):
            spec = yaml.safe_load(f)
        else:
            spec = json.load(f)

    # Determine version
    version = spec.get("openapi") or spec.get("swagger")
    if version.startswith("3"):
        return parse_openapi3(spec)
    else:
        return parse_swagger2(spec)

def parse_swagger2(spec):
    endpoints = []
    base_path = spec.get("basePath", "")
    security_defs = spec.get("securityDefinitions", {})

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            method_upper = method.upper()
            params_list = []
            headers = {}

            parameters = details.get("parameters", [])
            for param in parameters:
                param_name = param.get("name")
                param_in = param.get("in")

                if param_in in ["path", "query"]:
                    param_entry = {"name": param_name, "location": param_in}
                    if "enum" in param:
                        param_entry["enum"] = param["enum"]
                    elif "schema" in param and "enum" in param["schema"]:
                        param_entry["enum"] = param["schema"]["enum"]
                    elif param.get("type") == "array" and "items" in param and "enum" in param["items"]:
                         param_entry["enum"] = param["items"]["enum"]

                    params_list.append(param_entry)

                elif param_in == "header":
                    headers[param_name] = f"<<{param_name}>>"
                elif param_in in ["formData", "body"]:
                    if param.get("schema"):
                        schema = param["schema"]
                        ref = schema.get("$ref")
                        if ref:
                            properties = resolve_ref(ref, spec.get("definitions", {}))
                            for k in properties:
                                params_list.append({"name": k, "location": "body"})
                    else:
                        params_list.append({"name": param_name, "location": "body"})

            # Handle security headers
            security_reqs = details.get("security", spec.get("security", []))
            for sec in security_reqs:
                for sec_name in sec:
                    sec_def = security_defs.get(sec_name, {})
                    if sec_def.get("type") == "apiKey":
                        headers[sec_def.get("name")] = f"<<{sec_def.get('name')}>>"
                    elif sec_def.get("type") == "oauth2":
                        headers["Authorization"] = "Bearer <<ACCESS_TOKEN>>"

            body_template = build_body_template(params_list)
            full_path = base_path.rstrip("/") + path

            endpoints.append({
                "url": full_path,
                "method": method_upper,
                "params": params_list,
                "body_template": body_template,
                "headers": headers
            })
    return endpoints

def parse_openapi3(spec):
    endpoints = []
    base_path = spec.get("servers", [{}])[0].get("url", "").replace("https://", "").replace("http://", "")
    if "/" in base_path:
        base_path = "/" + base_path.split("/", 1)[1]
    else:
        base_path = ""

    components = spec.get("components", {})
    security_defs = components.get("securitySchemes", {})

    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            method_upper = method.upper()
            params_list = []
            headers = {}

            parameters = details.get("parameters", [])
            for param in parameters:
                param_name = param.get("name")
                param_in = param.get("in")

                if param_in in ["path", "query"]:
                    param_entry = {"name": param_name, "location": param_in}
                    if "enum" in param:
                        param_entry["enum"] = param["enum"]
                    elif "schema" in param and "enum" in param["schema"]:
                        param_entry["enum"] = param["schema"]["enum"]
                    elif param.get("type") == "array" and "items" in param and "enum" in param["items"]:
                        param_entry["enum"] = param["items"]["enum"]
                    params_list.append(param_entry)
                elif param_in == "header":
                    headers[param_name] = f"<<{param_name}>>"

            request_body = details.get("requestBody")
            if request_body:
                content = request_body.get("content", {})
                for media_type, media_details in content.items():
                    schema = media_details.get("schema", {})
                    body_params = resolve_schema(schema, components.get("schemas", {}))
                    for param in body_params:
                        params_list.append({"name": param, "location": "body"})
                    break  # only first media type

            # Handle security headers
            security_reqs = details.get("security", spec.get("security", []))
            for sec in security_reqs:
                for sec_name in sec:
                    sec_def = security_defs.get(sec_name, {})
                    if sec_def.get("type") == "apiKey":
                        headers[sec_def.get("name")] = f"<<{sec_def.get('name')}>>"
                    elif sec_def.get("type") == "http" and sec_def.get("scheme") == "bearer":
                        headers["Authorization"] = "Bearer <<ACCESS_TOKEN>>"

            body_template = build_body_template(params_list)
            full_path = base_path.rstrip("/") + path

            endpoints.append({
                "url": full_path,
                "method": method_upper,
                "params": params_list,
                "body_template": body_template,
                "headers": headers
            })

    return endpoints

def build_body_template(params):
    body = {p['name']: f"<<FUZZ_{p['name']}>>" for p in params if p['location'] == "body"}
    return json.dumps(body)

def resolve_ref(ref, definitions):
    key = ref.split("/")[-1]
    return definitions.get(key, {}).get("properties", {})

def resolve_schema(schema, components):
    if "$ref" in schema:
        ref = schema["$ref"].split("/")[-1]
        return list(components.get(ref, {}).get("properties", {}).keys())
    elif schema.get("type") == "object":
        return list(schema.get("properties", {}).keys())
    return []
