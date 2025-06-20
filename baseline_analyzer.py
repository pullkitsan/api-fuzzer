from deepdiff import DeepDiff
import json

def is_interesting(base_status, base_text, current_status, current_text, current_param=None):
    status_changed = current_status != base_status
    body_changed = False

    try:
        base_json = json.loads(base_text)
        current_json = json.loads(current_text)

        # If current_param is provided, ignore diff in that key
        exclude_paths = []
        if current_param:
            # Handle case-insensitive paths and nested paths:
            # This is a simple version for flat JSON:
            exclude_paths = [f"root['{current_param}']", f"root[\"{current_param}\"]"]

        diff = DeepDiff(
            base_json,
            current_json,
            ignore_order=True,
            exclude_paths=exclude_paths
        )

        # body_changed only True if there are differences outside excluded path
        body_changed = bool(diff)

    except Exception as e:
        # Fallback to length-based diff if not JSON or error occurs
        body_changed = len(current_text) != len(base_text)

    return status_changed, body_changed
