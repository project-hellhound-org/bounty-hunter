import os
import sys
import json
import importlib.util
import pkgutil

def extract_module_info(module_path, module_name):
    """
    Dynamically loads a Python module and extracts its metadata and OPTIONS.
    """
    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Extract core metadata
        name = getattr(module, 'NAME', module_name)
        category = getattr(module, 'CATEGORY', 'general')
        description = getattr(module, 'DESCRIPTION', 'No description provided.')
        options = getattr(module, 'OPTIONS', {})

        # Normalize options if they are a list (legacy support)
        normalized_options = {}
        if isinstance(options, list):
            for opt in options:
                opt_name = opt.get('name')
                if opt_name:
                    normalized_options[opt_name] = {
                        "type": str(opt.get('type', 'str')),
                        "required": opt.get('required', False),
                        "default": opt.get('default'),
                        "description": opt.get('help', 'No description.')
                    }
        elif isinstance(options, dict):
            for opt_name, opt_data in options.items():
                normalized_options[opt_name] = {
                    "type": str(opt_data.get('type', 'str')),
                    "required": opt_data.get('required', False),
                    "default": opt_data.get('default'),
                    "description": opt_data.get('description', 'No description.')
                }

        return {
            "name": name,
            "category": category,
            "description": description,
            "options": normalized_options,
            "path": module_path
        }
    except Exception as e:
        return {
            "name": module_name,
            "category": "error",
            "description": f"Load error: {str(e)}",
            "options": {},
            "error": True
        }

def discover_all_modules(project_root):
    """
    Walks the hellhound/modules directory and builds the Arsenal schema.
    """
    modules_root = os.path.join(project_root, 'hellhound', 'modules')
    arsenal = {}

    if not os.path.exists(modules_root):
        return arsenal

    # Walk through categories (subdirectories)
    for root, dirs, files in os.walk(modules_root):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                module_path = os.path.join(root, file)
                # Use filename as internal key
                module_key = os.path.splitext(file)[0]
                info = extract_module_info(module_path, module_key)
                arsenal[module_key] = info

    return arsenal

if __name__ == "__main__":
    # Get project root from args or assume parent of gui/
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..')
    
    modules_data = discover_all_modules(os.path.abspath(root))
    print(json.dumps(modules_data, indent=2))