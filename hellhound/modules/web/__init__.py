import pkgutil
import importlib
import inspect


def discover_modules():
    """
    Dynamically discover all modules inside hellhound.modules.*
    Each module must expose:
        NAME
        CATEGORY
        DESCRIPTION
        run(target, emit, options=None)
    """

    discovered = {}

    package = __name__

    for finder, name, ispkg in pkgutil.walk_packages(__path__, package + "."):
        try:
            module = importlib.import_module(name)

            # Validate required attributes
            if all(hasattr(module, attr) for attr in ["NAME", "CATEGORY", "DESCRIPTION", "run"]):

                discovered[module.NAME] = {
                    "name": module.NAME,
                    "category": module.CATEGORY,
                    "description": module.DESCRIPTION,
                    "module": module
                }

        except Exception:
            continue

    return discovered

