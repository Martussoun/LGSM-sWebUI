import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Dict, Type

from .base import GameHandler

# Registry mapping: shortname -> handler class
GAME_HANDLERS: Dict[str, Type[GameHandler]] = {}

# The folder containing this file
MODULE_PATH = Path(__file__).parent
PACKAGE = __package__  # needed for relative imports

for finder, name, ispkg in pkgutil.iter_modules([str(MODULE_PATH)]):
    if name == "base" or name == "games_registry":
        continue  # skip abstract base and this file itself

    full_module_name = f"{PACKAGE}.{name}" if PACKAGE else name
    try:
        module = importlib.import_module(full_module_name)
    except Exception as e:
        print(f"Failed to import game handler module '{full_module_name}': {e}")
        continue

    # Find all subclasses of GameHandler in the module
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, GameHandler) and obj is not GameHandler:
            if not hasattr(obj, "shortname"):
                continue
            shortname = getattr(obj, "shortname")
            if shortname in GAME_HANDLERS:
                print(f"Warning: shortname '{shortname}' already registered. Overwriting.")
            GAME_HANDLERS[shortname] = obj
