import sys
from pathlib import Path

# Ensure agent directory and parent directory are both in sys.path
_current_dir = Path(__file__).resolve().parent
_parent_dir = _current_dir.parent

if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))
if str(_current_dir) not in sys.path:
    sys.path.insert(1, str(_current_dir))
