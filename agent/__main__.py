import sys
from pathlib import Path

# Ensure sys.path contains both parent directory and current directory
_current_dir = Path(__file__).resolve().parent
_parent_dir = _current_dir.parent

if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))
if str(_current_dir) not in sys.path:
    sys.path.insert(1, str(_current_dir))

try:
    from agent.agent import run_agent
except ImportError:
    from agent import run_agent

if __name__ == "__main__":
    run_agent()
