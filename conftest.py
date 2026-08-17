import sys
from pathlib import Path

# Ensure project root is in python sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
