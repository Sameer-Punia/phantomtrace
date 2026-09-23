import sys
import os

# Add root directory to sys.path so it finds main.py and forensic_engine.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app