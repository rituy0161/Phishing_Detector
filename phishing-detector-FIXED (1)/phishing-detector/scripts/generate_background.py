#!/usr/bin/env python3
"""
DEPRECATED: This file is no longer used.

This script has been replaced by make_background.py which provides better
functionality for generating background.js from trained neural network models.

USAGE: Use make_background.py instead
    python make_background.py

This will read from models/ directory and generate src/background.js with
the neural network weights baked in.
"""

import sys

if __name__ == "__main__":
    print("⚠️  DEPRECATED: generate_background.py is no longer used.")
    print("   Please use: python make_background.py")
    print()
    print("   make_background.py will:")
    print("     - Read trained weights from models/nn_weights.json")
    print("     - Generate complete src/background.js with weights embedded")
    print("     - Require no external dependencies at runtime")
    sys.exit(1)
