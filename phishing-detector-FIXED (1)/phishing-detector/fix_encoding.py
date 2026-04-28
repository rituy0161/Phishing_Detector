#!/usr/bin/env python3
"""
Remove non-ASCII characters from JavaScript files.
Replace Unicode decorative characters with ASCII equivalents.
"""
import os
import sys

def fix_file(filepath):
    """Remove problem characters from a file."""
    print(f"Fixing {filepath}...")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_length = len(content)
    replacements = {
        '—': '--',  # em-dash to double dash
        '–': '-',   # en-dash to single dash
        '─': '-',   # box-drawing light horizontal to dash (U+2500)
        '──': '--', # combined box-drawing to double dash
        '───': '---',
        '────': '----',
        '─────': '-----',
        '──────': '------',
        '───────': '-------',
        '────────': '--------',
        '─────────': '---------',
        '──────────': '----------',
        '───────────': '-----------',
        '────────────': '------------',
        '─────────────': '-------------',
        '──────────────': '--------------',
        '───────────────': '---------------',
    }
    
    for old, new in replacements.items():
        content = content.replace(old, new)
    
    # Remove problematic emoji from comments but keep in strings
    # This is risky, so we'll be conservative
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    new_length = len(content)
    print(f"  Original: {original_length} chars")
    print(f"  New:      {new_length} chars")
    if original_length != new_length:
        print(f"  Removed:  {original_length - new_length} chars")

# Fix all JavaScript files
js_files = [
    'src/content.js',
    'src/popup.js',
    'src/background.js',
    'src/options.js',
]

os.chdir(os.path.dirname(os.path.abspath(__file__)))

for js_file in js_files:
    if os.path.exists(js_file):
        try:
            fix_file(js_file)
        except Exception as e:
            print(f"❌ Error fixing {js_file}: {e}")
            sys.exit(1)
    else:
        print(f"⚠️  {js_file} not found")

print("\n✅ All files fixed!")
