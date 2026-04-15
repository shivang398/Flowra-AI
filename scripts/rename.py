import os

replacements = {
    "Sentinel": "Flowra",
    "sentinel": "flowra",
    "SENTINEL": "FLOWRA"
}

target_extensions = {".py", ".html", ".md", ".yml", ".example"}

def replace_in_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        new_content = content
        for old, new in replacements.items():
            new_content = new_content.replace(old, new)
            
        if new_content != content:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"Updated: {filepath}")
    except Exception as e:
        print(f"Skipped {filepath}: {e}")

for root, dirs, files in os.walk("."):
    if "venv" in dirs:
        dirs.remove("venv")
    if ".git" in dirs:
        dirs.remove(".git")
    if "model" in dirs:
        dirs.remove("model")
    if ".pytest_cache" in dirs:
        dirs.remove(".pytest_cache")

    for file in files:
        ext = os.path.splitext(file)[1]
        # Ignore this script
        if file == "rename.py":
            continue
        if ext in target_extensions:
            filepath = os.path.join(root, file)
            replace_in_file(filepath)
