import os
with open("requirements.txt") as f:
    for line in f:
        package = line.strip()
        if package:
            print(f"Installing {package}...")
            os.system(f"pip install {package}")  # Replace with subprocess for more control
