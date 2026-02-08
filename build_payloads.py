
import hashlib, base64, json, os, struct
from cryptography.fernet import Fernet

SALT = "hyperion_gate_v2_2026"

def make_key(hwid):
    raw = hashlib.sha256((hwid + SALT).encode()).digest()
    return base64.urlsafe_b64encode(raw)

def make_filename(hwid):
    return hashlib.sha256(hwid.encode()).hexdigest()

def build_payload(dll_bytes, username, plus_status):

    meta = json.dumps({"u": username, "p": plus_status}).encode()
    return struct.pack('<I', len(meta)) + meta + dll_bytes

def main():
    # Read the DLL
    dll_path = "HyperionClient.dll"
    if not os.path.exists(dll_path):
        print(f"ERROR: {dll_path} not found")
        return

    with open(dll_path, 'rb') as f:
        dll_bytes = f.read()
    print(f"DLL loaded: {len(dll_bytes)} bytes")

    if not os.path.exists("Userbase.txt"):
        print("ERROR: Userbase.txt not found")
        return

    with open("Userbase.txt", 'r') as f:
        lines = f.readlines()

    os.makedirs("docs", exist_ok=True)

    with open("docs/index.html", 'w') as f:
        f.write("<!-- Hyperion Gate -->")

    count = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        parts = line.split(',', 2)
        if len(parts) < 3:
            print(f"  SKIP (bad format): {line}")
            continue

        hwid = parts[0].strip()
        plus_status = int(parts[1].strip())
        username = parts[2].strip()

        payload = build_payload(dll_bytes, username, plus_status)
        key = make_key(hwid)
        encrypted = Fernet(key).encrypt(payload)

        filename = make_filename(hwid)
        with open(f"docs/{filename}.enc", 'wb') as f:
            f.write(encrypted)

        count += 1
        print(f"  [{count}] {username} ({'PLUS' if plus_status else 'FREE'}) -> {filename[:16]}...")

    print(f"\nDone: {count} payloads built in docs/")

if __name__ == '__main__':
    main()
