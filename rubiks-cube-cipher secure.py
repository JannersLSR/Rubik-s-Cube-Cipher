import secrets

# === CORE CUBE LOGIC ===

def rotate_face(f): return [f[6], f[3], f[0], f[7], f[4], f[1], f[8], f[5], f[2]]
def rotate_face_ccw(f): return [f[2], f[5], f[8], f[1], f[4], f[7], f[0], f[3], f[6]]

def split_into_faces(c):
    return {"U": c[0:9], "F": c[9:18], "R": c[18:27],
            "L": c[27:36], "B": c[36:45], "D": c[45:54]}

def flatten_faces(f):
    return f["U"] + f["F"] + f["R"] + f["L"] + f["B"] + f["D"]

def move(cube, m):
    f = split_into_faces(cube)
    if m == "U":
        f["U"] = rotate_face(f["U"])
        t = f["F"][:3]
        f["F"][:3], f["R"][:3], f["B"][:3], f["L"][:3] = f["R"][:3], f["B"][:3], f["L"][:3], t
    elif m == "U'":
        f["U"] = rotate_face_ccw(f["U"])
        t = f["F"][:3]
        f["F"][:3], f["L"][:3], f["B"][:3], f["R"][:3] = f["L"][:3], f["B"][:3], f["R"][:3], t
    elif m == "D":
        f["D"] = rotate_face(f["D"])
        t = f["F"][6:9]
        f["F"][6:9], f["L"][6:9], f["B"][6:9], f["R"][6:9] = f["L"][6:9], f["B"][6:9], f["R"][6:9], t
    elif m == "D'":
        f["D"] = rotate_face_ccw(f["D"])
        t = f["F"][6:9]
        f["F"][6:9], f["R"][6:9], f["B"][6:9], f["L"][6:9] = f["R"][6:9], f["B"][6:9], f["L"][6:9], t
    elif m == "F":
        f["F"] = rotate_face(f["F"])
        t = [f["U"][6], f["U"][7], f["U"][8]]
        f["U"][6], f["U"][7], f["U"][8], f["L"][2], f["L"][5], f["L"][8], f["D"][0], f["D"][1], f["D"][2], f["R"][0], f["R"][3], f["R"][6] = \
        f["L"][8], f["L"][5], f["L"][2], f["D"][0], f["D"][1], f["D"][2], f["R"][6], f["R"][3], f["R"][0], t[0], t[1], t[2]
    elif m == "F'":
        f["F"] = rotate_face_ccw(f["F"])
        t = [f["U"][6], f["U"][7], f["U"][8]]
        f["U"][6], f["U"][7], f["U"][8], f["R"][0], f["R"][3], f["R"][6], f["D"][0], f["D"][1], f["D"][2], f["L"][2], f["L"][5], f["L"][8] = \
        f["R"][0], f["R"][3], f["R"][6], f["D"][2], f["D"][1], f["D"][0], f["L"][2], f["L"][5], f["L"][8], t[2], t[1], t[0]
    elif m == "B":
        f["B"] = rotate_face(f["B"])
        t = [f["U"][0], f["U"][1], f["U"][2]]
        f["U"][0], f["U"][1], f["U"][2], f["R"][2], f["R"][5], f["R"][8], f["D"][6], f["D"][7], f["D"][8], f["L"][0], f["L"][3], f["L"][6] = \
        f["R"][2], f["R"][5], f["R"][8], f["D"][8], f["D"][7], f["D"][6], f["L"][0], f["L"][3], f["L"][6], t[2], t[1], t[0]
    elif m == "B'":
        f["B"] = rotate_face_ccw(f["B"])
        t = [f["U"][0], f["U"][1], f["U"][2]]
        f["U"][0], f["U"][1], f["U"][2], f["L"][0], f["L"][3], f["L"][6], f["D"][6], f["D"][7], f["D"][8], f["R"][2], f["R"][5], f["R"][8] = \
        f["L"][6], f["L"][3], f["L"][0], f["D"][6], f["D"][7], f["D"][8], f["R"][8], f["R"][5], f["R"][2], t[0], t[1], t[2]
    elif m == "R":
        f["R"] = rotate_face(f["R"])
        t = [f["U"][2], f["U"][5], f["U"][8]]
        f["U"][2], f["U"][5], f["U"][8], f["F"][2], f["F"][5], f["F"][8], f["D"][2], f["D"][5], f["D"][8], f["B"][0], f["B"][3], f["B"][6] = \
        f["F"][2], f["F"][5], f["F"][8], f["D"][2], f["D"][5], f["D"][8], f["B"][6], f["B"][3], f["B"][0], t[2], t[1], t[0]
    elif m == "R'":
        f["R"] = rotate_face_ccw(f["R"])
        t = [f["U"][2], f["U"][5], f["U"][8]]
        f["U"][2], f["U"][5], f["U"][8], f["B"][0], f["B"][3], f["B"][6], f["D"][2], f["D"][5], f["D"][8], f["F"][2], f["F"][5], f["F"][8] = \
        f["B"][6], f["B"][3], f["B"][0], f["D"][8], f["D"][5], f["D"][2], f["F"][2], f["F"][5], f["F"][8], t[0], t[1], t[2]
    elif m == "L":
        f["L"] = rotate_face(f["L"])
        t = [f["U"][0], f["U"][3], f["U"][6]]
        f["U"][0], f["U"][3], f["U"][6], f["B"][2], f["B"][5], f["B"][8], f["D"][0], f["D"][3], f["D"][6], f["F"][0], f["F"][3], f["F"][6] = \
        f["B"][8], f["B"][5], f["B"][2], f["D"][0], f["D"][3], f["D"][6], f["F"][0], f["F"][3], f["F"][6], t[0], t[1], t[2]
    elif m == "L'":
        f["L"] = rotate_face_ccw(f["L"])
        t = [f["U"][0], f["U"][3], f["U"][6]]
        f["U"][0], f["U"][3], f["U"][6], f["F"][0], f["F"][3], f["F"][6], f["D"][0], f["D"][3], f["D"][6], f["B"][2], f["B"][5], f["B"][8] = \
        f["F"][0], f["F"][3], f["F"][6], f["D"][0], f["D"][3], f["D"][6], f["B"][8], f["B"][5], f["B"][2], t[2], t[1], t[0]
    return flatten_faces(f)

def apply_moves(cube, seq):
    for m in seq.split(): cube = move(cube, m)
    return cube

def invert_moves(seq):
    out = []
    for m in reversed(seq.split()):
        out.append(m[:-1] if m.endswith("'") else m + "'")
    return " ".join(out)

# === KEY GENERATION & MOVE DERIVATION ===

def gen_key(): return secrets.token_bytes(32)
def key_to_hex(k): return k.hex()
def hex_to_key(h): return bytes.fromhex(h)

def derive_moves(k, n=20):
    base = ["U","U'","D","D'","F","F'","B","B'","R","R'","L","L'"]
    e = k
    while len(e) < n:
        e += bytes([b ^ e[i % len(k)] for i, b in enumerate(e)])
    return " ".join(base[e[i] % len(base)] for i in range(n))

# === ENCRYPTION ===

def encrypt_message():
    msg = input("Enter plaintext: ").strip()
    if not msg:
        print("❌ Empty input.")
        return

    bs = 54
    blocks = [msg[i:i+bs] for i in range(0, len(msg), bs)]
    blocks[-1] = blocks[-1].ljust(bs, '~')

    key = gen_key()
    key_hex = key_to_hex(key)
    moves = derive_moves(key)

    enc_blocks = []
    for b in blocks:
        arr = [ord(x) for x in b]
        out = apply_moves(arr[:], moves)
        enc_blocks.append("".join(chr(c) for c in out))

    cipher = "".join(enc_blocks)
    print("\n=== ✅ Encryption Complete ===")
    print(f"Ciphertext:\n{cipher}\n")
    print(f"Key (256-bit):\n{key_hex}\n")

# === DECRYPTION ===

def decrypt_message():
    bs = 54
    cipher = input("Enter ciphertext: ").strip()
    if not cipher:
        print("❌ Empty input.")
        return
    if len(cipher) % bs != 0:
        print(f"❌ Ciphertext length must be multiple of {bs}.")
        return

    k_hex = input("Enter 256-bit key (64 hex): ").strip()
    if len(k_hex) != 64:
        print("❌ Invalid key length.")
        return

    try:
        key = hex_to_key(k_hex)
    except ValueError:
        print("❌ Invalid key format.")
        return

    moves = derive_moves(key)
    inv = invert_moves(moves)
    blocks = [cipher[i:i+bs] for i in range(0, len(cipher), bs)]

    out_blocks = []
    for b in blocks:
        arr = [ord(x) for x in b]
        d = apply_moves(arr[:], inv)
        out_blocks.append("".join(chr(x) for x in d))

    msg = "".join(out_blocks).rstrip('~')
    print("\n=== ✅ Decryption Complete ===")
    print(f"Decrypted message:\n{msg}\n")


# === MAIN MENU ===

if __name__ == "__main__":
    while True:
        print("=== Rubik's Cube Cipher (256-bit Key) ===")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        c = input("Select an option (1-3): ").strip()
        if c == "1": encrypt_message()
        elif c == "2": decrypt_message()
        elif c == "3":
            print("👋 Exiting program. Goodbye!")
            break
        else:
            print("❌ Invalid choice.\n")
