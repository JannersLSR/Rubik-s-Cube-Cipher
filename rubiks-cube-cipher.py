# CUBE CIPHER: MULTI-BLOCK RUBIK'S CUBE ENCRYPTION WITH 256-BIT KEY
# Cipher Order layout: [U, F, R, L, B, D]

import secrets

# CORE OPERATIONS -----------------------------------------------------

def rotate_face(face):
    """Rotate a 3x3 face clockwise (indices 0..8)."""
    return [face[6], face[3], face[0],
            face[7], face[4], face[1],
            face[8], face[5], face[2]]

def rotate_face_ccw(face):
    """Rotate a 3x3 face counterclockwise (indices 0..8)."""
    return [face[2], face[5], face[8],
            face[1], face[4], face[7],
            face[0], face[3], face[6]]

def split_into_faces(cube):
    """Splits the 54-sticker list into 6 named 9-sticker faces."""
    return {
        "U": cube[0:9],
        "F": cube[9:18],
        "R": cube[18:27],
        "L": cube[27:36],
        "B": cube[36:45],
        "D": cube[45:54],
    }

def flatten_faces(faces):
    """Flattens the 6 faces back into a 54-sticker list."""
    return faces["U"] + faces["F"] + faces["R"] + faces["L"] + faces["B"] + faces["D"]

def move(cube, notation):
    """Apply a single Rubik's Cube move (U, D, F, B, R, L, and inverses)."""
    f = split_into_faces(cube)

    if notation == "U":
        f["U"] = rotate_face(f["U"])
        temp = f["F"][0:3]
        f["F"][0:3] = f["R"][0:3]
        f["R"][0:3] = f["B"][0:3]
        f["B"][0:3] = f["L"][0:3]
        f["L"][0:3] = temp

    elif notation == "U'":
        f["U"] = rotate_face_ccw(f["U"])
        temp = f["F"][0:3]
        f["F"][0:3] = f["L"][0:3]
        f["L"][0:3] = f["B"][0:3]
        f["B"][0:3] = f["R"][0:3]
        f["R"][0:3] = temp

    elif notation == "D":
        f["D"] = rotate_face(f["D"])
        temp = f["F"][6:9]
        f["F"][6:9] = f["L"][6:9]
        f["L"][6:9] = f["B"][6:9]
        f["B"][6:9] = f["R"][6:9]
        f["R"][6:9] = temp

    elif notation == "D'":
        f["D"] = rotate_face_ccw(f["D"])
        temp = f["F"][6:9]
        f["F"][6:9] = f["R"][6:9]
        f["R"][6:9] = f["B"][6:9]
        f["B"][6:9] = f["L"][6:9]
        f["L"][6:9] = temp

    elif notation == "F":
        f["F"] = rotate_face(f["F"])
        temp = [f["U"][6], f["U"][7], f["U"][8]]
        f["U"][6], f["U"][7], f["U"][8] = f["L"][8], f["L"][5], f["L"][2]
        f["L"][2], f["L"][5], f["L"][8] = f["D"][0], f["D"][1], f["D"][2]
        f["D"][0], f["D"][1], f["D"][2] = f["R"][6], f["R"][3], f["R"][0]
        f["R"][0], f["R"][3], f["R"][6] = temp[0], temp[1], temp[2]

    elif notation == "F'":
        f["F"] = rotate_face_ccw(f["F"])
        temp = [f["U"][6], f["U"][7], f["U"][8]]
        f["U"][6], f["U"][7], f["U"][8] = f["R"][0], f["R"][3], f["R"][6]
        f["R"][0], f["R"][3], f["R"][6] = f["D"][2], f["D"][1], f["D"][0]
        f["D"][0], f["D"][1], f["D"][2] = f["L"][2], f["L"][5], f["L"][8]
        f["L"][2], f["L"][5], f["L"][8] = temp[2], temp[1], temp[0]

    elif notation == "B":
        f["B"] = rotate_face(f["B"])
        temp = [f["U"][0], f["U"][1], f["U"][2]]
        f["U"][0], f["U"][1], f["U"][2] = f["R"][2], f["R"][5], f["R"][8]
        f["R"][2], f["R"][5], f["R"][8] = f["D"][8], f["D"][7], f["D"][6]
        f["D"][6], f["D"][7], f["D"][8] = f["L"][0], f["L"][3], f["L"][6]
        f["L"][0], f["L"][3], f["L"][6] = temp[2], temp[1], temp[0]

    elif notation == "B'":
        f["B"] = rotate_face_ccw(f["B"])
        temp = [f["U"][0], f["U"][1], f["U"][2]]
        f["U"][0], f["U"][1], f["U"][2] = f["L"][6], f["L"][3], f["L"][0]
        f["L"][0], f["L"][3], f["L"][6] = f["D"][6], f["D"][7], f["D"][8]
        f["D"][6], f["D"][7], f["D"][8] = f["R"][8], f["R"][5], f["R"][2]
        f["R"][2], f["R"][5], f["R"][8] = temp[0], temp[1], temp[2]

    elif notation == "R":
        f["R"] = rotate_face(f["R"])
        temp = [f["U"][2], f["U"][5], f["U"][8]]
        f["U"][2], f["U"][5], f["U"][8] = f["F"][2], f["F"][5], f["F"][8]
        f["F"][2], f["F"][5], f["F"][8] = f["D"][2], f["D"][5], f["D"][8]
        f["D"][2], f["D"][5], f["D"][8] = f["B"][6], f["B"][3], f["B"][0]
        f["B"][0], f["B"][3], f["B"][6] = temp[2], temp[1], temp[0]

    elif notation == "R'":
        f["R"] = rotate_face_ccw(f["R"])
        temp = [f["U"][2], f["U"][5], f["U"][8]]
        f["U"][2], f["U"][5], f["U"][8] = f["B"][6], f["B"][3], f["B"][0]
        f["B"][0], f["B"][3], f["B"][6] = f["D"][8], f["D"][5], f["D"][2]
        f["D"][2], f["D"][5], f["D"][8] = f["F"][2], f["F"][5], f["F"][8]
        f["F"][2], f["F"][5], f["F"][8] = temp[0], temp[1], temp[2]

    elif notation == "L":
        f["L"] = rotate_face(f["L"])
        temp = [f["U"][0], f["U"][3], f["U"][6]]
        f["U"][0], f["U"][3], f["U"][6] = f["B"][8], f["B"][5], f["B"][2]
        f["B"][2], f["B"][5], f["B"][8] = f["D"][6], f["D"][3], f["D"][0]
        f["D"][0], f["D"][3], f["D"][6] = f["F"][0], f["F"][3], f["F"][6]
        f["F"][0], f["F"][3], f["F"][6] = temp[0], temp[1], temp[2]

    elif notation == "L'":
        f["L"] = rotate_face_ccw(f["L"])
        temp = [f["U"][0], f["U"][3], f["U"][6]]
        f["U"][0], f["U"][3], f["U"][6] = f["F"][0], f["F"][3], f["F"][6]
        f["F"][0], f["F"][3], f["F"][6] = f["D"][0], f["D"][3], f["D"][6]
        f["D"][0], f["D"][3], f["D"][6] = f["B"][8], f["B"][5], f["B"][2]
        f["B"][2], f["B"][5], f["B"][8] = temp[2], temp[1], temp[0]

    return flatten_faces(f)

def apply_moves(cube, moves):
    for m in moves.split():
        cube = move(cube, m)
    return cube

def invert_moves(moves):
    """Invert a move sequence for decryption."""
    inverted = []
    for m in reversed(moves.split()):
        inverted.append(m[:-1] if m.endswith("'") else m + "'")
    return " ".join(inverted)

# KEY FUNCTIONS ------------------------------------------------------

def generate_256bit_key():
    return secrets.token_bytes(32)

def key_to_hex(key):
    return key.hex()

def hex_to_key(hex_string):
    return bytes.fromhex(hex_string)

def derive_moves_from_key(key, num_moves=20):
    moves_list = ["U", "U'", "D", "D'", "F", "F'", "B", "B'", "R", "R'", "L", "L'"]
    extended_key = key
    while len(extended_key) < num_moves:
        extended_key += bytes([b ^ extended_key[i % len(key)] for i, b in enumerate(extended_key)])
    derived_moves = [moves_list[extended_key[i] % len(moves_list)] for i in range(num_moves)]
    return " ".join(derived_moves)

# VISUALIZATION ------------------------------------------------------

def print_cube(cube):
    faces = split_into_faces(cube)
    for name, face in faces.items():
        print(f"{name} face:")
        for i in range(3):
            print(" ".join(chr(face[i * 3 + j]) if 32 <= face[i * 3 + j] <= 126 else "?" for j in range(3)))
        print()

# ENCRYPTION ---------------------------------------------------------

def encrypt_message():
    """Encrypts a plaintext message using a 256-bit key with retry loops."""
    while True:
        plaintext = input("Enter plaintext: ").strip()
        if not plaintext:
            print("❌ Error: Plaintext cannot be empty. Try again.\n")
            continue
        break

    block_size = 54
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    blocks[-1] = blocks[-1].ljust(block_size, '~')

    key = generate_256bit_key()
    key_hex = key_to_hex(key)
    print(f"\n🔑 Generated 256-bit key:\n   {key_hex}\n")

    key_moves = derive_moves_from_key(key, num_moves=20)
    print(f"🌀 Derived moves from key:\n   {key_moves}\n")

    encrypted_blocks = []

    print("=== 🔒 Encryption Process Start ===")
    for i, block in enumerate(blocks):
        print(f"\n--- Block {i + 1}/{len(blocks)} ---")
        ascii_block = [ord(c) for c in block]
        print("\nOriginal Cube:")
        print_cube(ascii_block)
        encrypted = apply_moves(ascii_block[:], key_moves)
        print("Encrypted Cube:")
        print_cube(encrypted)
        encrypted_blocks.append("".join(chr(c) for c in encrypted))

    ciphertext = "".join(encrypted_blocks)
    print("\n=== ✅ Encryption Complete ===")
    print(f"Ciphertext ({len(ciphertext)} chars):\n{ciphertext}\n")
    print("🔑 Save this key to decrypt:\n" + key_hex + "\n")

# DECRYPTION ---------------------------------------------------------

def decrypt_message():
    """Decrypts a ciphertext using the 256-bit key with retry loops."""
    block_size = 54

    # Loop until valid ciphertext
    while True:
        ciphertext = input("Enter full ciphertext: ").strip()
        if not ciphertext:
            print("❌ Error: Ciphertext cannot be empty. Try again.\n")
            continue
        if len(ciphertext) % block_size != 0:
            print(f"❌ Error: Ciphertext length ({len(ciphertext)}) must be multiple of {block_size}. Try again.\n")
            continue
        break

    # Loop until valid key
    while True:
        key_hex = input("Enter 256-bit key (64 hex chars): ").strip()
        if len(key_hex) != 64:
            print("❌ Error: Key must be exactly 64 hex characters (256 bits). Try again.\n")
            continue
        try:
            key = hex_to_key(key_hex)
            break
        except ValueError:
            print("❌ Error: Invalid hexadecimal format. Try again.\n")

    key_moves = derive_moves_from_key(key, num_moves=20)
    inverted_moves = invert_moves(key_moves)

    print(f"\nDerived moves:\n   {key_moves}")
    print(f"Inverted for decryption:\n   {inverted_moves}\n")

    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []

    print("=== 🔓 Decryption Process Start ===")
    for i, block in enumerate(blocks):
        print(f"\n--- Block {i + 1}/{len(blocks)} ---")
        ascii_block = [ord(c) for c in block]
        print("\nEncrypted Cube (Input):")
        print_cube(ascii_block)
        decrypted = apply_moves(ascii_block[:], inverted_moves)
        print("Decrypted Cube (Output):")
        print_cube(decrypted)
        decrypted_blocks.append("".join(chr(c) for c in decrypted))

    message = "".join(decrypted_blocks).rstrip('~')
    print("\n=== ✅ Decryption Complete ===")
    print(f"📜 Decrypted message: '{message}'\n")

# MAIN MENU ----------------------------------------------------------

if __name__ == "__main__":
    while True:
        print("=== Rubik's Cube Cipher (256-bit Key) ===")
        print("1. Encrypt (Auto-generate 256-bit key)")
        print("2. Decrypt (Using 256-bit key)")
        print("3. Exit")

        choice = input("Select an option (1-3): ").strip()
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            print("👋 Exiting program. Goodbye!")
            break
        else:
            print("❌ Invalid option. Please select 1-3.\n")
