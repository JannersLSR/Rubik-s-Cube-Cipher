import secrets

PADDING_BYTES = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
    0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
    0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4
]

def rotate_face(face):
    return [face[6], face[3], face[0],
            face[7], face[4], face[1],
            face[8], face[5], face[2]]

def rotate_face_ccw(face):
    return [face[2], face[5], face[8],
            face[1], face[4], face[7],
            face[0], face[3], face[6]]

def split_into_faces(cube):
    return {
        "U": cube[0:9],
        "F": cube[9:18],
        "R": cube[18:27],
        "L": cube[27:36],
        "B": cube[36:45],
        "D": cube[45:54],
    }

def flatten_faces(faces):
    return faces["U"] + faces["F"] + faces["R"] + faces["L"] + faces["B"] + faces["D"]

def move(cube, notation):
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
    inverted = []
    for m in reversed(moves.split()):
        inverted.append(m[:-1] if m.endswith("'") else m + "'")
    return " ".join(inverted)

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

def encrypt_message():
    while True:
        plaintext = input("Enter plaintext: ").strip()
        if not plaintext:
            print("Error: Plaintext cannot be empty. Try again.")
            continue
        break

    block_size = 54
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    
    if len(blocks[-1]) < block_size:
        pad_len = block_size - len(blocks[-1])
        pads = [secrets.choice(PADDING_BYTES) for _ in range(pad_len)]
        blocks[-1] = blocks[-1] + ''.join(chr(b) for b in pads)

    key = generate_256bit_key()
    key_hex = key_to_hex(key)
    key_moves = derive_moves_from_key(key, num_moves=20)

    encrypted_blocks = []

    print("=== Encryption Process Start ===")
    for i, block in enumerate(blocks):
        ascii_block = [ord(c) for c in block]
        encrypted = apply_moves(ascii_block[:], key_moves)
        encrypted_blocks.append("".join(chr(c) for c in encrypted))

    ciphertext = "".join(encrypted_blocks)
    print("\n=== Encryption Complete ===")
    print(f"Ciphertext:\n{ciphertext}\n")
    print("Save this key to decrypt:\n" + key_hex + "\n")

def decrypt_message():
    block_size = 54

    while True:
        ciphertext = input("Enter full ciphertext: ").strip()
        if not ciphertext:
            print("Error: Ciphertext cannot be empty. Try again.")
            continue
        if len(ciphertext) % block_size != 0:
            print(f"Error: Ciphertext length must be multiple of {block_size}. Try again.")
            continue
        break

    while True:
        key_hex = input("Enter 256-bit key (64 hex chars): ").strip()
        if len(key_hex) != 64:
            print("Error: Key must be exactly 64 hex characters. Try again.")
            continue
        try:
            key = hex_to_key(key_hex)
            break
        except ValueError:
            print("Error: Invalid hexadecimal format. Try again.")

    key_moves = derive_moves_from_key(key, num_moves=20)
    inverted_moves = invert_moves(key_moves)

    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []

    print("=== Decryption Process Start ===")
    for i, block in enumerate(blocks):
        ascii_block = [ord(c) for c in block]
        decrypted = apply_moves(ascii_block[:], inverted_moves)
        decrypted_blocks.append("".join(chr(c) for c in decrypted))

    raw = [ord(c) for c in "".join(decrypted_blocks)]
    while raw and raw[-1] in PADDING_BYTES:
        raw.pop()
    message = ''.join(chr(b) for b in raw)

    print("\n=== Decryption Complete ===")
    print(f"Decrypted message: '{message}'\n")

if __name__ == "__main__":
    while True:
        print("=== Rubik's Cube Cipher (256-bit Key) ===")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("Select an option (1-3): ").strip()
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid option. Please select 1-3.\n")