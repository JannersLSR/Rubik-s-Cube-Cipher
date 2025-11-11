# CUBE CIPHER: MULTI-BLOCK RUBIK'S CUBE ENCRYPTION WITH 256-BIT KEY
# Cube layout: [U, F, R, L, B, D], each 3x3 = 54 total stickers.

import os
import secrets

# === Core Cube Operations ===

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
        if m.endswith("'"):
            inverted.append(m[:-1])
        else:
            inverted.append(m + "'")
    return " ".join(inverted)

# === 256-bit Key Generation and Derivation ===

def generate_256bit_key():
    """Generate a cryptographically secure 256-bit (32-byte) random key."""
    return secrets.token_bytes(32)

def key_to_hex(key):
    """Convert key bytes to hexadecimal string."""
    return key.hex()

def hex_to_key(hex_string):
    """Convert hexadecimal string back to key bytes."""
    return bytes.fromhex(hex_string)

def derive_moves_from_key(key, num_moves=20):
    """
    Derive a sequence of Rubik's Cube moves from a 256-bit key.
    Uses each byte of the key to deterministically generate moves.
    """
    moves_list = ["U", "U'", "D", "D'", "F", "F'", "B", "B'", "R", "R'", "L", "L'"]
    
    # Expand key using a simple deterministic expansion if we need more bytes
    extended_key = key
    while len(extended_key) < num_moves:
        # Simple expansion: XOR with rotated version
        extended_key = extended_key + bytes([b ^ extended_key[i % len(key)] for i, b in enumerate(extended_key)])
    
    # Derive moves from key bytes
    derived_moves = []
    for i in range(num_moves):
        move_index = extended_key[i] % len(moves_list)
        derived_moves.append(moves_list[move_index])
    
    return " ".join(derived_moves)

# === Visualization ===

def print_cube(cube):
    """Prints the state of a 54-sticker cube in a readable format."""
    faces = split_into_faces(cube)
    for name, face in faces.items():
        print(f"{name} face:")
        for i in range(3):
            row = ""
            for j in range(3):
                idx = i * 3 + j
                if isinstance(face[idx], int):
                    char_val = chr(face[idx])
                else:
                    char_val = str(face[idx])
                row += char_val + " "
            print(row)
        print()

# === Multi-Block Encryption/Decryption ===

def encrypt_message():
    """Encrypts a plaintext message using a 256-bit key."""
    plaintext = input("Enter plaintext: ").strip()
    
    block_size = 54
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    
    last_block = blocks[-1]
    padded_last_block = last_block + ('~' * (block_size - len(last_block)))
    blocks[-1] = padded_last_block
    
    # Generate 256-bit key
    key = generate_256bit_key()
    key_hex = key_to_hex(key)
    
    print(f"\n=== GENERATED 256-BIT KEY ===")
    print(f"Key (hex): {key_hex}")
    print(f"Key length: {len(key)} bytes ({len(key) * 8} bits)")
    print("=" * 50)
    
    # Derive moves from key
    key_moves = derive_moves_from_key(key, num_moves=20)
    print(f"\nDerived moves from key: {key_moves}")
    print(f"Number of moves: {len(key_moves.split())}")
    
    encrypted_blocks = []
    
    print("\n--- Encryption Process ---")
    for i, block in enumerate(blocks):
        print(f"\nProcessing Block {i+1} of {len(blocks)}...")
        
        ascii_block = [ord(c) for c in block]
        
        print(f"Original Block {i+1}:")
        print_cube(ascii_block)
        
        encrypted = apply_moves(ascii_block[:], key_moves)
        
        encrypted_string = "".join([chr(c) for c in encrypted])
        encrypted_blocks.append(encrypted_string)
        
        print(f"Encrypted Block {i+1}:")
        print_cube(encrypted)

    final_ciphertext = "".join(encrypted_blocks)
    
    print("--------------------------")
    print(f"Encrypted message (Total {len(final_ciphertext)} chars):")
    print(f"'{final_ciphertext}'")
    print(f"\n🔑  SAVE THIS KEY TO DECRYPT: {key_hex}")
    print()

def decrypt_message():
    """Decrypts a ciphertext using the 256-bit key."""
    ciphertext = input("Enter full ciphertext: ").strip()
    
    block_size = 54
    if len(ciphertext) % block_size != 0:
        print(f"Error: Ciphertext length ({len(ciphertext)}) must be a multiple of {block_size}.")
        return
    
    # Get key from user
    key_hex = input("Enter 256-bit key (64 hex characters): ").strip()
    
    try:
        key = hex_to_key(key_hex)
        if len(key) != 32:
            print(f"Error: Key must be exactly 32 bytes (256 bits). Received {len(key)} bytes.")
            return
    except ValueError:
        print("Error: Invalid hexadecimal key format.")
        return
    
    # Derive moves from key
    key_moves = derive_moves_from_key(key, num_moves=20)
    print(f"\nDerived moves from key: {key_moves}")
    
    inverted_moves = invert_moves(key_moves)
    
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []
    
    print(f"Applying inverted moves: {inverted_moves}")
    print("\n--- Decryption Process ---")
    
    for i, block in enumerate(blocks):
        print(f"\nProcessing Block {i+1} of {len(blocks)}...")
        
        ascii_block = [ord(c) for c in block]
        
        print(f"Encrypted Block {i+1} (Input):")
        print_cube(ascii_block)
        
        decrypted = apply_moves(ascii_block[:], inverted_moves)
        
        print(f"Decrypted Block {i+1} (Output):")
        print_cube(decrypted)
        
        decrypted_blocks.append("".join([chr(c) for c in decrypted]))

    full_decrypted_string = "".join(decrypted_blocks)
    decrypted_message = full_decrypted_string.rstrip('~')
    
    print("--------------------------")
    print(f"Decrypted message: '{decrypted_message}'")
    print()

def manual_mode():
    """Allow users to manually enter moves (original functionality)."""
    print("\n=== Manual Mode (Use Custom Moves) ===")
    plaintext = input("Enter plaintext: ").strip()
    
    block_size = 54
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    
    last_block = blocks[-1]
    padded_last_block = last_block + ('~' * (block_size - len(last_block)))
    blocks[-1] = padded_last_block
    
    key_moves = input("Enter key moves (e.g. U R L F D'): ").strip()
    
    encrypted_blocks = []
    
    print("\n--- Encryption Process ---")
    for i, block in enumerate(blocks):
        print(f"\nProcessing Block {i+1} of {len(blocks)}...")
        
        ascii_block = [ord(c) for c in block]
        encrypted = apply_moves(ascii_block[:], key_moves)
        encrypted_string = "".join([chr(c) for c in encrypted])
        encrypted_blocks.append(encrypted_string)

    final_ciphertext = "".join(encrypted_blocks)
    
    print("--------------------------")
    print(f"Encrypted message: '{final_ciphertext}'")
    print()

# === Main Menu Loop ===

if __name__ == "__main__":
    while True:
        print("=== Rubik's Cube Cipher (256-bit Key) ===")
        print("1. Encrypt (Auto-generate 256-bit key)")
        print("2. Decrypt (Using 256-bit key)")
        print("3. Manual Mode (Custom moves)")
        print("4. Exit")
        
        choice = input("Select an option (1-4): ").strip()
        
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            manual_mode()
        elif choice == "4":
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid option. Please select 1-4.\n")