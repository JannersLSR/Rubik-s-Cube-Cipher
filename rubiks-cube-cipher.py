# CUBE CIPHER: MULTI-BLOCK RUBIK'S CUBE ENCRYPTION
# Cube layout: [U, F, R, L, B, D], each 3x3 = 54 total stickers.

# === Core Cube Operations ===

def rotate_face(face):
    """Rotate a 3x3 face clockwise (indices 0..8)."""
    # 0->2, 1->5, 2->8, 3->1, 4->4, 5->7, 6->0, 7->3, 8->6
    return [face[6], face[3], face[0],
            face[7], face[4], face[1],
            face[8], face[5], face[2]]

def rotate_face_ccw(face):
    """Rotate a 3x3 face counterclockwise (indices 0..8)."""
    # 0->6, 1->3, 2->0, 3->7, 4->4, 5->1, 6->8, 7->5, 8->2
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

    # Helper indices for columns/rows:
    TOP = slice(0, 3)
    BOT = slice(6, 9)
    LEFT = [0, 3, 6]
    RIGHT = [2, 5, 8]
    
    # Helper to get/set lists by complex index:
    def get_indices(face, indices):
        return [face[i] for i in indices]
    def set_indices(face, indices, values):
        for i, val in zip(indices, values):
            face[i] = val
        return face

    if notation == "U":
        f["U"] = rotate_face(f["U"])
        # F, R, B, L top rows rotate (No flips needed)
        temp = f["F"][TOP]
        f["F"][TOP], f["R"][TOP], f["B"][TOP], f["L"][TOP] = f["R"][TOP], f["B"][TOP], f["L"][TOP], temp
    elif notation == "U'":
        f["U"] = rotate_face_ccw(f["U"])
        # F, L, B, R top rows rotate (No flips needed)
        temp = f["F"][TOP]
        f["F"][TOP], f["L"][TOP], f["B"][TOP], f["R"][TOP] = f["L"][TOP], f["B"][TOP], f["R"][TOP], temp

    # --- D and D' ---
    elif notation == "D":
        f["D"] = rotate_face(f["D"])
        temp = f["F"][BOT]
        
        # F[6,7,8] <- R[6,7,8] (No flip)
        f["F"][BOT] = f["R"][BOT]
        
        # R[6,7,8] <- B[6,7,8] (Flip needed due to B orientation)
        f["R"][6], f["R"][7], f["R"][8] = f["B"][8], f["B"][7], f["B"][6]
        
        # B[6,7,8] <- L[6,7,8] (Flip needed due to B orientation)
        f["B"][6], f["B"][7], f["B"][8] = f["L"][8], f["L"][7], f["L"][6]

        # L[6,7,8] <- F[6,7,8] (temp - No flip)
        f["L"][BOT] = temp
        
    elif notation == "D'":
        f["D"] = rotate_face_ccw(f["D"])
        temp = f["F"][BOT]

        # F[6,7,8] <- L[6,7,8] (No flip)
        f["F"][BOT] = f["L"][BOT]

        # L[6,7,8] <- B[6,7,8] (Flip needed)
        f["L"][6], f["L"][7], f["L"][8] = f["B"][8], f["B"][7], f["B"][6]
        
        # B[6,7,8] <- R[6,7,8] (Flip needed)
        f["B"][6], f["B"][7], f["B"][8] = f["R"][8], f["R"][7], f["R"][6]

        # R[6,7,8] <- F[6,7,8] (temp - No flip)
        f["R"][BOT] = temp
        
    # --- F and F' ---
    elif notation == "F":
        f["F"] = rotate_face(f["F"])
        temp = get_indices(f["U"], BOT) # U[6, 7, 8]
        
        set_indices(f["U"], BOT, get_indices(f["L"], RIGHT)[::-1]) # U <- L (Flipped: L[8,5,2] -> U[6,7,8])
        set_indices(f["L"], RIGHT, get_indices(f["D"], RIGHT)[::-1]) # L <- D (Flipped: D[2,1,0] -> L[8,5,2])
        set_indices(f["D"], TOP, get_indices(f["R"], LEFT)[::-1])   # D <- R (Flipped: R[6,3,0] -> D[0,1,2])
        set_indices(f["R"], LEFT, temp)                             # R <- U (No flip on indices used: R[0,3,6] <- U[6,7,8])

    elif notation == "F'":
        f["F"] = rotate_face_ccw(f["F"])
        temp = get_indices(f["U"], BOT) # U[6, 7, 8]

        set_indices(f["U"], BOT, get_indices(f["R"], LEFT)) # U <- R (No flip: R[0,3,6] -> U[6,7,8])
        set_indices(f["R"], LEFT, get_indices(f["D"], TOP)[::-1]) # R <- D (Flipped: D[2,1,0] -> R[6,3,0])
        set_indices(f["D"], TOP, get_indices(f["L"], RIGHT)[::-1])# D <- L (Flipped: L[8,5,2] -> D[2,1,0])
        set_indices(f["L"], RIGHT, temp)                         # L <- U (No flip on indices used: L[2,5,8] <- U[6,7,8])

    # --- B and B' ---
    elif notation == "B":
        f["B"] = rotate_face(f["B"])
        temp = get_indices(f["U"], TOP) # U[0, 1, 2]

        set_indices(f["U"], TOP, get_indices(f["L"], LEFT)[::-1]) # U <- L (Flipped: L[6,3,0] -> U[0,1,2])
        set_indices(f["L"], LEFT, get_indices(f["D"], BOT)[::-1]) # L <- D (Flipped: D[8,7,6] -> L[0,3,6])
        set_indices(f["D"], BOT, get_indices(f["R"], RIGHT)[::-1])# D <- R (Flipped: R[8,5,2] -> D[6,7,8])
        set_indices(f["R"], RIGHT, temp)                          # R <- U (No flip: R[2,5,8] <- U[0,1,2])

    elif notation == "B'":
        f["B"] = rotate_face_ccw(f["B"])
        temp = get_indices(f["U"], TOP) # U[0, 1, 2]

        set_indices(f["U"], TOP, get_indices(f["R"], RIGHT)) # U <- R (No flip: R[2,5,8] -> U[0,1,2])
        set_indices(f["R"], RIGHT, get_indices(f["D"], BOT)[::-1])# R <- D (Flipped: D[8,7,6] -> R[8,5,2])
        set_indices(f["D"], BOT, get_indices(f["L"], LEFT)[::-1]) # D <- L (Flipped: L[6,3,0] -> D[6,7,8])
        set_indices(f["L"], LEFT, temp)                           # L <- U (No flip: L[0,3,6] <- U[0,1,2])
        
    # --- R and R' ---
    elif notation == "R":
        f["R"] = rotate_face(f["R"])
        temp = get_indices(f["U"], RIGHT) # U[2, 5, 8]

        set_indices(f["U"], RIGHT, get_indices(f["B"], LEFT)[::-1]) # U <- B (Flipped: B[6,3,0] -> U[2,5,8])
        set_indices(f["B"], LEFT, get_indices(f["D"], RIGHT)[::-1]) # B <- D (Flipped: D[8,5,2] -> B[6,3,0])
        set_indices(f["D"], RIGHT, get_indices(f["F"], RIGHT))      # D <- F (No flip: D[2,5,8] <- F[2,5,8])
        set_indices(f["F"], RIGHT, temp)                            # F <- U (No flip: F[2,5,8] <- U[2,5,8])

    elif notation == "R'":
        f["R"] = rotate_face_ccw(f["R"])
        temp = get_indices(f["U"], RIGHT) # U[2, 5, 8]

        set_indices(f["U"], RIGHT, get_indices(f["F"], RIGHT))     # U <- F (No flip: U[2,5,8] <- F[2,5,8])
        set_indices(f["F"], RIGHT, get_indices(f["D"], RIGHT))     # F <- D (No flip: F[2,5,8] <- D[2,5,8])
        set_indices(f["D"], RIGHT, get_indices(f["B"], LEFT)[::-1])# D <- B (Flipped: B[0,3,6] -> D[8,5,2])
        set_indices(f["B"], LEFT, temp[::-1])                      # B <- U (Flipped: B[0,3,6] <- U[8,5,2])

    # --- L and L' ---
    elif notation == "L":
        f["L"] = rotate_face(f["L"])
        temp = get_indices(f["U"], LEFT) # U[0, 3, 6]

        set_indices(f["U"], LEFT, get_indices(f["F"], LEFT))      # U <- F (No flip: U[0,3,6] <- F[0,3,6])
        set_indices(f["F"], LEFT, get_indices(f["D"], LEFT))      # F <- D (No flip: F[0,3,6] <- D[0,3,6])
        set_indices(f["D"], LEFT, get_indices(f["B"], RIGHT)[::-1]) # D <- B (Flipped: B[2,5,8] -> D[6,3,0])
        set_indices(f["B"], RIGHT, temp[::-1])                     # B <- U (Flipped: B[8,5,2] <- U[6,3,0])

    elif notation == "L'":
        f["L"] = rotate_face_ccw(f["L"])
        temp = get_indices(f["U"], LEFT) # U[0, 3, 6]

        set_indices(f["U"], LEFT, get_indices(f["B"], RIGHT)[::-1]) # U <- B (Flipped: B[8,5,2] -> U[0,3,6])
        set_indices(f["B"], RIGHT, get_indices(f["D"], LEFT)[::-1]) # B <- D (Flipped: D[6,3,0] -> B[8,5,2])
        set_indices(f["D"], LEFT, get_indices(f["F"], LEFT))      # D <- F (No flip: D[0,3,6] <- F[0,3,6])
        set_indices(f["F"], LEFT, temp)                           # F <- U (No flip: F[0,3,6] <- U[0,3,6])

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
                    # Use ord() to chr() conversion
                    char_val = chr(face[idx])
                else:
                    char_val = str(face[idx])
                row += char_val + " "
            print(row)
        print()

# === Multi-Block Encryption/Decryption Approach (Visuals Restored) ===

def encrypt_message():
    """Encrypts a plaintext message of any length using 54-character blocks."""
    plaintext = input("Enter plaintext: ").strip()
    
    # Split plaintext into 54-char blocks and pad the last one
    block_size = 54
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    
    # Pad the last block with '~'
    last_block = blocks[-1]
    padded_last_block = last_block + ('~' * (block_size - len(last_block)))
    blocks[-1] = padded_last_block
    
    key_moves = input("Enter key moves (e.g. U R L F D'): ").strip()
    
    encrypted_blocks = []
    
    print("\n--- Encryption Process ---")
    for i, block in enumerate(blocks):
        print(f"\nProcessing Block {i+1} of {len(blocks)}...")
        
        ascii_block = [ord(c) for c in block]
        
        # Print original block state
        print(f"Original Block {i+1}:")
        print_cube(ascii_block)
        
        # Apply encryption moves
        encrypted = apply_moves(ascii_block[:], key_moves)
        
        # Convert to string and store
        encrypted_string = "".join([chr(c) for c in encrypted])
        encrypted_blocks.append(encrypted_string)
        
        # Print encrypted block state
        print(f"Encrypted Block {i+1}:")
        print_cube(encrypted)

    final_ciphertext = "".join(encrypted_blocks)
    
    print("--------------------------")
    print(f"Encrypted message (Total {len(final_ciphertext)} chars):")
    print(f"'{final_ciphertext}'")
    print()

def decrypt_message():
    """Decrypts a ciphertext generated by the multi-block cipher."""
    ciphertext = input("Enter full ciphertext: ").strip()
    
    block_size = 54
    if len(ciphertext) % block_size != 0:
        print(f"Error: Ciphertext length ({len(ciphertext)}) must be a multiple of {block_size}.")
        return
    
    key_moves = input("Enter key moves (same as encryption): ").strip()
    inverted_moves = invert_moves(key_moves)
    
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []
    
    print(f"\nApplying inverted moves: {inverted_moves}")
    print("\n--- Decryption Process ---")
    
    for i, block in enumerate(blocks):
        print(f"\nProcessing Block {i+1} of {len(blocks)}...")
        
        ascii_block = [ord(c) for c in block]
        
        # Print encrypted block state (the input to this step)
        print(f"Encrypted Block {i+1} (Input):")
        print_cube(ascii_block)
        
        # Apply inverted moves
        decrypted = apply_moves(ascii_block[:], inverted_moves)
        
        # Print decrypted block state
        print(f"Decrypted Block {i+1} (Output):")
        print_cube(decrypted)
        
        # Convert to string and store
        decrypted_blocks.append("".join([chr(c) for c in decrypted]))

    # Join all blocks and remove trailing padding from the *very last* character set
    full_decrypted_string = "".join(decrypted_blocks)
    decrypted_message = full_decrypted_string.rstrip('~')
    
    print("--------------------------")
    print(f"Decrypted message: '{decrypted_message}'")
    print()

# === Main Menu Loop ===

if __name__ == "__main__":
    while True:
        print("=== Rubik's Cube Cipher (Multi-Block) ===")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        
        choice = input("Select an option (1-3): ").strip()
        
        if choice == "1":
            encrypt_message()
        elif choice == "2":
            decrypt_message()
        elif choice == "3":
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid option. Please select 1, 2, or 3.\n")