# 🧩 Rubik's Cube Cipher System

# Author: You :)

# Cube layout: [U, F, R, L, B, D], each 3x3 = 54 total stickers.

# === Core Cube Operations ===

def rotate_face(face):
    """Rotate a 3x3 face clockwise."""
    return [face[6], face[3], face[0],
            face[7], face[4], face[1],
            face[8], face[5], face[2]]

def rotate_face_ccw(face):
    """Rotate a 3x3 face counterclockwise."""
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
    """Apply a single Rubik's Cube move."""
    f = split_into_faces(cube)

    if notation == "U":
        f["U"] = rotate_face(f["U"])
        temp = f["F"][:3]
        f["F"][:3], f["R"][:3], f["B"][:3], f["L"][:3] = f["R"][:3], f["B"][:3], f["L"][:3], temp
    elif notation == "U'":
        f["U"] = rotate_face_ccw(f["U"])
        temp = f["F"][:3]
        f["F"][:3], f["L"][:3], f["B"][:3], f["R"][:3] = f["L"][:3], f["B"][:3], f["R"][:3], temp
    elif notation == "D":
        f["D"] = rotate_face(f["D"])
        temp = f["F"][6:9]
        f["F"][6:9], f["L"][6:9], f["B"][6:9], f["R"][6:9] = f["L"][6:9], f["B"][6:9], f["R"][6:9], temp
    elif notation == "D'":
        f["D"] = rotate_face_ccw(f["D"])
        temp = f["F"][6:9]
        f["F"][6:9], f["R"][6:9], f["B"][6:9], f["L"][6:9] = f["R"][6:9], f["B"][6:9], f["L"][6:9], temp
    elif notation == "F":
        f["F"] = rotate_face(f["F"])
        temp = [f["U"][6], f["U"][7], f["U"][8]]
        f["U"][6], f["U"][7], f["U"][8] = f["L"][8], f["L"][5], f["L"][2]
        f["L"][2], f["L"][5], f["L"][8] = f["D"][2], f["D"][1], f["D"][0]
        f["D"][0], f["D"][1], f["D"][2] = f["R"][6], f["R"][3], f["R"][0]
        f["R"][0], f["R"][3], f["R"][6] = temp
    elif notation == "F'":
        f["F"] = rotate_face_ccw(f["F"])
        temp = [f["U"][6], f["U"][7], f["U"][8]]
        f["U"][6], f["U"][7], f["U"][8] = f["R"][0], f["R"][3], f["R"][6]
        f["R"][0], f["R"][3], f["R"][6] = f["D"][2], f["D"][1], f["D"][0]
        f["D"][0], f["D"][1], f["D"][2] = f["L"][8], f["L"][5], f["L"][2]
        f["L"][2], f["L"][5], f["L"][8] = temp
    elif notation == "B":
        f["B"] = rotate_face(f["B"])
        temp = [f["U"][0], f["U"][1], f["U"][2]]
        f["U"][0], f["U"][1], f["U"][2] = f["R"][2], f["R"][5], f["R"][8]
        f["R"][2], f["R"][5], f["R"][8] = f["D"][8], f["D"][7], f["D"][6]
        f["D"][6], f["D"][7], f["D"][8] = f["L"][0], f["L"][3], f["L"][6]
        f["L"][0], f["L"][3], f["L"][6] = temp
    elif notation == "B'":
        f["B"] = rotate_face_ccw(f["B"])
        temp = [f["U"][0], f["U"][1], f["U"][2]]
        f["U"][0], f["U"][1], f["U"][2] = f["L"][0], f["L"][3], f["L"][6]
        f["L"][0], f["L"][3], f["L"][6] = f["D"][6], f["D"][7], f["D"][8]
        f["D"][6], f["D"][7], f["D"][8] = f["R"][2], f["R"][5], f["R"][8]
        f["R"][2], f["R"][5], f["R"][8] = temp
    elif notation == "R":
        f["R"] = rotate_face(f["R"])
        temp = [f["U"][2], f["U"][5], f["U"][8]]
        f["U"][2], f["U"][5], f["U"][8] = f["F"][2], f["F"][5], f["F"][8]
        f["F"][2], f["F"][5], f["F"][8] = f["D"][2], f["D"][5], f["D"][8]
        f["D"][2], f["D"][5], f["D"][8] = f["B"][6], f["B"][3], f["B"][0]
        f["B"][0], f["B"][3], f["B"][6] = temp
    elif notation == "R'":
        f["R"] = rotate_face_ccw(f["R"])
        temp = [f["U"][2], f["U"][5], f["U"][8]]
        f["U"][2], f["U"][5], f["U"][8] = f["B"][0], f["B"][3], f["B"][6]
        f["B"][0], f["B"][3], f["B"][6] = f["D"][8], f["D"][5], f["D"][2]
        f["D"][2], f["D"][5], f["D"][8] = f["F"][2], f["F"][5], f["F"][8]
        f["F"][2], f["F"][5], f["F"][8] = temp
    elif notation == "L":
        f["L"] = rotate_face(f["L"])
        temp = [f["U"][0], f["U"][3], f["U"][6]]
        f["U"][0], f["U"][3], f["U"][6] = f["B"][8], f["B"][5], f["B"][2]
        f["B"][2], f["B"][5], f["B"][8] = f["D"][6], f["D"][3], f["D"][0]
        f["D"][0], f["D"][3], f["D"][6] = f["F"][0], f["F"][3], f["F"][6]
        f["F"][0], f["F"][3], f["F"][6] = temp
    elif notation == "L'":
        f["L"] = rotate_face_ccw(f["L"])
        temp = [f["U"][0], f["U"][3], f["U"][6]]
        f["U"][0], f["U"][3], f["U"][6] = f["F"][0], f["F"][3], f["F"][6]
        f["F"][0], f["F"][3], f["F"][6] = f["D"][0], f["D"][3], f["D"][6]
        f["D"][0], f["D"][3], f["D"][6] = f["B"][8], f["B"][5], f["B"][2]
        f["B"][2], f["B"][5], f["B"][8] = temp

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
    faces = split_into_faces(cube)
    for name, face in faces.items():
        print(f"{name} face:")
        print(f"{face[0]} {face[1]} {face[2]}")
        print(f"{face[3]} {face[4]} {face[5]}")
        print(f"{face[6]} {face[7]} {face[8]}")
        print()

# === Main Cipher Logic ===

if __name__ == "__main__":

    # Input plaintext and convert to ASCII using ord()
    plaintext = input("Enter plaintext (max 54 chars): ").strip()[:54]
    ascii_plaintext = [ord(c) for c in plaintext]

    # If the string is shorter than 54 characters, pad with ord('_') (underscore)
    ascii_plaintext.extend([ord('_')] * (54 - len(ascii_plaintext)))

    key_moves = input("Enter key moves (e.g. U R' L F D'): ").strip()

    # Display original cube
    cube = ascii_plaintext

    print("\n--- Original Cube ---")
    print_cube(cube)

    # Encrypt
    encrypted = apply_moves(cube[:], key_moves)
    
    print("--- After Encryption ---")
    print_cube(encrypted)
    
    # Convert the encrypted list back to characters (excluding underscores)
    encrypted_message = "".join([chr(c) for c in encrypted if c != ord('_')])
    print("Encrypted message:", encrypted_message)

    # Decrypt (WALA MUNA)
    # decrypted = apply_moves(encrypted[:], invert_moves(key_moves))
    # print("--- After Decryption ---")
    # print_cube(decrypted)
    # decrypted_message = "".join([chr(c) for c in decrypted if c != ord('_')])
    # print("Decrypted message:", decrypted_message)
