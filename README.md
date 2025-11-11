# A 256-Bit Key Multi-Block Permutation Cipher Using Rubik’s Cube State Space


> This is a multi-block permutation cipher that combines the combinatorial state space of the Rubik’s Cube with a cryptographically secure 256-bit random key. The cipher maps a 54-character plaintext block to the cube’s 54 stickers, with encryption performed by applying move sequences derived deterministically from the 256-bit key. Each byte of the key contributes to a canonical Rubik’s Cube move, ensuring that encryption sequences are random yet repeatable for valid decryption. Messages exceeding 54 characters are handled using a multi-block extension with padding. This paper outlines the full algorithmic structure, mathematical representation of cube permutations, and the deterministic key-to-move mapping. A comparative cryptographic analysis demonstrates that the addition of a true random 256-bit key increases key entropy beyond the cube’s original state space limit, thus enhancing the cipher’s theoretical security.


### Check the Research Paper ~~[Here!]()~~
