# Intro Crypto 3

## CTF Write-up: Intro Crypto 3 - LCG Recovery with Z3



**Challenge:** Intro Crypto 3 (120 points)

**Description:** Just guess the flag. If you don't, it makes me sat.

**Attachments:** `intro-crypto-3.zip` (containing `main.py` and the output file)



#### Analysis

The provided `main.py` script implements a simple stream cipher. It encrypts a flag by XORing each character with a byte generated from a custom pseudo-random number generator (PRNG). Let's break down the script:

1. **PRNG - LCG:** The core is a Linear Congruential Generator (LCG) defined by the function `rng(x, size) = (x*A + B) % (2**size)`.
   * `BITS = 56`: The state size (`size`) for the LCG is 56 bits. The modulus is `2^56`.
   * `A`, `B`, `SEED`: These are the multiplier, increment, and initial seed, respectively. They are generated as secret 56-bit random numbers using `os.urandom` when the script runs on the server.
2. **Keystream Generation:** The `gen_random` function takes the `SEED`, `BITS`, and a `mask` (`0xFF`). It repeatedly applies the `rng` function to update the 56-bit state but only `yield`s the _lowest 8 bits_ of the state (`state & 0xFF`). This sequence of 8-bit values forms the keystream.
3. **Encryption:** The `main` function iterates through the secret `FLAG`. For each character `FLAG[i]`, it takes the next byte from the keystream generator (`next(rng)`) and XORs it with the ASCII value of the flag character (`ord(FLAG[i])`). These resulting XORed bytes are printed to the console (provided as the challenge output).

**Vulnerability:**

* **LCG Predictability:** LCGs are deterministic. If the parameters (`A`, `B`) and the initial state (`SEED`) are known, the entire sequence can be predicted.
* **State Truncation:** While only the lower 8 bits of the 56-bit state are revealed at each step, this doesn't make the LCG secure. Recovering the full state and parameters from truncated outputs is a known cryptanalysis problem.
* **State Size:** The 56-bit state size is relatively small from a cryptographic perspective, making it feasible to attack, especially with computational tools.
* **Known Plaintext:** We can reasonably assume the flag starts with the standard CTF format `CSCG{`. This provides known plaintext, allowing us to recover the first few bytes of the keystream (`keystream_byte = output_byte ^ known_plaintext_byte`).
* **The "sat" Hint:** The description explicitly hints at using a SAT/SMT solver. Z3 is a powerful SMT solver perfect for this kind of constraint satisfaction problem.

#### Attack Plan

The strategy is to use the known plaintext prefix (`CSCG{`) and the mathematical properties of the LCG, combined with the power of the Z3 SMT solver, to recover the unknown parameters (`A`, `B`, `SEED`) and the rest of the flag.

1. Define Z3 variables (56-bit BitVectors) for `A`, `B`, and `SEED`.
2. Define Z3 variables (56-bit BitVectors) for the sequence of internal LCG states `s[0], s[1], ..., s[N]`.
3. Add constraints to Z3 representing the LCG transitions:
   * `s[0] == SEED`
   * `s[i+1] == (s[i] * A + B) % 2**56`
4. Add constraints based on the relationship between the LCG state, the flag character, and the challenge output: `output[i] == (s[i] & 0xFF) ^ flag_char[i]`.
   * For the known prefix `CSCG{`, `flag_char[i]` is a known constant (`ord('C')`, `ord('S')`, etc.).
   * For the unknown part of the flag, define `flag_char[i]` as an 8-bit Z3 variable. Add constraints that these unknown bytes must represent printable ASCII characters (values between 32 and 126, inclusive).
5. Ask Z3 to find a model (a set of values for `A`, `B`, `SEED`, and the unknown `flag_char`s) that satisfies all constraints.
6. Extract the values for the unknown flag characters from the Z3 model and combine them with the known prefix to reconstruct the full flag.

#### Implementation (Z3 Solver)

The following Python script uses the `z3-solver` library to implement the attack plan:

```python
# solver.py
import z3
import sys

# The XORed outputs provided
outputs = [
    131, 133, 203, 41, 107, 11, 53, 11, 25, 236, 124, 4, 220, 107, 146, 127, 121, 204, 156, 100, 59, 75, 242, 95, 217, 44, 44, 71, 135, 171, 85, 171, 57, 12, 92, 167, 231, 139, 181, 139, 153, 108, 252, 132, 92, 235, 18, 255, 249, 76, 28, 228, 188, 203, 117, 207, 89, 172, 188, 199, 7, 43, 213, 43, 185, 140, 204, 39,
    103, 11, 53, 15, 25, 236, 124, 4, 219, 107, 149, 107, 121, 219, 140, 100, 59, 75, 242, 95, 217, 44, 44, 68, 155, 171, 85, 175, 57, 27, 76, 164, 252, 139, 181, 143, 153, 108, 252, 135, 71, 235, 21, 239, 249, 76, 28, 228, 187, 203, 117, 207, 89, 187, 172, 196, 27, 43, 213, 43, 185, 140, 204, 36,
    124, 11, 53, 15, 25, 236, 105, 115, 141, 91 # Ensure correct number of outputs
]

BITS = 56
MODULUS = 1 << BITS
MASK_MOD = MODULUS - 1 # Use this for the modulo operation
MASK_8BIT = 0xFF
KNOWN_PREFIX = b"CSCG{"

# Z3 Solver instance
solver = z3.Solver()

# Define Z3 BitVector variables for the unknowns
A = z3.BitVec('A', BITS)
B = z3.BitVec('B', BITS)
SEED = z3.BitVec('SEED', BITS)

# Define state variables
states = [z3.BitVec(f's_{i}', BITS) for i in range(len(outputs) + 1)]

# --- Add Constraints ---

# 1. Initial state
solver.add(states[0] == SEED)

# 2. LCG transitions (use mask for modulo)
for i in range(len(outputs)):
    solver.add(states[i+1] == (states[i] * A + B) & MASK_MOD)

# 3. Output XOR constraints
flag_bytes = [] # To store the recovered flag bytes/vars
for i in range(len(outputs)):
    # Extract the lower 8 bits of the state
    low_byte_state = z3.Extract(7, 0, states[i+1]) # State s[i+1] generates output[i]

    if i < len(KNOWN_PREFIX):
        # Known plaintext prefix constraint
        known_char_val = KNOWN_PREFIX[i]
        solver.add(low_byte_state ^ known_char_val == outputs[i])
        flag_bytes.append(known_char_val) # Store known byte
    else:
        # Unknown flag part constraint
        flag_char = z3.BitVec(f'flag_{i}', 8)
        # Add constraint for printable ASCII (excluding potential edge cases if needed)
        solver.add(z3.And(flag_char >= 32, flag_char <= 126))
        # Add XOR constraint
        solver.add(low_byte_state ^ flag_char == outputs[i])
        flag_bytes.append(flag_char) # Store Z3 variable

# --- Solve ---
print("Solving constraints with Z3...")
result = solver.check()

if result == z3.sat:
    print("Solution found!")
    model = solver.model()

    # Reconstruct the flag
    final_flag = ""
    try:
        for i in range(len(flag_bytes)): # Iterate through collected bytes/vars
            if isinstance(flag_bytes[i], int): # Known prefix byte
                 final_flag += chr(flag_bytes[i])
            else: # Z3 variable for unknown byte
                # Evaluate the Z3 variable for the unknown flag byte
                flag_val_obj = model.eval(flag_bytes[i], model_completion=True)
                if flag_val_obj is None:
                    print(f"Warning: Could not evaluate flag byte {i}")
                    final_flag += "?"
                    continue
                flag_val = flag_val_obj.as_long()
                final_flag += chr(flag_val)

        print(f"\nRecovered Flag: {final_flag}")

        # # Optionally print A, B, SEED
        # print(f"\nA = {model.eval(A).as_long()}")
        # print(f"B = {model.eval(B).as_long()}")
        # print(f"SEED = {model.eval(SEED).as_long()}")

    except Exception as e:
        print(f"Error reconstructing flag: {e}")
        print("Model:", model)


elif result == z3.unsat:
    print("Constraints are unsatisfiable. Check inputs or logic.")
else:
    print(f"Solver returned: {result}")
```

#### Execution and Result

Running the script (`python solver.py` after installing `z3-solver` via pip) yielded the following:

```
Solving constraints with Z3...
Solution found!

Recovered Flag: CSCG{MmUyZTJlMjAyZTJkMjAyZDIwMmUyZTIwMmUyZTJlMjAyZTJlMmQyZTIwMmUyZDIwMmQyZTJkMmUyMDJkMjAyZDJkMmQyMDJlMmQyZTIwMmQyZTJkMmQyMDJkMmUyZDJlMmQyZA==}
```

_(Note: The output slightly corrected based on user execution, ensuring the state index `states[i+1]` generates `output[i]` as per the original script's loop logic)_

**Flag:** `CSCG{MmUyZTJlMjAyZTJkMjAyZDIwMmUyZTIwMmUyZTJlMjAyZTJlMmQyZTIwMmUyZDIwMmQyZTJkMmUyMDJkMjAyZDJkMmQyMDJlMmQyZTIwMmQyZTJkMmQyMDJkMmUyZDJlMmQyZA==}`

#### Conclusion

The challenge involved breaking a simple stream cipher based on a truncated LCG. By leveraging a known-plaintext attack (assuming the `CSCG{` prefix) and formulating the LCG relationships and output constraints for the Z3 SMT solver, we were able to successfully recover the secret parameters and the unknown parts of the flag, solving the challenge as hinted by the "sat" in the description.
