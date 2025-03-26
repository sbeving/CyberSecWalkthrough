# Malakar's Deception

## ML MALAKAr'S dECEPTION

```python
import base64
import marshal
import dis  # For disassembling bytecode
import sys
import codecs

def decompile_lambda(encoded_code):
    """Decodes and decompiles a base64-encoded Python bytecode object."""
    try:
        decoded_bytes = base64.b64decode(encoded_code)
    except Exception as e:
       print(f"base64 decode error: {e}")
       return

    # Marshal is used to load compiled code objects
    try:
       code_object = marshal.loads(decoded_bytes)
    except Exception as e:
      print(decoded_bytes)
      print(f"marshal load error {e}")
      return

    print("--- Decompiled Code ---")
    dis.dis(code_object)  # Disassemble the bytecode
    print("--- Source Code (Attempt) ---")

    # Try to make an educated guess at the source. This isn't always perfect.
    try:
        # Check if the code object is runnable (like a function)
        if hasattr(code_object, 'co_consts'):
          for const in code_object.co_consts:
             if isinstance(const, str):
                print(const)
             if isinstance(const, bytes):
                try:
                  print(const.decode('utf-8'))
                except:
                  pass
        # Handle case if the result is the code object itself (rare but possible)
        if isinstance(code_object, str):
          print("Extracted String: ", code_object)
          if "flag{" in code_object:
             return
        #If its a code object
        if hasattr(code_object, 'co_code'): #if code object
          #print source code
          decompiled_code = dis.Bytecode(code_object)
          source_code = ""
          # try:
          #  source_code = decompyle3.decompile(decompiled_code)
          #  print(source_code)
          # except Exception as e:
          #   print(f"Decompile failed: {e}") #no good library found

    except Exception as e:
        print(f"Error during decompilation/source reconstruction: {e}")

# --- Extract the encoded code from the previous output ---
encoded_function_code = (
    "4wEAAAAAAAAAAAAAAAQAAAADAAAA8zYAAACXAGcAZAGiAXQBAAAAAAAAAAAAAGQCXAEAAKsBAAAA"
    "AAAAAAB8AGYDZAMZAAAAAAAAAAAAUwApBE4pGulIAAAA6VQAAADpQgAAAOl7AAAA6WsAAADpMwAA"
    "AOlyAAAA6TQAAADpUwAAAOlfAAAA6UwAAAByCQAAAOl5AAAAcgcAAAByCAAAAHILAAAA6TEAAADp"
    "bgAAAOlqAAAAcgcAAADpYwAAAOl0AAAAcg4AAADpMAAAAHIPAAAA6X0AAAB6JnByaW50KCdZb3Vy"
    "IG1vZGVsIGhhcyBiZWVuIGhpamFja2VkIScp6f////8pAdoEZXZhbCkB2gF4cwEAAAAgeh88aXB5"
    "dGhvbi1pbnB1dC02OS0zMjhhYjc5ODJiNGY++gg8bGFtYmRhPnIYAAAADgAAAHM0AAAAgADwAgEJ"
    "SAHwAAEJSAHwAAEJSAHlCAzQDTXRCDbUCDbYCAnwCQUPBvAKAAcJ9AsFDwqAAPMAAAAA"
)
encoded_output_shape_code = (
  "4wEAAAAAAAAAAAAAAAEAAAADAAAA8wYAAACXAHwAUwApAU6pACkB2gFzcwEAAAAgeh88aXB5"
  "dGhvbi1pbnB1dC02OS0zMjhhYjc5ODJiNGY++gg8bGFtYmRhPnIEAAAAFQAAAHMGAAAAgACYMYAA8wAA"
  "AAA="
)

print("Decoding Function Code:")
decompile_lambda(encoded_function_code)
print("\nDecoding Output Shape Code:")
decompile_lambda(encoded_output_shape_code)
```

```
Decoding Function Code:
--- Decompiled Code ---
 14           0 RESUME                   0

 15           2 BUILD_LIST               0
              4 LOAD_CONST               1 ((72, 84, 66, 123, 107, 51, 114, 52, 83, 95, 76, 52, 121, 51, 114, 95, 49, 110, 106, 51, 99, 116, 49, 48, 110, 125))
              6 LIST_EXTEND              1

 17           8 LOAD_GLOBAL              1 (NULL + eval)
             18 CACHE
             20 LOAD_CONST               2 ("print('Your model has been hijacked!')")
             22 UNPACK_SEQUENCE          1
             26 CALL                     1
             34 CACHE

 18          36 LOAD_FAST                0 (x)

 14          38 BUILD_TUPLE              3

 19          40 LOAD_CONST               3 (-1)

 14          42 BINARY_SUBSCR
             46 CACHE
             48 CACHE
             50 CACHE
             52 RETURN_VALUE
--- Source Code (Attempt) ---
print('Your model has been hijacked!')

Decoding Output Shape Code:
--- Decompiled Code ---
 21           0 RESUME                   0
              2 LOAD_FAST                0 (s)
              4 RETURN_VALUE
--- Source Code (Attempt) ---
```

> ```
> ((72, 84, 66, 123, 107, 51, 114, 52, 83, 95, 76, 52, 121, 51, 114, 95, 49, 110, 106, 51, 99, 116, 49, 48, 110, 125))
> ```

IS THE FLAG \
\
HTB{k3r4S\_L4y3r\_1nj3ct10n}
