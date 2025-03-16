---
description: >-
  Alice encodes a picture into a shared entangled state and shares her quantum
  operations. Bob needs to reconstruct the image on his computer using this
  information.
---

# QThumbnail

<figure><img src="../../../../../.gitbook/assets/Pasted image 20250314182146.png" alt=""><figcaption></figcaption></figure>

### info.txt

```info.txt
ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX ZX I I I I I I I I ZX ZX ZX ZX ZX ZX ZX ZX...
```

The `info.txt` file contains a long sequence of "ZX" and "I" strings. These represent quantum gates. "ZX" likely corresponds to a quantum operation, and "I" represents the identity gate (no operation). Based on the earlier analysis of this challenge and the shape of the image found we can try different widths until we see something.

#### Solution Strategy

The core strategy is to interpret the "ZX" and "I" gates as black and white pixels, respectively, and reconstruct the image using PIL (Pillow).

**Step 1: Refined Code with Logging**

```python
from PIL import Image
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("solver.log"),
        logging.StreamHandler()
    ]
)

def solve(width):
    logging.info(f"Starting solving process with width={width}")
    try:
        with open("info.txt", "r") as f:
            gates = f.read().split()
            logging.debug(f"Read {len(gates)} gates from info.txt")
    except FileNotFoundError:
        logging.error("info.txt file not found")
        return
    except Exception as e:
        logging.error(f"Error reading info.txt: {e}")
        return

    num_pixels = len(gates)
    # width = 200 # Try a reasonable width based on the image hints

    if num_pixels % width != 0:
        logging.error(f"Error: Number of gates ({num_pixels}) is not divisible by width ({width}).")
        return

    height = num_pixels // width
    logging.info(f"Image size: {width}x{height}")

    # Create image data (0 = black, 255 = white)
    image_data = []
    for gate in gates:
        if gate == "ZX":
            image_data.append(0)  # Black
        elif gate == "I":
            image_data.append(255)  # White
        else:
            logging.error(f"Unknown gate: {gate}")
            return
    
    logging.debug(f"Created image data with {len(image_data)} pixels")

    # Reshape the data into a 2D array
    pixels = [image_data[i * width:(i + 1) * width] for i in range(height)]
    logging.debug("Reshaped data into 2D array")

    # Create a PIL image
    img = Image.new("L", (width, height))  # "L" mode for grayscale
    for y in range(height):
        for x in range(width):
            img.putpixel((x, y), pixels[y][x])
    
    output_filename = f"output_{width}.png"
    try:
        img.save(output_filename)
        logging.info(f"Image successfully saved to {output_filename}")
    except Exception as e:
        logging.error(f"Failed to save image: {e}")

if __name__ == "__main__":
    logging.info("Script started")
    # You can add code here to try different widths
    solve(200)  # Default width to try
    logging.info("Script completed")
```

**Explanation:**

1. **Logging:** Added comprehensive logging using the `logging` module. This helps track the script's execution, identify errors, and debug the process. Logging levels (INFO, DEBUG, ERROR) provide different levels of detail. The logging will be sent to both the console and to a file `solver.log`.
2. **File Handling:** Includes checks and error handling for reading `info.txt`.
3. **Image Dimensions:** Attempts to determine image dimensions automatically based on the number of gates. Since no automatic method was successful the `width` was changed manually by multiple runs to check image outputs.
4. **Pixel Data:** Interprets 'ZX' as black (0) and 'I' as white (255) pixels.
5. **Reshape:** Reshapes the pixel data into a 2D array representing the image.
6. **Create Image:** Uses PIL (`Image.new` and `putpixel`) to create a grayscale image from the pixel data.
7. **Save Image:** Saves the image to a file.

**Step 3: Running the Code and Analyzing the Output**

Running the code with a `width` of 200 (as shown in the code snippet you provided) generated an image file.

```log
PS C:\Users\saleh\Downloads\CTFKareemSecurinetsTekup\qt> python .\solver.py
2025-03-15 01:37:39,056 - INFO - Script started
2025-03-15 01:37:39,056 - INFO - Starting solving process with width=200
2025-03-15 01:37:39,057 - INFO - Image size: 200x100
2025-03-15 01:37:39,087 - INFO - Image successfully saved to output_200.png
2025-03-15 01:37:39,087 - INFO - Script completed
```

<figure><img src="../../../../../.gitbook/assets/output_200.png" alt=""><figcaption></figcaption></figure>

I got to look at the QR code and by scanning using a phone scanner was able to obtain the correct flag.

#### Flag

The flag is: `Securinets{Sup1r_Qub1t}`.



\
\
