# Heha3

Title : Heha\
Description : You have to figure this one yourself\
Difficulty : Medium\
Points : 450

Given a data.bin file

Hidden file(s) are within for sure

Let's try searching for hidden png

```python
def extract_png_images(bin_path, output_prefix):
    png_header = b'\x89PNG\r\n\x1a\n'
    png_footer = b'\x00\x00\x00\x00IEND\xAEB`\x82'
    with open(bin_path, "rb") as bin_file:
        bin_data = bin_file.read()

    start = 0
    image_count = 0
    while True:
        start_image = bin_data.find(png_header, start)
        if start_image == -1:
            break

        end_image = bin_data.find(png_footer, start_image) + len(png_footer)
        if end_image == -1:
            break

        image_data = bin_data[start_image:end_image]
        with open(f"{output_prefix}_{image_count + 1}.png", "wb") as img_file:
            img_file.write(image_data)

        start = end_image
        image_count += 1
    print(f"{image_count} PNG images extracted.")

  

bin_path = "data.bin"
output_prefix = "image"

extract_png_images(bin_path, output_prefix)
```

**10 Images was extracted**

<figure><img src="../../../../.gitbook/assets/Pasted image 20250212155532.png" alt=""><figcaption></figcaption></figure>



Assembling the images vertically gave us the flag

<figure><img src="../../../../.gitbook/assets/image_2-min (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image_3-min.png" alt=""><figcaption></figcaption></figure>

Flag : **FL1TZ{th4t\_w4s\_tr1cky\_huhhh}**
