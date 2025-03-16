# The Sleuth Kit: A Comprehensive Guide

The Sleuth Kit (TSK) is a powerful, open-source library and command-line toolset for digital forensics. It's used to analyze disk images, filesystems, and other data storage devices to extract and recover forensic evidence. This document provides a detailed overview of the Sleuth Kit, covering key tools, concepts, and use cases.

## The Sleuth Kit Basics

*   **File System Analysis:** TSK focuses on analyzing the underlying file system structures to explore data and metadata.
*   **Command-Line Tools:** It consists of numerous command-line tools for specific forensic tasks.
*   **Disk Image Support:** It supports various disk image formats, like raw (`dd`) images, EnCase, and others.
*   **Cross-Platform:** TSK is available on multiple platforms like Linux, macOS, and Windows (using WSL).

## Core Sleuth Kit Tools and Concepts

Here's a breakdown of key TSK tools and concepts:

1.  **`mmls`:** Displays the layout of the partitions in a disk image file.
    *   **Use Cases:**
        *   Exploring the partition structure of a hard drive or any other media.
            *   **Example:** `mmls image.dd`
2.  **`fls`:** Lists files and directories in a file system image. You will need to specify partition offset (from `mmls`) to get the right partition.
      * **Use Cases:**
           *   Exploring file systems within disk images.
           *  Check for deleted files using metadata.
              *   **Example:** `fls -o 63 image.dd` (replace 63 with the offset)

3.  **`icat`:** Extracts the contents of a file from a disk image. Useful to dump the contents of a file.
    *   **Use Cases:**
         *  Extract file contents.
            * **Example:** `icat -o 63 image.dd 128 > output.txt` (replace 63 with offset, and 128 with the inode)

4.  **`fsstat`:** Displays file system metadata.
     *  **Use Cases:**
        *  Show file system related information like the type, size, date, etc...
            * **Example:** `fsstat -o 63 image.dd` (replace 63 with the offset)

5.  **`imgstat`:** Displays disk image metadata, like its size or volume size.
     *   **Use Cases:**
        *   Exploring image metadata
           *   **Example:** `imgstat image.dd`
6.  **`istat`:** Displays metadata of a file with a given inode number.
    *   **Use Cases:**
        *  Explore low level details for a file.
            *   **Example:** `istat -o 63 image.dd 128 `(replace 63 with the offset, and 128 with the inode)
7.  **`blkcalc`:** Used to determine the block size from the file system.
      * **Use Cases:** Find the block size of a partition.
            *  **Example:** `blkcalc -o 63 image.dd` (replace 63 with the offset)
8.  **`tsk_gettimes`:** Displays the timestamp of files
   *   **Use Cases:** Get metadata such as creation, modified and access times of a file.
     *  **Example:** `tsk_gettimes -o 63 image.dd 128` (replace 63 with offset, and 128 with the inode)

## Practical Sleuth Kit Examples

1.  **Display partition information from an image:**

    ```bash
    mmls image.dd
    ```

2.  **List files in a specific partition:**
    ```bash
    fls -o 63 image.dd
    ```
    (replace 63 with the appropriate offset)

3.  **Extract content of a file:**

    ```bash
    icat -o 63 image.dd 128 > output.txt
    ```
    (replace 63 with the offset, and 128 with the inode)
4. **Get information about the image:**
  ```bash
    imgstat image.dd
  ```

5. **Get information about the file system:**
   ```bash
      fsstat -o 63 image.dd
   ```
     (replace 63 with the appropriate offset)
6. **Obtain file details using istat:**
  ```bash
  istat -o 63 image.dd 128
  ```
  (replace 63 with the offset, and 128 with the inode)
7. **Calculate the block size of the partition:**
  ```bash
    blkcalc -o 63 image.dd
  ```
(replace 63 with the appropriate offset)
8. **Get file timestamps:**
  ```bash
    tsk_gettimes -o 63 image.dd 128
  ```
   (replace 63 with the offset, and 128 with the inode)

## Use Cases

*   **Digital Forensics:** Analyzing disk images for evidence in criminal or civil investigations.
*   **Incident Response:** Investigating security incidents by analyzing the file systems of compromised systems.
*   **Data Recovery:** Recovering deleted files and data from disk images.
*   **Security Research:** Studying the internals of filesystems and disk structures.

## Conclusion

The Sleuth Kit is a very important set of tools for performing low-level disk analysis. Its low-level operations makes it very good for digital forensics and incident response. Always use this tool responsibly and ethically, only on systems that you are authorized to test.

---