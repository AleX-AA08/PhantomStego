<h3 align="center">PhantomStego — Ultimate Steganography Tool</h3>

<p align="center">Professional cross-platform GUI tool for hiding and extracting any files inside images**  
Supports strong encryption, multiple steganography methods, auto-detection and zero dependencies hassle.</p>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-yellowgreen)

</div>


## Key Features

| Feature                        | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| **EXIF Embedding**            | Hide unlimited data in JPEG EXIF metadata (invisible to most viewers)      |
| **LSB Steganography**         | Classic Least Significant Bit method for PNG/BMP (up to ~25% of image size)|
| **Polyglot Files**            | Universal container with custom magic bytes                                 |
| **PNG Comment Chunk**         | Hide data in official PNG text/comment chunks                               |
| **AES-256 + PBKDF2**          | Military-grade encryption with proper key derivation                       |
| **Multi-Layer Encryption**    | AES → XOR → XOR(reverse key) for extra paranoia                            |
| **Auto-Detection**            | Extract mode automatically tries all methods                               |
| **Polymorphic Markers**       | Random signature to defeat signature-based detection                       |
| **Standalone Encryptor**      | Encrypt/decrypt any file without steganography                              |
| **Zero Install**              | Dependencies auto-installed on first launch                                 |

## Installation

```bash
git clone https://github.com/yourusername/phantomstego.git
cd phantomstego
python phantom_stego.py
```

Legal Disclaimer
This tool is provided strictly for educational, penetration testing, and authorized research purposes.
The author is not responsible for any misuse or illegal activities.

⚠ Warning: This code is for educational purposes and security testing in controlled environments only. Unauthorized use may be illegal.
Thanks for exploring!
