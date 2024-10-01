# AES Encryption and Decryption with RSA Key Management

This project implements AES encryption and decryption using RSA for secure key management. It demonstrates how to encrypt sensitive data with an AES key, which is itself encrypted using RSA. 

## Features

- **AES Encryption**: Securely encrypts data using a symmetric AES key.
- **RSA Key Management**: Uses RSA to encrypt and decrypt the AES key, ensuring secure handling of encryption keys.
- **File Handling**: Loads, encrypts, and decrypts data from files.

## File Structure

- `main.go`: The main application containing encryption and decryption logic.
- `encrypted_aes_key.bin`: The AES key encrypted with RSA (for demonstration).
- `encrypted_data.bin`: Sample encrypted data (for demonstration).
- `decrypted_plaintext.txt`: Output file for decrypted data.
