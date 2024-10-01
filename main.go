package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

// DecryptAES decrypts data using a given AES key and ciphertext.
func DecryptAES(key, ciphertext []byte) ([]byte, error) { 
    block, err := aes.NewCipher(key) // Create a new AES cipher block with the provided key.
    if err != nil {
        return nil, err
    }
    iv := ciphertext[:aes.BlockSize] // Extract the Initialization Vector (IV).
    ciphertext = ciphertext[aes.BlockSize:] // Remove the IV from the ciphertext.
    stream := cipher.NewCFBDecrypter(block, iv) // Create a CFB mode decrypter.
    stream.XORKeyStream(ciphertext, ciphertext) // Decrypt the ciphertext.
    return ciphertext, nil // Return the decrypted plaintext.
}

// DecryptAESKeyWithRSA decrypts the AES key using the RSA private key.
func DecryptAESKeyWithRSA(privateKey *rsa.PrivateKey, encryptedKey []byte) ([]byte, error) {
    decryptedKey, err := rsa.DecryptOAEP( // Decrypt the AES key using RSA with OAEP padding.
        crypto.SHA256.New(), // Use SHA-256 for hashing.
        rand.Reader, // Randomness source, required for the function.
        privateKey, // The RSA private key.
        encryptedKey, // The encrypted AES key.
        nil, // Optional label, not used here.
    )
    if err != nil {
        return nil, err // Return any error encountered.
    }
    return decryptedKey, nil // Return the decrypted AES key.
}

func main() {
    // Load RSA private key from file
    privKeyFile, err := os.Open("private.pem") // Open the private key file.
    if err != nil {
        panic(err) // Panic if the file cannot be opened.
    }
    defer privKeyFile.Close() // Ensure the file is closed after use.

    privKeyBytes, _ := ioutil.ReadAll(privKeyFile) // Read the private key file.
    block, _ := pem.Decode(privKeyBytes) // Decode the PEM-encoded private key.

    privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes) // Parse the private key using PKCS#8 format.
    if err != nil {
        panic(err) // Panic if there is an error in parsing the key.
    }

    rsaPrivKey, ok := privKey.(*rsa.PrivateKey) // Assert the parsed key to *rsa.PrivateKey.
    if !ok {
        panic("not an RSA private key") // Panic if the key is not of the expected type.
    }

    // Load and decrypt the AES key.
    encryptedAESKey, err := ioutil.ReadFile("encrypted_aes_key.bin") // Read the encrypted AES key from the file.
    if err != nil {
        panic(err) // Panic if there is an error in reading the key.
    }
    aesKey, err := DecryptAESKeyWithRSA(rsaPrivKey, encryptedAESKey) // Decrypt the AES key.
    if err != nil {
        panic(err) // Panic if there is an error in decrypting the key.
    }

    // Load and decrypt the file data.
    encryptedData, err := ioutil.ReadFile("encrypted_data.bin") // Read the encrypted data from the file.
    if err != nil {
        panic(err) // Panic if there is an error in reading the data.
    }
    plaintext, err := DecryptAES(aesKey, encryptedData) // Decrypt the data using the AES key.
    if err != nil {
        panic(err) // Panic if there is an error in decryption.
    }

    // Save the decrypted file.
    err = ioutil.WriteFile("decrypted_plaintext.txt", plaintext, 0644) // Write the decrypted plaintext to a new file.
    if err != nil {
        panic(err) // Panic if there is an error in writing the file.
    }
}
