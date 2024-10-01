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

// DecryptAES decrypts data using AES with a given key.
func DecryptAES(key, ciphertext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]
    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)
    return ciphertext, nil
}

// DecryptAESKeyWithRSA decrypts the AES key with an RSA private key.
func DecryptAESKeyWithRSA(privateKey *rsa.PrivateKey, encryptedKey []byte) ([]byte, error) {
    decryptedKey, err := rsa.DecryptOAEP(
        crypto.SHA256.New(),
        rand.Reader,
        privateKey,
        encryptedKey,
        nil,
    )
    if err != nil {
        return nil, err
    }
    return decryptedKey, nil
}

func main() {
    // Load RSA private key
    privKeyFile, err := os.Open("private.pem")
    if err != nil {
        panic(err)
    }
    defer privKeyFile.Close()

    privKeyBytes, _ := ioutil.ReadAll(privKeyFile)
    block, _ := pem.Decode(privKeyBytes)

    // Use PKCS#8 format
    privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        panic(err)
    }

    // Type assert to *rsa.PrivateKey
    rsaPrivKey, ok := privKey.(*rsa.PrivateKey) // Adding type assertion here
    if !ok {
        panic("not an RSA private key")
    }

    // Load and decrypt AES key
    encryptedAESKey, err := ioutil.ReadFile("encrypted_aes_key.bin")
    if err != nil {
        panic(err)
    }
    aesKey, err := DecryptAESKeyWithRSA(rsaPrivKey, encryptedAESKey) // Use the asserted type here
    if err != nil {
        panic(err)
    }

    // Load and decrypt file data
    encryptedData, err := ioutil.ReadFile("encrypted_data.bin")
    if err != nil {
        panic(err)
    }
    plaintext, err := DecryptAES(aesKey, encryptedData)
    if err != nil {
        panic(err)
    }

    // Save decrypted file
    ioutil.WriteFile("decrypted_plaintext.txt", plaintext, 0644)
}
