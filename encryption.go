package main

import (
	"crypto"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509" //generate, sign certificates, encoding public and pvt keys
    "encoding/pem" // privacy enhanced mail: represent certificates, keys
    "io"
    "io/ioutil"
    "os"
)

// GenerateAESKey creates a random AES key.
func GenerateAESKey() ([]byte, error) {
    key := make([]byte, 32) // AES-256
    _, err := rand.Read(key) // underscore is used to ignore values returned by a function. := means declaration+ init in same statement
    if err != nil {
        return nil, err
    }
    return key, nil
}

// EncryptAES encrypts data using AES with a given key.
func EncryptAES(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key) //makes a new cipher block
    if err != nil {
        return nil, err
    }
    ciphertext := make([]byte, aes.BlockSize+len(plaintext))
    iv := ciphertext[:aes.BlockSize] // iv= initialization vector, used to provide initial state . this line extracts 1st 16 bytes from ciphertext
    if _, err := io.ReadFull(rand.Reader, iv); err != nil { // fils iv with 16 random bytes (printable, non printable chars from 0-255)
        return nil, err
    }
    stream := cipher.NewCFBEncrypter(block, iv) // CFB= cipher feedback
    stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext) // takes plaintext, XORs it and stores it in ciphertext[aes.BlockSize:end]
    return ciphertext, nil 
}

// EncryptAESKeyWithRSA encrypts the AES key with an RSA public key.
func EncryptAESKeyWithRSA(publicKey *rsa.PublicKey, aesKey []byte) ([]byte, error) {
    encryptedKey, err := rsa.EncryptOAEP(
        crypto.SHA256.New(), //hash func
        rand.Reader,
        publicKey, //rsa key used to encrypt aesKey
        aesKey,
        nil,
    )
    if err != nil {
        return nil, err
    }
    return encryptedKey, nil
}

func main() {
    // Load RSA public key
    pubKeyFile, err := os.Open("public.pem") //public.pem has rsa public key. which we use to encrypt the aes key
    if err != nil {
        panic(err)
    }
    defer pubKeyFile.Close() // ensures that this function (close file) gets excecuted in the end, even if some error occurs in opening the file. prevents resource leak incase the file wasnt able to close
    pubKeyBytes, _ := ioutil.ReadAll(pubKeyFile)
    block, _ := pem.Decode(pubKeyBytes)
    pubKey, err := x509.ParsePKIXPublicKey(block.Bytes) //pkix is a standard format for public keys 
    if err != nil {
        panic(err)
    }
    rsaPubKey := pubKey.(*rsa.PublicKey) 

    // Generate AES key
    aesKey, err := GenerateAESKey()
    if err != nil {
        panic(err)
    }

    // Encrypt AES key with RSA
    encryptedAESKey, err := EncryptAESKeyWithRSA(rsaPubKey, aesKey)
    if err != nil {
        panic(err)
    }

    // Encrypt file data
    plaintext, err := ioutil.ReadFile("plaintext.txt")
    if err != nil {
        panic(err)
    }
    encryptedData, err := EncryptAES(aesKey, plaintext)
    if err != nil {
        panic(err)
    }

    // Save encrypted data and AES key to file
    ioutil.WriteFile("encrypted_data.bin", encryptedData, 0644)// 0644 specifies permissions. (0 for ?) 6 so that owner can r/w , 4 and 4 means groups and everyone else can only read it 
    ioutil.WriteFile("encrypted_aes_key.bin", encryptedAESKey, 0644)
}
