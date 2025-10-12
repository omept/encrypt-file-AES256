package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/omept/encrypt-file-aes256/utils/checkerr"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file") // create a .env file with the attached .env.example as template
	}

	//start encrypts a file
	start()

}

// start encrypts a disk file and saves the new encrypted copy
func start() {

	fileName := os.Getenv("FILE_NAME") // file to encrypt
	file, err := os.Open(fileName)
	checkerr.Check(err)

	key := os.Getenv("ENCRYPT_DECRYPT_KEY") // key lenght of 32 to use AES-256
	var bucket [1024 * 10]byte              // copy to memory by reading chuncks of 1024 * 10 bytes (10kb) from the file
	var memFile bytes.Buffer
	for {
		n, err := file.Read(bucket[:])
		if n == 0 {
			break
		}
		log.Printf("read %d bytes from file\n", n)
		if err == io.EOF {
			// copy to memory
			memFile.Write(bucket[:n])
			break
		}
		// copy to memory
		memFile.Write(bucket[:n])
	}
	file.Close()
	log.Printf("✅ File completly coppied to memory")

	encBytes, err := encrypt(memFile.Bytes(), key)
	checkerr.Check(err)

	// save to new file
	newFileName := os.Getenv("ENCRYPTED_FILE_NAME")
	err = os.WriteFile(newFileName, encBytes, 0666)
	checkerr.Check(err)
	log.Printf("💪🏽 Encryption Complete")

}

// encrypt takes a byte slice and encrypts with AES
func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	cipherBytes := gcm.Seal(nonce, nonce, data, nil)
	return cipherBytes, nil
}
