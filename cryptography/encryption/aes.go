package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"
)

func pad(input []byte, blockSize int) []byte {
	padding := blockSize - len(input)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(input, padText...)
}
func unpad(input []byte) ([]byte, error) {
	length := len(input)
	if length == 0 {
		return nil, fmt.Errorf("input is empty, cannot unpad")
	}
	padding := int(input[length-1])
	if padding > length {
		return nil, fmt.Errorf("invalid padding size")
	}
	return input[:length-padding], nil
}

func AESEncryptDecrypt(isEncrypt bool, input []byte, key []byte, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: must be 32 bytes (256 bits)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	blockSize := block.BlockSize()
	var output []byte

	if isEncrypt {
		input = pad(input, blockSize)
		mode := cipher.NewCBCEncrypter(block, iv)
		output = make([]byte, len(input))
		mode.CryptBlocks(output, input)
	} else {
		if len(input)%blockSize != 0 {
			return nil, fmt.Errorf("input length is not a multiple of the block size")
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		output = make([]byte, len(input))
		mode.CryptBlocks(output, input)
		output, err = unpad(output)
		if err != nil {
			return nil, fmt.Errorf("failed to unpad decrypted data: %v", err)
		}
	}

	return output, nil
}

func IVgenbyte(length int) []byte {
	iv := make([]byte, length)
	_, err := rand.Read(iv)
	if err != nil {
		fmt.Printf("failed to generate random IV: %v", err)
		return nil
	}
	return iv
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:'\\\",.<>?/"

// AesIVgenstr generates a random string using typable characters from the keyboard.
func IVgenstr(leng int) string {
	length := leng
	if length <= 0 {
		return ""
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		index, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			fmt.Println("ERROR GENERATING IV STRING")
			return ""
		}
		result[i] = charset[index.Int64()]
	}

	return string(result)
}
