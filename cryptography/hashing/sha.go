package hashing

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/sha3"
)

func HashSHA3_256(data []byte) []byte {
	hash := sha3.New256()
	hash.Write(data)
	return hash.Sum(nil)
}

func HashSHA3_512(data []byte) []byte {
	hash := sha3.New512()
	hash.Write(data)
	return hash.Sum(nil)
}

func HashSHAKE256(data []byte, outputLength int) []byte {
	hash := sha3.NewShake256()
	hash.Write(data)
	output := make([]byte, outputLength)
	hash.Read(output)
	return output
}

func HashSHA2_256(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}
func HashSHA2_512(data []byte) []byte {
	hash := sha512.New()
	hash.Write(data)
	return hash.Sum(nil)
}
