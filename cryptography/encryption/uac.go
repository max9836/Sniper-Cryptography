package encryption

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/rand"
)

const (
	BlockSize = 32   // Example block size in bytes
	Rounds    = 2048 // Number of encryption rounds
)

// EncryptDecrypt performs encryption or decryption based on isEncrypt flag.
func UacEncryptDecrypt(isEncrypt bool, input []byte, key []byte, iv []byte) ([]byte, error) {
	if len(key) < BlockSize || len(iv) != BlockSize {
		return nil, errors.New("key must be at least 32 bytes")
	}

	// Derive subkeys for each round
	subkeys := deriveSubkeys(key, iv)

	// Generate a dynamic S-box based on the key and IV
	sbox := generateDynamicSBox(key, iv)

	// Pad input if encrypting
	if isEncrypt {
		input = pad(input, BlockSize)
	} else {
		if len(input)%BlockSize != 0 {
			return nil, errors.New("invalid input length for decryption")
		}
	}

	// Process input block by block
	output := make([]byte, len(input))
	for i := 0; i < len(input); i += BlockSize {
		block := input[i : i+BlockSize]
		if isEncrypt {
			block = encryptBlock(block, subkeys, sbox)
		} else {
			block = decryptBlock(block, subkeys, sbox)
		}
		copy(output[i:], block)
	}

	// Remove padding if decrypting
	if !isEncrypt {
		output = uacunpad(output)
	}

	return output, nil
}

// Derive subkeys using SHA-512 for simplicity
func deriveSubkeys(key []byte, iv []byte) [][]byte {
	subkeys := make([][]byte, Rounds)
	seed := append(key, iv...)
	for i := 0; i < Rounds; i++ {
		hash := sha512.Sum512(append(seed, byte(i)))
		subkeys[i] = hash[:BlockSize]
	}
	return subkeys
}

// Generate a dynamic S-box based on the key and IV
func generateDynamicSBox(key []byte, iv []byte) []byte {
	seed := binary.BigEndian.Uint64(append(key, iv...)[:8])
	rng := rand.New(rand.NewSource(int64(seed)))
	sbox := make([]byte, 256)
	for i := range sbox {
		sbox[i] = byte(i)
	}
	rng.Shuffle(256, func(i, j int) {
		sbox[i], sbox[j] = sbox[j], sbox[i]
	})
	return sbox
}

// Substitute bytes using the S-box
func substitute(block []byte, sbox []byte) []byte {
	output := make([]byte, len(block))
	for i, b := range block {
		output[i] = sbox[b]
	}
	return output
}

// Permute block (e.g., reverse bytes for simplicity)
func permute(block []byte) []byte {
	output := make([]byte, len(block))
	for i, b := range block {
		output[len(block)-1-i] = b
	}
	return output
}

// XOR block with key
func xorWithKey(block []byte, key []byte) []byte {
	output := make([]byte, len(block))
	for i := range block {
		output[i] = block[i] ^ key[i]
	}
	return output
}

// Encrypt a single block
func encryptBlock(block []byte, subkeys [][]byte, sbox []byte) []byte {
	for _, key := range subkeys {
		block = substitute(block, sbox)
		block = permute(block)
		block = xorWithKey(block, key)
	}
	return block
}

// Decrypt a single block (reverse operations)
func decryptBlock(block []byte, subkeys [][]byte, sbox []byte) []byte {
	for i := len(subkeys) - 1; i >= 0; i-- {
		block = xorWithKey(block, subkeys[i])
		block = permute(block) // Permutation is symmetric
		block = reverseSubstitute(block, sbox)
	}
	return block
}

// Reverse substitution
func reverseSubstitute(block []byte, sbox []byte) []byte {
	reverseSBox := make([]byte, 256)
	for i, v := range sbox {
		reverseSBox[v] = byte(i)
	}
	output := make([]byte, len(block))
	for i, b := range block {
		output[i] = reverseSBox[b]
	}
	return output
}

func uacunpad(data []byte) []byte {
	length := len(data)
	padding := int(data[length-1])
	return data[:length-padding]
}
