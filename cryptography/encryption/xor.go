package encryption

// Xor Encryption
func xor(data, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)] // XOR operation with key cycling
	}
	return result
}

func XOREncryptDecrypt(data, key []byte) []byte {
	return xor(data, key)
}
