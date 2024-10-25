package router

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

// generateSalt generates a random salt of the given length
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// hashPassword hashes the provided password with the given salt using Argon2
func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt,
		uint32(GetParams("ENC_TIME")), uint32(GetParams("ENC_MEMORY")), uint8(GetParams("ENC_THREADS")), uint32(GetParams("ENC_KEYLEN")))
}
