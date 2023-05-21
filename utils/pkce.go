package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func GenerateRandomString(size int) string {
	bytes := make([]byte, size)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
