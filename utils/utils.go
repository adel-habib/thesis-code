package utils

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateState() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}
