package services

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Payload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
	Iat int64  `json:"iat"`
	// Add other claims here as needed.
}
type JwtTokenValidator interface {
	validate(jwt string, publicKey *rsa.PublicKey) error
	introspect(jwt string) error
}
type JwtService struct {
	IntrospectionURL string
	OAuthConfig      *oauth2.Config
}

func (j *JwtService) introspect(jwt string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.PostForm(j.IntrospectionURL, url.Values{"token": {jwt}})

	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return errors.New("token introspection failed")
	}

	return nil
}

func (j *JwtService) validate(jwt string, publicKey *rsa.PublicKey) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return errors.New("invalid token")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return err
	}

	if header.Alg != "RS256" {
		return errors.New("unsupported signing method")
	}
	if header.Typ != "JWT" {
		return errors.New("invalid token type")
	}

	var payload Payload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return err
	}

	now := time.Now().Unix()
	if payload.Exp < now {
		return errors.New("token has expired")
	}
	if payload.Nbf > now {
		return errors.New("token is not valid yet")
	}
	if payload.Iat > now {
		return errors.New("token was issued in the future")
	}

	hashed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return errors.New("invalid signature")
	}
	return nil
}
