// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/gofrs/uuid/v3"
	"golang.org/x/crypto/pbkdf2"
)

// Pbkdf2SaltSize is the minimum recommended size of the Salt used for PBKDF2
const Pbkdf2SaltSize int = 8

// Pbkdf2RoundsSize is the Size of the Encoded number of rounds in a byte array
const Pbkdf2RoundsSize int = 8

// For Mock
var readFull = io.ReadFull

// GetRandom returns a cryptographically safe randome numbers byte array
// with the size specified
func GetRandom(size int) ([]byte, error) {
	if size <= 0 {
		return nil, ErrParameter
	}

	buf := make([]byte, size)
	_, err := readFull(rand.Reader, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Random numbers - %w", err)
	}

	return buf, nil
}

// For Mock
var uuidFn = uuid.NewV4

// UUIDv4 function helps to generate UUID using V4 algorithm
func UUIDv4() (string, error) {
	u, err := uuidFn()
	if err != nil {
		return "", fmt.Errorf("failed to generate new UUID in UUIDv4 - %w", err)
	}
	return u.String(), nil
}

// Pbkdf2HS1 perform PBKDF2 Key Derivation using HMAC-SHA1
func Pbkdf2HS1(key []byte, rounds int) (derivedKey []byte, salt []byte, err error) {
	if key == nil || len(key) == 0 || rounds <= 0 {
		return nil, nil, ErrParameter
	}

	salt, err = GetRandom(Pbkdf2SaltSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read random salt in Pbkdf2HS256 - %w", err)
	}

	derivedKey = pbkdf2.Key(key, salt, rounds, sha1.Size, sha1.New)

	return derivedKey, salt, err
}

// CheckPbkdf2HS1 check the PBKDF2 HMAC-SHA1 Key with an derived key
func CheckPbkdf2HS1(key []byte, derivedKey []byte, salt []byte, rounds int) error {
	if key == nil || len(key) == 0 || rounds <= 0 ||
		derivedKey == nil || salt == nil ||
		len(derivedKey) != sha1.Size || len(salt) != Pbkdf2SaltSize {
		return ErrParameter
	}

	derivedKeyNew := pbkdf2.Key(key, salt, rounds, sha1.Size, sha1.New)

	result := subtle.ConstantTimeCompare(derivedKey, derivedKeyNew)

	if result != 1 {
		return fmt.Errorf("comprison failed for key")
	}

	return nil
}

// Pbkdf2HS256 perform PBKDF2 Key Derivation using HMAC-SHA256
func Pbkdf2HS256(key []byte, rounds int) (derivedKey []byte, salt []byte, err error) {
	if key == nil || len(key) == 0 || rounds <= 0 {
		return nil, nil, ErrParameter
	}

	salt, err = GetRandom(Pbkdf2SaltSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read random salt in Pbkdf2HS256 - %w", err)
	}

	derivedKey = pbkdf2.Key(key, salt, rounds, sha256.Size, sha256.New)

	return derivedKey, salt, err
}

// CheckPbkdf2HS256 check the PBKDF2 HMAC-SHA256 Key with an derived key
func CheckPbkdf2HS256(key []byte, derivedKey []byte, salt []byte, rounds int) error {
	if key == nil || len(key) == 0 || rounds <= 0 ||
		derivedKey == nil || salt == nil ||
		len(derivedKey) != sha256.Size || len(salt) != Pbkdf2SaltSize {
		return ErrParameter
	}

	derivedKeyNew := pbkdf2.Key(key, salt, rounds, sha256.Size, sha256.New)

	result := subtle.ConstantTimeCompare(derivedKey, derivedKeyNew)

	if result != 1 {
		return fmt.Errorf("comprison failed for key")
	}

	return nil
}

// Pbkdf2HS512 perform PBKDF2 Key Derivation using HMAC-SHA512
func Pbkdf2HS512(key []byte, rounds int) (derivedKey []byte, salt []byte, err error) {
	if key == nil || len(key) == 0 || rounds <= 0 {
		return nil, nil, ErrParameter
	}

	salt, err = GetRandom(Pbkdf2SaltSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read random salt in Pbkdf2HS256 - %w", err)
	}

	derivedKey = pbkdf2.Key(key, salt, rounds, sha512.Size, sha512.New)

	return derivedKey, salt, err
}

// CheckPbkdf2HS512 check the PBKDF2 HMAC-SHA512 Key with an derived key
func CheckPbkdf2HS512(key []byte, derivedKey []byte, salt []byte, rounds int) error {
	if key == nil || len(key) == 0 || rounds <= 0 ||
		derivedKey == nil || salt == nil ||
		len(derivedKey) != sha512.Size || len(salt) != Pbkdf2SaltSize {
		return ErrParameter
	}

	derivedKeyNew := pbkdf2.Key(key, salt, rounds, sha512.Size, sha512.New)

	result := subtle.ConstantTimeCompare(derivedKey, derivedKeyNew)

	if result != 1 {
		return fmt.Errorf("comprison failed for key")
	}

	return nil
}
