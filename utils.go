// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// ToBase64 converts a bytes array into a URL-Base64 Encoded string
func ToBase64(data []byte) (string, error) {
	if data == nil {
		return "", ErrParameter
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

// ToBase64Std converts a bytes array into a Standard-Base64 Encoded string
func ToBase64Std(data []byte) (string, error) {
	if data == nil {
		return "", ErrParameter
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// ToHex converts a bytes array into a Hex Encoded string
func ToHex(data []byte) (string, error) {
	if data == nil {
		return "", ErrParameter
	}
	return hex.EncodeToString(data), nil
}

// FromBase64 converts a URL-Base64 encoded string back to a bytes array
func FromBase64(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrParameter
	}
	return base64.URLEncoding.DecodeString(input)
}

// FromBase64Std converts a Standard-Base64 encoded string back to a bytes array
func FromBase64Std(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrParameter
	}
	return base64.StdEncoding.DecodeString(input)
}

// FromHex converts a Hex encoded string back to a bytes array
func FromHex(input string) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrParameter
	}
	return hex.DecodeString(input)
}

// SHA256 generates the SHA-256 Hash of the supplied data
func SHA256(data []byte) ([]byte, error) {
	if data == nil {
		return nil, ErrParameter
	}

	s := sha256.New()

	_, err := s.Write(data)
	if err != nil {
		return nil, fmt.Errorf("error in Sha256 - %w", err)
	}

	result := s.Sum(nil)

	return result, nil
}

// SHA512 generates the SHA-512 Hash of the supplied data
func SHA512(data []byte) ([]byte, error) {
	if data == nil {
		return nil, ErrParameter
	}

	s := sha512.New()

	_, err := s.Write(data)
	if err != nil {
		return nil, fmt.Errorf("error in Sha256 - %w", err)
	}

	result := s.Sum(nil)

	return result, nil
}

// HS256 performs the HMAC-SHA256 operation on input data using the supplied key
func HS256(data []byte, key []byte) ([]byte, error) {
	if data == nil || key == nil || len(data) == 0 || len(key) != sha256.Size {
		return nil, ErrParameter
	}

	h := hmac.New(sha256.New, key)

	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data in HS256 - %w", err)
	}

	result := h.Sum(nil)

	return result, nil
}

// CheckHS256 verifies the given MAC with supplied input
func CheckHS256(input []byte, mac []byte, key []byte) error {
	if input == nil || mac == nil || key == nil {
		return ErrParameter
	}

	inputHmac, err := HS256(input, key)
	if err != nil {
		return fmt.Errorf("failed to generate hmac for input in CheckHS256 - %w", err)
	}

	if hmac.Equal(inputHmac, mac) {
		return nil
	}

	return fmt.Errorf("hmac comparison failed")
}

// HS512 performs the HMAC-SHA512 operation on input data using the supplied key
func HS512(data []byte, key []byte) ([]byte, error) {
	if data == nil || key == nil || len(data) == 0 || len(key) != sha512.Size {
		return nil, ErrParameter
	}

	h := hmac.New(sha512.New, key)

	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data in HS512 - %w", err)
	}

	result := h.Sum(nil)

	return result, nil
}

// CheckHS512 verifies the given MAC with supplied input
func CheckHS512(input []byte, mac []byte, key []byte) error {
	if input == nil || mac == nil || key == nil {
		return ErrParameter
	}

	inputHmac, err := HS512(input, key)
	if err != nil {
		return fmt.Errorf("failed to generate hmac for input in CheckHS512 - %w", err)
	}

	if hmac.Equal(inputHmac, mac) {
		return nil
	}

	return fmt.Errorf("hmac comparison failed")
}
