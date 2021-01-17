// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

// Package aesgcm provides easy to use function to perform encryption and decryption
// using the secure AES-GCM AHEAD algorithm. It support AES-128, AES-192 and AES-256
// key sizes. This package wraps the go's 'crypto/aes' library operations
// into easy to use functions like 'Encrypt' and 'Decrypt'. It also provides
// the required constants that are needed for dermining size of keys and nonce.
// Additionally it ensure a proper cryptographically secure nonce is used for
// the encryption process automatically when the same is not supplied.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/boseji/auth"
)

const (
	// NonceSize provides the default recommended Nonce size
	NonceSize = 12
	// KeySizeAES128 specifies the minimum Key size needed for AES-GCM-128
	KeySizeAES128 = 16
	// KeySizeAES192 specifies the minimum Key size needed for AES-GCM-192
	KeySizeAES192 = 24
	// KeySizeAES256 specifies the minimum Key size needed for AES-GCM-256
	KeySizeAES256 = 32
)

// For Mocking
var getCipher = aes.NewCipher
var getGCM = cipher.NewGCM
var getRandom = auth.GetRandom

// Encrypt function performs the AES-GCM Encryption
// The supplied 'plaintext' is encrypted using the 'key'. Typically a Nonce
// is needed for the computation involved in encryption. This can be supplied
// using `iNonce` parameter and should at least have a size equivalent
// to 'NonceSize' constant. In case no nonce is supplied then a cryptographically
// secure random nonce is generated (using auth.GetRandom function).
func Encrypt(plaintext, key, iNonce []byte) (ciphertext []byte, nonce []byte, err error) {
	if plaintext == nil || key == nil || len(plaintext) == 0 {
		return nil, nil, auth.ErrParameter
	}

	keySize := len(key)
	if keySize != KeySizeAES128 && keySize != KeySizeAES192 && keySize != KeySizeAES256 {
		return nil, nil, auth.ErrParameter
	}

	block, err := getCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get cipher in Encrypt - %w", err)
	}

	gcm, err := getGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get AHEAD instance in Encrypt - %w", err)
	}

	if iNonce != nil && len(iNonce) < gcm.NonceSize() {
		return nil, nil, auth.ErrParameter
	}

	t := iNonce
	if iNonce == nil {
		t, err = getRandom(gcm.NonceSize())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get random nonce in Encrypt - %w", err)
		}
	}
	nonce = t

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// Decrypt function performs the AES-GCM Decryption
func Decrypt(ciphertext, nonce, key []byte) (plaintext []byte, err error) {
	if ciphertext == nil || key == nil || nonce == nil ||
		len(ciphertext) == 0 || len(nonce) == 0 {
		return nil, auth.ErrParameter
	}

	keySize := len(key)
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, auth.ErrParameter
	}

	block, err := getCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get cipher in Decrypt - %w", err)
	}

	gcm, err := getGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to get AHEAD instance in Decrypt - %w", err)
	}

	if len(nonce) < gcm.NonceSize() {
		return nil, auth.ErrParameter
	}

	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt - %w", err)
	}

	return plaintext, nil
}
