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
	cryptorand "crypto/rand"
	"fmt"

	"github.com/boseji/auth"
	"golang.org/x/crypto/sha3"
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
	// AES128 defines the Encryption method AES-GCM-128
	AES128 = "AES128"
	// AES192 defines the Encryption method AES-GCM-192
	AES192 = "AES192"
	// AES256 defines the Encryption method AES-GCM-256
	AES256 = "AES256"
)

// Crypt implements the Auth interface for Encryption and Decryption
type Crypt struct {
	gcm cipher.AEAD
}

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

// Decrypt function performs the AES-GCM Decryption.
// On needs to provide the same nonce generated by the Encrypt function and the
// same key as used there. The ciphertext needs to be non tampered else the
// decryption would fail. This is due to the AHEAD security nature of AES-GCM.
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

// Set method of the Auth Interface configures the Cipher engine for AES-GCM.
// The methods supported are specied by AES128 , AES192 and AES256. Any thing
// else would return an error. If the supplied key is shorter than specified
// length for a given method, then a SHAKE256 Hash is taken to expand the key.
func (c *Crypt) Set(method string, key interface{}) error {
	if key == nil {
		return auth.ErrParameter
	}

	bKey, ok := key.([]byte)
	if !ok || len(bKey) == 0 {
		return auth.ErrParameter
	}

	var keyLen int

	switch method {
	case AES128:
		keyLen = KeySizeAES128
	case AES192:
		keyLen = KeySizeAES192
	case AES256:
		keyLen = KeySizeAES256
	default:
		return fmt.Errorf("Invalid AES Encryption method")
	}

	if len(bKey) < keyLen || len(bKey) > keyLen {
		k := make([]byte, keyLen)
		sha3.ShakeSum256(k, bKey)
		bKey = k
	}

	block, err := getCipher(bKey)
	if err != nil {
		return fmt.Errorf("failed to get cipher in Crypt.Set - %w", err)
	}
	bKey = nil

	c.gcm, err = getGCM(block)
	if err != nil {
		return fmt.Errorf("failed to get AHEAD instance in Crypt.Set - %w", err)
	}

	return nil
}

// For Mocking
var readRandom = cryptorand.Read

// Create method of Auth interface performs the Encryption operation using
// the pre-initialized cipher in Crypt. The output is actually the ciphertext.
// It contains both the nonce and cipher text combined in one block.
func (c *Crypt) Create(plaintext []byte, _ interface{}) (ciphertext []byte, err error) {
	if c.gcm == nil {
		return nil, auth.ErrNotInitialized
	}

	if plaintext == nil || len(plaintext) == 0 {
		return nil, auth.ErrParameter
	}

	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := make([]byte, c.gcm.NonceSize(), c.gcm.NonceSize()+c.gcm.Overhead()+len(plaintext))
	if _, err := readRandom(nonce); err != nil {
		return nil, fmt.Errorf("failed in generating nonce ")
	}

	// Encrypt the message and append the ciphertext to the nonce.
	ciphertext = c.gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Verify method of the Auth interface performs the Decryption operation using
// the pre-initialized cipher in Crypt. This would only work with the ciphertext
// generated using the Create function with the same Crypt configuration.
// This method returns the plaintext and the nonce used upon successful decryption.
func (c *Crypt) Verify(ciphertext []byte, _ interface{}) (plaintext []byte, nonce interface{}, err error) {

	if c.gcm == nil {
		return nil, nil, auth.ErrNotInitialized
	}

	// Incase the Ciphertext was not generated correctly
	if ciphertext == nil || len(ciphertext) <= (c.gcm.NonceSize()+c.gcm.Overhead()) {
		return nil, nil, auth.ErrParameter
	}

	// Split nonce and ciphertext.
	nonceIn := ciphertext[:c.gcm.NonceSize()]
	encryptedMsg := ciphertext[c.gcm.NonceSize():]

	plaintext, err = c.gcm.Open(nil, nonceIn, encryptedMsg, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt in Crypt.Verify - %w", err)
	}

	return plaintext, nonceIn, nil
}

// Encrypt method wraps Create method
func (c *Crypt) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	return c.Create(plaintext, nil)
}

// Decrypt method wraps the Verify method
func (c *Crypt) Decrypt(ciphertext []byte) (plaintext []byte, nonce interface{}, err error) {
	return c.Verify(ciphertext, nil)
}

// New function creates a new instance of the AES-GCM Crypt Engine.
// In case it fails to do so it returns the underlying error cause.
// The methods supported are specied by AES128 , AES192 and AES256. Any thing
// else would return an error. If the supplied key is shorter than specified
// length for a given method, then a SHAKE256 Hash is taken to expand the key.
func New(method string, key []byte) (*Crypt, error) {
	c := &Crypt{}
	err := c.Set(method, key)
	if err != nil {
		return nil, err
	}
	return c, nil
}
