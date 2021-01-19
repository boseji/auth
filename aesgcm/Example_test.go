// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package aesgcm_test

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/boseji/auth/aesgcm"
)

func Example() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("exampleplaintext")

	// Encryption without Nonce, it will be automatically be generated automatically
	ciphertext, nonce, err := aesgcm.Encrypt(plaintext, key, nil)
	if err != nil {
		panic(err.Error())
	}

	// Decryption should use the same nonce and key as used for Encryption
	plaintext2, err := aesgcm.Decrypt(ciphertext, nonce, key)
	if err != nil {
		panic(err.Error())
	}

	// Cryptographically secure constant time comparison
	if subtle.ConstantTimeCompare(plaintext, plaintext2) != 1 {
		fmt.Println("Error results don't match")
		return
	}

	fmt.Println("Success !")

	// Output: Success !
}

func ExampleEncrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("exampleplaintext")

	// Should not use a Zero Nonce for normal operation
	iNonce := make([]byte, aesgcm.NonceSize)

	// Encryption using a fixed or pre-set nonce
	ciphertext, nonce, err := aesgcm.Encrypt(plaintext, key, iNonce)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Nonce: %x\n", nonce)
	fmt.Printf("Cipher Text: %x\n", ciphertext)

	// Output:
	// Nonce: 000000000000000000000000
	// Cipher Text: b9e3743b8019206437b8ddc1ceb150096aa14c85d9f623096ffffaf48232c4f8
	//
}

func ExampleDecrypt() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString("022100c774487456c404b3bb9b3938c7234b3837746a27fbd84a91df5d3ba62e")
	nonce, _ := hex.DecodeString("eed01d5099dc428d44bb18f1")

	// Decryption with supplied nonce and key
	plaintext, err := aesgcm.Decrypt(ciphertext, nonce, key)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Plain Text: %s\n", plaintext)

	// Output:
	// Plain Text: exampleplaintext
	//
}

func ExampleNew() {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	plaintext := []byte("exampleplaintext")

	// Create the Crypt instance to perfrom AES-GCM operations
	crypt, err := aesgcm.New(aesgcm.AES256, key)
	if err != nil {
		panic(err.Error())
	}

	// Encryption :  Nonce, it will be automatically be generated automatically
	// and placed inside the Cipher text
	ciphertext, err := crypt.Encrypt(plaintext)
	if err != nil {
		panic(err.Error())
	}

	// Decryption : Same Ciphertext as from encryption
	plaintext2, _, err := crypt.Decrypt(ciphertext)
	if err != nil {
		panic(err.Error())
	}

	// Cryptographically secure constant time comparison
	if subtle.ConstantTimeCompare(plaintext, plaintext2) != 1 {
		fmt.Println("Error results don't match")
		return
	}

	fmt.Println("Success !")

	// Output: Success !
}
