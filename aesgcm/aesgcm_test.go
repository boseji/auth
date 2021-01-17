// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package aesgcm

import (
	"crypto/cipher"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/boseji/auth"
)

func TestBasic(t *testing.T) {
	tests := []struct {
		name      string
		keysize   int
		withNonce bool
		nonce     []byte
	}{
		{
			name:    "AES-GCM-128",
			keysize: KeySizeAES128,
		},
		{
			name:    "AES-GCM-192",
			keysize: KeySizeAES192,
		},
		{
			name:    "AES-GCM-256",
			keysize: KeySizeAES256,
		},
		{
			name:      "AES-GCM-128 with Nonce",
			keysize:   KeySizeAES128,
			withNonce: true,
			nonce:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			key, err := auth.GetRandom(tt.keysize)
			if err != nil {
				t.Errorf("Error in generating key - %v", err)
				return
			}

			plaintext, err := auth.GetRandom(tt.keysize * 2)
			if err != nil {
				t.Errorf("Error in generating plaintext - %v", err)
				return
			}

			iNonce := []byte(nil)
			if tt.withNonce {
				iNonce = tt.nonce
			}

			cipherText, nonce, err := Encrypt(plaintext, key, iNonce)
			if err != nil {
				t.Errorf("Failed in Encrypt() expected nil error, got %v", err)
				return
			}

			plaintext2, err := Decrypt(cipherText, nonce, key)
			if err != nil {
				t.Errorf("Failed in Encrypt() expected nil error, got %v", err)
				return
			}

			if !reflect.DeepEqual(plaintext, plaintext2) {
				t.Errorf("Failed to get AES Decryption correct - \nExpected %x, \n  got %x", plaintext, plaintext2)
				return
			}

			if tt.withNonce && !reflect.DeepEqual(iNonce, nonce) {
				t.Errorf("Failed to get Nonce correct - \nExpected %x, \n  got %x", iNonce, nonce)
				return
			}
		})
	}

}

func TestEncrypt(t *testing.T) {
	key, err := auth.GetRandom(KeySizeAES256)
	if err != nil {
		t.Errorf("Error in generating key - %v", err)
		return
	}
	plaintext, err := auth.GetRandom(KeySizeAES256 * 2)
	if err != nil {
		t.Errorf("Error in generating plaintext - %v", err)
		return
	}

	type args struct {
		plaintext []byte
		key       []byte
		iNonce    []byte
	}
	tests := []struct {
		name           string
		args           args
		wantCiphertext []byte
		wantNonce      []byte
		wantErr        bool
	}{
		{
			name:    "No Plaintext",
			args:    args{},
			wantErr: true,
		},
		{
			name: "Empty Plaintext",
			args: args{
				plaintext: []byte{},
			},
			wantErr: true,
		},
		{
			name: "No Key",
			args: args{
				plaintext: plaintext,
			},
			wantErr: true,
		},
		{
			name: "Short Key",
			args: args{
				plaintext: plaintext,
				key:       key[:KeySizeAES128-5],
			},
			wantErr: true,
		},
		{
			name: "Short Nonce",
			args: args{
				plaintext: plaintext,
				key:       key,
				iNonce:    []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCiphertext, gotNonce, err := Encrypt(tt.args.plaintext, tt.args.key, tt.args.iNonce)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCiphertext, tt.wantCiphertext) {
				t.Errorf("Encrypt() gotCiphertext = %v, want %v", gotCiphertext, tt.wantCiphertext)
			}
			if !reflect.DeepEqual(gotNonce, tt.wantNonce) {
				t.Errorf("Encrypt() gotNonce = %v, want %v", gotNonce, tt.wantNonce)
			}
		})
	}
}

func TestEncrypt_Misc(t *testing.T) {
	key, err := auth.GetRandom(KeySizeAES256)
	if err != nil {
		t.Errorf("Error in generating key - %v", err)
		return
	}
	plaintext, err := auth.GetRandom(KeySizeAES256 * 2)
	if err != nil {
		t.Errorf("Error in generating plaintext - %v", err)
		return
	}

	t.Run("Cipher Error", func(t *testing.T) {
		// Mock the Cipher
		orig := getCipher
		getCipher = func(key []byte) (cipher.Block, error) {
			return nil, auth.ErrNotSupported
		}
		defer func() { getCipher = orig }()

		_, _, err := Encrypt(plaintext, key, nil)
		if err == nil {
			t.Errorf("expected error got nil")
			return
		}
	})

	t.Run("GCM Error", func(t *testing.T) {
		// Mock the GCM
		orig := getGCM
		getGCM = func(cipher cipher.Block) (cipher.AEAD, error) {
			return nil, auth.ErrNotSupported
		}
		defer func() { getGCM = orig }()

		_, _, err := Encrypt(plaintext, key, nil)
		if err == nil {
			t.Errorf("expected error got nil")
			return
		}
	})

	t.Run("GetRandom Error", func(t *testing.T) {
		// Mock the GCM
		orig := getRandom
		getRandom = func(size int) ([]byte, error) {
			return nil, auth.ErrNotSupported
		}
		defer func() { getRandom = orig }()

		_, _, err := Encrypt(plaintext, key, nil)
		if err == nil {
			t.Errorf("expected error got nil")
			return
		}
	})
}

func TestDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString("022100c774487456c404b3bb9b3938c7234b3837746a27fbd84a91df5d3ba62e")
	nonce, _ := hex.DecodeString("eed01d5099dc428d44bb18f1")
	// plaintext := []byte("exampleplaintext")
	type args struct {
		ciphertext []byte
		nonce      []byte
		key        []byte
	}
	tests := []struct {
		name          string
		args          args
		wantPlaintext []byte
		wantErr       bool
	}{
		{
			name: "No Ciphertext",
			args: args{
				nonce: nonce,
				key:   key,
			},
			wantErr: true,
		},
		{
			name: "Empty Ciphertext",
			args: args{
				ciphertext: []byte{},
				nonce:      nonce,
				key:        key,
			},
			wantErr: true,
		},
		{
			name: "No Key",
			args: args{
				ciphertext: ciphertext,
				nonce:      nonce,
			},
			wantErr: true,
		},
		{
			name: "Empty Nonce",
			args: args{
				ciphertext: ciphertext,
				nonce:      []byte{},
				key:        key,
			},
			wantErr: true,
		},
		{
			name: "Short Key",
			args: args{
				ciphertext: ciphertext,
				nonce:      nonce,
				key:        key[:KeySizeAES128-3],
			},
			wantErr: true,
		},
		{
			name: "Short Nonce",
			args: args{
				ciphertext: ciphertext,
				nonce:      []byte{1, 2, 3, 4, 5},
				key:        key,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPlaintext, err := Decrypt(tt.args.ciphertext, tt.args.nonce, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPlaintext, tt.wantPlaintext) {
				t.Errorf("Decrypt() = %v, want %v", gotPlaintext, tt.wantPlaintext)
			}
		})
	}
}

func TestDecrypt_Misc(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	ciphertext, _ := hex.DecodeString("022100c774487456c404b3bb9b3938c7234b3837746a27fbd84a91df5d3ba62e")
	nonce, _ := hex.DecodeString("eed01d5099dc428d44bb18f1")
	// plaintext := []byte("exampleplaintext")

	t.Run("Cipher Error", func(t *testing.T) {
		// Mock the Cipher
		orig := getCipher
		getCipher = func(key []byte) (cipher.Block, error) {
			return nil, auth.ErrNotSupported
		}
		defer func() { getCipher = orig }()

		_, err := Decrypt(ciphertext, nonce, key)
		if err == nil {
			t.Errorf("expected error got nil")
			return
		}
	})

	t.Run("GCM Error", func(t *testing.T) {
		// Mock the GCM
		orig := getGCM
		getGCM = func(cipher cipher.Block) (cipher.AEAD, error) {
			return nil, auth.ErrNotSupported
		}
		defer func() { getGCM = orig }()

		_, err := Decrypt(ciphertext, nonce, key)
		if err == nil {
			t.Errorf("expected error got nil")
			return
		}
	})

	t.Run("Cipher text Error", func(t *testing.T) {
		ciphertext[5] = 0

		_, err := Decrypt(ciphertext[:KeySizeAES128], nonce, key)
		if err == nil {
			t.Errorf("expected error got nil")
			return
		}
	})
}
