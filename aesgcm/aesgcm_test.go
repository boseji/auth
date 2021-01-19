// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package aesgcm

import (
	"crypto/cipher"
	"crypto/subtle"
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

	tests2 := []struct {
		name    string
		method  string
		keysize int
	}{
		{
			name:    "Crypt AES-GCM-128 Normal",
			method:  AES128,
			keysize: KeySizeAES128,
		},
		{
			name:    "Crypt AES-GCM-192 Normal",
			method:  AES192,
			keysize: KeySizeAES192,
		},
		{
			name:    "Crypt AES-GCM-256 Normal",
			method:  AES256,
			keysize: KeySizeAES256,
		},
		{
			name:    "Crypt AES-GCM-128 Short Key",
			method:  AES128,
			keysize: KeySizeAES128 - 1,
		},
		{
			name:    "Crypt AES-GCM-192 Short Key",
			method:  AES192,
			keysize: KeySizeAES192 - 1,
		},
		{
			name:    "Crypt AES-GCM-256 Short Key",
			method:  AES256,
			keysize: KeySizeAES256 - 1,
		},
		{
			name:    "Crypt AES-GCM-128 Long Key",
			method:  AES128,
			keysize: KeySizeAES128 + 10,
		},
		{
			name:    "Crypt AES-GCM-192 Long Key",
			method:  AES192,
			keysize: KeySizeAES192 + 10,
		},
		{
			name:    "Crypt AES-GCM-256 Long Key",
			method:  AES256,
			keysize: KeySizeAES256 + 10,
		},
	}

	for _, tt := range tests2 {
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

			c, err := New(tt.method, key)
			if err != nil {
				t.Errorf("Failed in New() expected nil error, got %v", err)
			}

			cipherText, err := c.Create(plaintext, nil)
			if err != nil {
				t.Errorf("Failed in Crypt.Create() expected nil error, got %v", err)
				return
			}

			c2, err := New(tt.method, key)
			if err != nil {
				t.Errorf("Failed in New() II expected nil error, got %v", err)
			}

			plaintext2, nonce, err := c2.Verify(cipherText, nil)
			if err != nil {
				t.Errorf("Failed in Encrypt() expected nil error, got %v", err)
				return
			}

			if !reflect.DeepEqual(plaintext, plaintext2) {
				t.Errorf("Failed to get AES Decryption correct - \nExpected %x, \n  got %x", plaintext, plaintext2)
				return
			}

			if nonce == nil {
				t.Errorf("Failed to get Nonce correct - Got Nil")
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

func TestNew(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	type args struct {
		method string
		key    []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Empty Keys",
			args: args{
				key: []byte{},
			},
			wantErr: true,
		},
		{
			name: "Wrong Method",
			args: args{
				key:    key,
				method: "Unknown",
			},
			wantErr: true,
		},
		{
			name: "Short Key",
			args: args{
				key:    key[:KeySizeAES128-2],
				method: AES128,
			},
		},
		{
			name: "Long Key",
			args: args{
				key:    key,
				method: AES128,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.method, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil && !tt.wantErr {
				t.Errorf("New() failed = nil")
			}
		})
	}
}

func TestCrypt_Set(t *testing.T) {
	type args struct {
		method string
		key    interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "No Key",
			args:    args{},
			wantErr: true,
		},
		{
			name: "Wrong Key Type",
			args: args{
				key: "Wrong",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Crypt{}
			if err := c.Set(tt.args.method, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("Crypt.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("Error in getCipher", func(t *testing.T) {
		// Mock
		orig := getCipher
		getCipher = func(key []byte) (cipher.Block, error) {
			return nil, auth.ErrNotSupported
		}
		defer func() { getCipher = orig }()

		c := &Crypt{}

		err := c.Set(AES128, []byte{1, 2, 3, 4, 5})
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}

	})

	t.Run("Error in getGCM", func(t *testing.T) {
		// Mock
		orig := getGCM
		getGCM = func(cipher cipher.Block) (cipher.AEAD, error) {
			return nil, auth.ErrNotSupported
		}
		defer func() { getGCM = orig }()

		c := &Crypt{}

		err := c.Set(AES128, []byte{1, 2, 3, 4, 5})
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}

	})
}

func TestCrypt_Create(t *testing.T) {
	t.Run("Non Initialized Call", func(t *testing.T) {
		c := Crypt{}

		_, err := c.Create([]byte("Test"), nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})

	t.Run("No Plaintext", func(t *testing.T) {
		c, err := New(AES128, []byte("Test Key"))
		if err != nil {
			t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
			return
		}

		_, err = c.Create(nil, nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})

	t.Run("Empty Plaintext", func(t *testing.T) {
		c, err := New(AES128, []byte("Test Key"))
		if err != nil {
			t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
			return
		}

		_, err = c.Create([]byte{}, nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})

	t.Run("Read Random Error", func(t *testing.T) {
		// Mock
		orig := readRandom
		readRandom = func(b []byte) (n int, err error) {
			return 0, auth.ErrNotSupported
		}
		defer func() { readRandom = orig }()

		c, err := New(AES128, []byte("Test Key"))
		if err != nil {
			t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
			return
		}

		_, err = c.Create([]byte("Example Plaintext"), nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})
}

func TestCrypt_Verify(t *testing.T) {
	t.Run("Non Initialized Call", func(t *testing.T) {
		c := Crypt{}

		_, _, err := c.Verify([]byte("Test"), nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})

	t.Run("No Ciphertext", func(t *testing.T) {
		c, err := New(AES128, []byte("Test Key"))
		if err != nil {
			t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
			return
		}

		_, _, err = c.Verify(nil, nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})

	t.Run("Empty Ciphertext", func(t *testing.T) {
		c, err := New(AES128, []byte("Test Key"))
		if err != nil {
			t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
			return
		}

		_, _, err = c.Verify([]byte{}, nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})

	t.Run("Short Ciphertext", func(t *testing.T) {
		c, err := New(AES128, []byte("Test Key"))
		if err != nil {
			t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
			return
		}

		ciphertext, err := c.Create([]byte("Example Plaintext"), nil)
		if err != nil {
			t.Errorf("Failed in Crypt.Create() Expected no Errors, Got - %v", err)
			return
		}

		_, _, err = c.Verify(ciphertext[:c.gcm.NonceSize()+2], nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})

	t.Run("Decrypt Error", func(t *testing.T) {
		c, err := New(AES128, []byte("Test Key"))
		if err != nil {
			t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
			return
		}

		ciphertext, err := c.Create([]byte("Example Plaintext"), nil)
		if err != nil {
			t.Errorf("Failed in Crypt.Create() Expected no Errors, Got - %v", err)
			return
		}

		ciphertext[2] = 0
		ciphertext[8] = 0

		_, _, err = c.Verify(ciphertext[:len(ciphertext)-2], nil)
		if err == nil {
			t.Errorf("Expected Error but got nil")
			return
		}
	})
}

func TestCrypt_Others(t *testing.T) {
	c, err := New(AES128, []byte("Test Key"))
	if err != nil {
		t.Errorf("Failed in New() Expected no Errors, Got - %v", err)
		return
	}

	ciphertext, err := c.Encrypt([]byte("Example Plaintext"))
	if err != nil {
		t.Errorf("Failed in Crypt.Encrypt() Expected no Errors, Got - %v", err)
		return
	}

	c2, err := New(AES128, []byte("Test Key"))
	if err != nil {
		t.Errorf("Failed in New() II Expected no Errors, Got - %v", err)
		return
	}

	plaintext, nonce, err := c2.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("Failed in Crypt.Decrypt() Expected no Errors, Got - %v", err)
		return
	}

	if subtle.ConstantTimeCompare(plaintext, []byte("Example Plaintext")) != 1 {
		t.Errorf("Expted result to be 'Example Plaintext', got %q", string(plaintext))
		return
	}

	if nonce == nil {
		t.Errorf("Expected Nonce but got nil")
		return
	}
}
