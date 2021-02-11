// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

// Package hash provides an easy way to generate digest or one way hash.
// It wraps the standard library packages such as crypt/sha1
// and crypt/sha256 into easy to use functions.
package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"

	"github.com/boseji/auth"
	"golang.org/x/crypto/sha3"
)

// Hashit type is a function that implements the New creation Method that returns
// hash.Hash
type Hashit func() hash.Hash

// ShakeHashit is a function that implements variable Hash creation Method for
// SHAKE128 and SHAKE256 algorithms
type ShakeHashit func() sha3.ShakeHash

var (
	// MD5 is a pointer to MD5 creation function usable for HMAC and KDF
	MD5 Hashit = md5.New
	// SHA1 is a pointer to SHA1 creation function usable for HMAC and KDF
	SHA1 Hashit = sha1.New
	// SHA244 is a pointer to SHA2-224 creation function usable for HMAC and KDF
	SHA244 Hashit = sha256.New224
	// SHA256 is a pointer to SHA2-256 creation function usable for HMAC and KDF
	SHA256 Hashit = sha256.New
	// SHA384 is a pointer to SHA2-384 creation function usable for HMAC and KDF
	SHA384 Hashit = sha512.New384
	// SHA512 is a pointer to SHA2-512 creation function usable for HMAC and KDF
	SHA512 Hashit = sha512.New
	// SHA244Sha3 is a pointer to SHA3-244 creation function usable for HMAC and KDF
	SHA244Sha3 Hashit = sha3.New224
	// SHA256Sha3 is a pointer to SHA3-256 creation function usable for HMAC and KDF
	SHA256Sha3 Hashit = sha3.New256
	// SHA384Sha3 is a pointer to SHA3-384 creation function usable for HMAC and KDF
	SHA384Sha3 Hashit = sha3.New384
	// SHA512Sha3 is a pointer to SHA3-512 creation function usable for HMAC and KDF
	SHA512Sha3 Hashit = sha3.New512
	// SHAKE128 is a pointer to SHAKE128 creation function
	SHAKE128 ShakeHashit = sha3.NewShake128
	// SHAKE256 is a pointer to SHAKE256 creation function
	SHAKE256 ShakeHashit = sha3.NewShake128
)

// Sum function Generates the HASH of the respective type.
// It takes the distice Hashit type for computation and the input data buffer to be used.
// In case the input data buffer has enough capacity the generated sum would be appended
// to the same input data buffer.
func Sum(hf Hashit, p []byte) []byte {
	l := len(p)
	if l == 0 || hf == nil {
		return nil
	}

	h := hf()
	sz := h.Size()

	_, err := h.Write(p)
	if err != nil {
		return nil
	}

	// Check if we have space
	if (l < cap(p)) && ((cap(p) - l) >= sz) {
		return h.Sum(p)
	}

	return h.Sum(nil)
}

// ShakeSum function generates the Shake Variable Hash of the supplied input buffer.
// The size can be as big as needed. It is recommended that the size should be
// at least 32 bytes. If the size provided is 0 or no data is provided this
// function returns a nil. If sufficeint capacity (as pe the supplied size) is
// available in the supplied input buffer, then this function appends
// the digest to it.
func ShakeSum(s ShakeHashit, p []byte, size int) (r []byte) {

	l := len(p)
	if size <= 0 || l == 0 || s == nil {
		return nil
	}

	h := s()

	_, err := h.Write(p)
	if err != nil {
		return nil
	}

	// Check if the Supplied buffer has an space
	space := false
	if (cap(p) - len(p)) >= size {
		// Expand into the Backing array
		r = p[l : l+size]
		space = true
	} else {
		// Allocate if no space
		r = make([]byte, size)
	}

	_, err = h.Read(r)
	if err != nil {
		return nil
	}

	// Return the full spec array
	if space {
		return p[:l+size]
	}

	return
}

// HMAC function calculates the Keyed-Hash Message Authentication Code (HMAC)
// using the supplied key and data. Depending the supplied newFn the respective
// HMAC computation would be performed.
// If sufficeint capacity (as pe the supplied size) is available in the
// supplied input buffer, then this function appends the MAC to it.
func HMAC(hf Hashit, p, key []byte) ([]byte, error) {
	l := len(p)
	if l == 0 || hf == nil || len(key) == 0 {
		return nil, auth.ErrParameter
	}

	h := hmac.New(hf, key)
	sz := h.Size()

	_, err := h.Write(p)
	if err != nil {
		return nil, fmt.Errorf("couldn't write data in HMAC - %w", err)
	}

	// Check if we have space
	if (cap(p) - l) >= sz {
		return h.Sum(p), nil
	}

	return h.Sum(nil), nil
}

// ShakeMAC function performs the MAC operation using the Shake Variable Hash function.
// It mixes the input data 'p' with the authenticator part 'key' to generate
// the MAC code. The same can be performed and verified to check authenticity.
// It is recommended that the size should be at least 32 bytes.
// If sufficeint capacity (as pe the supplied size) is available in the
// supplied input buffer, then this function appends the MAC to it.
func ShakeMAC(s ShakeHashit, p, key []byte, size int) (mac []byte, err error) {
	l := len(p)
	if size <= 0 || l == 0 || s == nil || len(key) == 0 {
		return nil, auth.ErrParameter
	}

	h := s()

	_, err = h.Write(p)
	if err != nil {
		return nil, fmt.Errorf("couldn't write data in ShakeMAC - %w", err)
	}

	_, err = h.Write(key)
	if err != nil {
		return nil, fmt.Errorf("couldn't write authenticator in ShakeMAC - %w", err)
	}

	// Check if the Supplied buffer has an space
	space := false
	if (cap(p) - len(p)) >= size {
		// Expand into the Backing array
		mac = p[l : l+size]
		space = true
	} else {
		// Allocate if no space
		mac = make([]byte, size)
	}

	_, err = h.Read(mac)
	if err != nil {
		return nil, fmt.Errorf("couldn't read back mac value in ShakeMAC - %w", err)
	}

	// Return the full spec array
	if space {
		mac = p[:l+size]
	}

	return
}

// Compare is the cryptographically constant time compare function.
// This allows the comparison of 2 byte slices. If they are equal a true value
// is returned else false.
func Compare(x, y []byte) bool {
	if subtle.ConstantTimeCompare(x, y) == 1 {
		return true
	}
	return false
}
