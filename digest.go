// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Digest implementation shows the Singleton + Functional options
// with only one Core function(Digest) that needs to be exposed.

// DigestIt interface defines the way by which Hash function coverts byte array
// of arbitrary size to a byte array of a fixed size called
// the "hash value", "hash", or "message digest"
type DigestIt interface {

	// Name Returns the Name in String for the given Hash Function
	Name() string

	// Proc function takes in the byte array of arbitrary Size and
	// process it into a digest of fix size
	Proc([]byte) ([]byte, error)
}

// DigestOptions provides a functional Option for attribute modification functions
type DigestOptions func(DigestIt) DigestIt

// HashFn function implements the DigestIt interface
type HashFn struct {
	FnName string
	Hash   crypto.Hash
}

// hmacFn implements the standard Hash functions along with HMAC operation
type hmacFn struct {
	*HashFn
	key []byte
}

// BcryptFn implements the DigestIt interface but needs a special option to work
type BcryptFn struct {
	FnName string
}

// bcryptWithCost implements the DigestIt interface with Custom Cost
type bcryptWithCost struct {
	*BcryptFn
	cost int
}

type bcryptVerify struct {
	*BcryptFn
	digest []byte
}

// List of All the Digest functions
var digestFuncs = map[string]DigestIt{}

// Lock for the Digest Function List
var digestFuncsLock = new(sync.RWMutex)

// List of Hash Functions
var (
	Md5    *HashFn
	Sha1   *HashFn
	Sha224 *HashFn
	Sha256 *HashFn
	Sha384 *HashFn
	Sha512 *HashFn
	Bcrypt *BcryptFn
)

func init() {
	Md5 = &HashFn{FnName: "MD5", Hash: crypto.MD5}
	RegisterDigestFunction(Md5.FnName, Md5)

	Sha1 = &HashFn{FnName: "SHA1", Hash: crypto.SHA1}
	RegisterDigestFunction(Sha1.FnName, Sha1)

	Sha224 = &HashFn{FnName: "SHA224", Hash: crypto.SHA224}
	RegisterDigestFunction(Sha224.FnName, Sha224)

	Sha256 = &HashFn{FnName: "SHA256", Hash: crypto.SHA256}
	RegisterDigestFunction(Sha256.FnName, Sha256)

	Sha384 = &HashFn{FnName: "SHA384", Hash: crypto.SHA384}
	RegisterDigestFunction(Sha384.FnName, Sha384)

	Sha512 = &HashFn{FnName: "SHA512", Hash: crypto.SHA512}
	RegisterDigestFunction(Sha512.FnName, Sha512)

	Bcrypt = &BcryptFn{FnName: "bcrypt"}
	RegisterDigestFunction(Bcrypt.FnName, Bcrypt)
}

// RegisterDigestFunction adds the specific Hash generation functions in the
// global list. It is typically run during init() stage.
func RegisterDigestFunction(name string, f DigestIt) {
	digestFuncsLock.Lock()
	defer digestFuncsLock.Unlock()

	digestFuncs[name] = f
}

// GetDigestFunction fetches the respective Hash generation function using
// its pre registed name.
func GetDigestFunction(name string) (f DigestIt) {
	digestFuncsLock.RLock()
	defer digestFuncsLock.RUnlock()

	if fn, ok := digestFuncs[name]; ok {
		f = fn
	}

	return f
}

// Name method of the DigestIt Interface
func (h *HashFn) Name() string {
	return h.FnName
}

// HashFunc method returns the internal Hash Function unit of Crypto
func (h *HashFn) HashFunc() crypto.Hash {
	return h.Hash
}

// New method creates a new instance of the Internal New Method
func (h *HashFn) New() hash.Hash {
	return h.Hash.New()
}

// Size method exposes the internal Size Method
func (h *HashFn) Size() int {
	return h.Hash.Size()
}

// Proc method implementation for DigestIt
func (h *HashFn) Proc(data []byte) ([]byte, error) {
	if data == nil || len(data) == 0 {
		return nil, ErrParameter
	}

	fn := h.New()

	_, err := fn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write into hash function - %w", err)
	}

	result := fn.Sum(nil)

	return result, nil
}

// Proc method implementation for DigestIt
func (h *hmacFn) Proc(data []byte) ([]byte, error) {
	if data == nil || len(data) == 0 {
		return nil, ErrParameter
	}

	fn := hmac.New(h.HashFn.New, h.key)

	_, err := fn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write into hash function - %w", err)
	}

	result := fn.Sum(nil)

	return result, nil
}

// For Mock
var bcryptGenerate = bcrypt.GenerateFromPassword

func (b *BcryptFn) operation(data []byte, cost int) ([]byte, error) {
	if data == nil || len(data) == 0 {
		return nil, ErrParameter
	}

	result, err := bcryptGenerate(data, cost)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bcrypt hash - %w", err)
	}

	return result, nil
}

// For Mock
var bcryptCompare = bcrypt.CompareHashAndPassword

func (b *BcryptFn) verify(orig []byte, digest []byte) error {
	if orig == nil || digest == nil || len(orig) == 0 || len(digest) == 0 {
		return ErrParameter
	}
	err := bcryptCompare(digest, orig)
	if err != nil {
		return fmt.Errorf("bcrypt compare failed - %w", err)
	}

	return nil
}

// Name method of the DigestIt Interface
func (b *BcryptFn) Name() string {
	return b.FnName
}

// Proc method implementation for DigestIt
func (b *BcryptFn) Proc(data []byte) ([]byte, error) {
	return b.operation(data, bcrypt.DefaultCost)
}

// Proc method implementation for DigestIt
func (b *bcryptWithCost) Proc(data []byte) ([]byte, error) {
	return b.BcryptFn.operation(data, b.cost)
}

// Proc method implementation for DigestIt
func (b *bcryptVerify) Proc(data []byte) ([]byte, error) {
	err := b.BcryptFn.verify(data, b.digest)
	if err != nil {
		return nil, err
	}
	return b.digest, nil
}

// WithHMACKey helps to implement HMAC operation
func WithHMACKey(key []byte) DigestOptions {
	return func(d DigestIt) DigestIt {
		if h, ok := d.(*HashFn); ok {
			// New Encapsulated value
			hm := &hmacFn{h, key}
			return hm
		}
		return d
	}
}

// WithBcryptCost helps to implement Alternative Bcrypt operation
func WithBcryptCost(cost int) DigestOptions {
	return func(d DigestIt) DigestIt {
		if b, ok := d.(*BcryptFn); ok {
			// Verify Cost range
			if cost > bcrypt.MaxCost {
				cost = bcrypt.DefaultCost
			} else if cost < bcrypt.MinCost {
				cost = bcrypt.MinCost
			}
			// New Encapsulated value
			bc := &bcryptWithCost{b, cost}
			return bc
		}
		return d
	}
}

// WithBcryptDigest helps to implement Verification as part of Digest
func WithBcryptDigest(digest []byte) DigestOptions {
	return func(d DigestIt) DigestIt {
		if b, ok := d.(*BcryptFn); ok {
			bv := &bcryptVerify{b, digest}
			return bv
		}
		return d
	}
}

// Digest is the generic function for obtaining various type of HASH function
// operations on the data
func Digest(d DigestIt, data []byte, opts ...DigestOptions) ([]byte, error) {
	if d == nil {
		return nil, ErrParameter
	}

	// Fetch the Digest function Name
	dig := GetDigestFunction(d.Name())
	if dig == nil {
		return nil, ErrNotImplemented
	}

	// Process Options
	if opts != nil {
		for _, option := range opts {
			dig = option(dig)
		}
	}

	return dig.Proc(data)
}
