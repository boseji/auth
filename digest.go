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

	// Get function takes in the byte array of arbitrary Size and
	// process it into a digest of fix size
	Get([]byte) ([]byte, error)

	// Auth Interface is Implemented here
	Auth
}

// DigestOptions provides a functional Option for attribute modification functions
type DigestOptions func(DigestIt) DigestIt

// hashFn function implements the DigestIt interface
type hashFn struct {
	FnName string
	Hash   crypto.Hash
}

// hmacFn implements the standard Hash functions along with HMAC operation
type hmacFn struct {
	DigestIt
	key []byte
}

// hmacVerify helps to check the HMAC digest
type hmacVerify struct {
	DigestIt
	digest []byte
}

// bcryptFn implements the DigestIt interface but needs a special option to work
type bcryptFn struct {
	FnName string
}

// bcryptWithCost implements the DigestIt interface with Custom Cost
type bcryptWithCost struct {
	DigestIt
	cost int
}

// bcryptVerify helps to check the bcrypt digest
type bcryptVerify struct {
	DigestIt
	digest []byte
}

const (
	// BcryptDefaultCost is the Bcrypt Default Cost where the performace is optimal
	BcryptDefaultCost = bcrypt.DefaultCost
	// BcryptMaxCost is the Bcrypt Maximum Cost with Longest Time
	BcryptMaxCost = bcrypt.MaxCost
	// BcryptMinCost is the Bcrypt Minimum Cost with Shortest time
	BcryptMinCost = bcrypt.MinCost
	// MethodMD5 describes the MD5 Hashing Algorithm
	MethodMD5 = "MD5"
	// MethodSHA1 describes the SHA1 Hashing Algorithm
	MethodSHA1 = "SHA1"
	// MethodSHA224 describes the SHA224 Hashing Algorithm
	MethodSHA224 = "SHA224"
	// MethodSHA256 describes the SHA256 Hashing Algorithm
	MethodSHA256 = "SHA256"
	// MethodSHA384 describes the SHA384 Hashing Algorithm
	MethodSHA384 = "SHA384"
	// MethodSHA512 describes the SHA512 Hashing Algorithm
	MethodSHA512 = "SHA512"
	// MethodBcrypt describes the bcrypt Hashing Algorithm
	MethodBcrypt = "bcrypt"
)

// List of All the Digest functions
var digestFuncs = map[string]DigestIt{}

// Lock for the Digest Function List
var digestFuncsLock = new(sync.RWMutex)

// List of Hash Functions
var (
	Md5    *hashFn
	Sha1   *hashFn
	Sha224 *hashFn
	Sha256 *hashFn
	Sha384 *hashFn
	Sha512 *hashFn
	Bcrypt *bcryptFn
)

func init() {
	Md5 = &hashFn{FnName: MethodMD5, Hash: crypto.MD5}
	RegisterDigestFunction(Md5.FnName, Md5)

	Sha1 = &hashFn{FnName: MethodSHA1, Hash: crypto.SHA1}
	RegisterDigestFunction(Sha1.FnName, Sha1)

	Sha224 = &hashFn{FnName: MethodSHA224, Hash: crypto.SHA224}
	RegisterDigestFunction(Sha224.FnName, Sha224)

	Sha256 = &hashFn{FnName: MethodSHA256, Hash: crypto.SHA256}
	RegisterDigestFunction(Sha256.FnName, Sha256)

	Sha384 = &hashFn{FnName: MethodSHA384, Hash: crypto.SHA384}
	RegisterDigestFunction(Sha384.FnName, Sha384)

	Sha512 = &hashFn{FnName: MethodSHA512, Hash: crypto.SHA512}
	RegisterDigestFunction(Sha512.FnName, Sha512)

	Bcrypt = &bcryptFn{FnName: MethodBcrypt}
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
func (h *hashFn) Name() string {
	return h.FnName
}

// HashFunc method returns the internal Hash Function unit of Crypto
func (h *hashFn) HashFunc() crypto.Hash {
	return h.Hash
}

// New method creates a new instance of the Internal New Method
func (h *hashFn) New() hash.Hash {
	return h.Hash.New()
}

// Size method exposes the internal Size Method
func (h *hashFn) Size() int {
	return h.Hash.Size()
}

// Get method implementation for DigestIt
func (h *hashFn) Get(data []byte) ([]byte, error) {
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

// Create Method from Auth interface wraps the Get method
func (h *hashFn) Create(data []byte, _ interface{}) (output []byte, err error) {
	return h.Get(data)
}

// Verify Method from Auth interface can be used for Compare
func (h *hashFn) Verify(hash1 []byte, hash2 interface{}) (h1 []byte, h2 interface{}, err error) {
	if hash1 == nil || len(hash1) == 0 || hash2 == nil {
		return nil, nil, ErrParameter
	}
	buf, ok := hash2.([]byte)
	if !ok || len(buf) != len(hash1) {
		return nil, nil, ErrParameter
	}

	if hmac.Equal(hash1, buf) {
		return hash1, buf, nil
	}

	return nil, nil, fmt.Errorf("verification failed in HashFn.Verify")
}

// Set Method from Auth interface is generally not support it only
//  return error when called with wrong method name
func (h *hashFn) Set(method string, _ interface{}) error {
	if method != h.FnName {
		return ErrParameter
	}
	return nil
}

// Get method implementation for DigestIt
func (h *hmacFn) Get(data []byte) ([]byte, error) {
	if data == nil || len(data) == 0 {
		return nil, ErrParameter
	}

	hm := h.DigestIt.(*hashFn)
	fn := hmac.New(hm.HashFunc().New, h.key)

	_, err := fn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write into hash function - %w", err)
	}

	result := fn.Sum(nil)

	return result, nil
}

// Get method implementation for DigestIt
func (h *hmacVerify) Get(data []byte) ([]byte, error) {
	input := data
	// In case HMAC was requested
	if _, ok := h.DigestIt.(*hmacFn); ok {
		buf, err := h.DigestIt.Get(data)
		if err != nil {
			return nil, err
		}
		input = make([]byte, len(buf))
		copy(input, buf)
	}
	h1, _, err := h.Verify(input, h.digest)
	return h1, err
}

// For Mock
var bcryptGenerate = bcrypt.GenerateFromPassword

// Generate creates the Bcrypt digest of the password
func (b *bcryptFn) Generate(password []byte, cost int) ([]byte, error) {
	if password == nil || len(password) == 0 {
		return nil, ErrParameter
	}

	result, err := bcryptGenerate(password, cost)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bcrypt hash - %w", err)
	}

	return result, nil
}

// For Mock
var bcryptCompare = bcrypt.CompareHashAndPassword

// Check function verify at the password against the Bcrypt digest
func (b *bcryptFn) Check(password []byte, digest []byte) error {
	if password == nil || digest == nil || len(password) == 0 || len(digest) == 0 {
		return ErrParameter
	}
	err := bcryptCompare(digest, password)
	if err != nil {
		return fmt.Errorf("bcrypt compare failed - %w", err)
	}

	return nil
}

// Name method of the DigestIt Interface
func (b *bcryptFn) Name() string {
	return b.FnName
}

// Get method implementation for DigestIt
func (b *bcryptFn) Get(data []byte) ([]byte, error) {
	return b.Create(data, bcrypt.DefaultCost)
}

// Create Method from Auth interface is a wrapper for Generate function
func (b *bcryptFn) Create(password []byte, bCost interface{}) (dig []byte, err error) {
	if bCost == nil {
		return nil, ErrParameter
	}
	cost, ok := bCost.(int)
	if !ok {
		cost = bcrypt.DefaultCost
	}

	if cost > bcrypt.MaxCost {
		cost = bcrypt.MaxCost
	} else if cost < bcrypt.MinCost {
		cost = bcrypt.MinCost
	}

	return b.Generate(password, cost)
}

// Verify Method from Auth interface is a wrapper for Check function
func (b *bcryptFn) Verify(password []byte, bDig interface{}) (pass []byte, iDig interface{}, err error) {
	if bDig == nil {
		return nil, nil, ErrParameter
	}
	dig, ok := bDig.([]byte)
	if !ok || len(dig) == 0 {
		return nil, nil, ErrParameter
	}

	err = b.Check(password, dig)
	if err != nil {
		return nil, nil, err
	}
	return password, dig, nil
}

// Set Method from Auth interface
func (b *bcryptFn) Set(method string, key interface{}) error {
	if method != b.FnName {
		return ErrParameter
	}
	return nil
}

// Get method implementation for DigestIt
func (b *bcryptWithCost) Get(data []byte) ([]byte, error) {
	return b.Create(data, b.cost)
}

// Get method implementation for DigestIt
func (b *bcryptVerify) Get(data []byte) ([]byte, error) {
	_, _, err := b.Verify(data, b.digest)
	if err != nil {
		return nil, err
	}
	return b.digest, nil
}

// WithHMACKey helps to implement HMAC operation
func WithHMACKey(key []byte) DigestOptions {
	return func(d DigestIt) DigestIt {
		if h, ok := d.(*hashFn); ok {
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
		if b, ok := d.(*bcryptFn); ok {
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

// WithDigest helps to implement Verification as part of Digest operations
func WithDigest(digest []byte) DigestOptions {
	return func(d DigestIt) DigestIt {
		if b, ok := d.(*bcryptFn); ok {
			bv := &bcryptVerify{b, digest}
			return bv
		}
		if b, ok := d.(*bcryptWithCost); ok {
			bv := &bcryptVerify{b, digest}
			return bv
		}
		if h, ok := d.(*hashFn); ok {
			hv := &hmacVerify{h, digest}
			return hv
		}
		if h, ok := d.(*hmacFn); ok {
			hv := &hmacVerify{h, digest}
			return hv
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

	return dig.Get(data)
}
