// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// PasswordHash is used to generated cryptographically secure digest
// from the supplied password and also verify the digest.
type PasswordHash struct {
	method string
}

// Password Hash Methods

// MethodPasswordHashHS256 defines password hash generation using
// HMAC-SHA256
const MethodPasswordHashHS256 = "Password Hash using HMAC-SHA256"

// MethodPasswordHashHS512 defines password hash generation using
// HMAC-SHA512
//const MethodPasswordHashHS512 = "Password Hash using HMAC-SHA512"

// MethodPasswordHashBcrypt defines password hash generation using
// bcrypt
//const MethodPasswordHashBcrypt = "Password Hash using bcrypt"

// MethodPasswordHashPbkdf2S256 defines password hash generation using
// pbkdf2 with HMAC-SHA256
//const MethodPasswordHashPbkdf2S256 = "Password Hash using pbkdf2 and HMAC-SHA256"

type passwordHashHS256 struct {
	PasswordHash
	initialized bool
	key         []byte
}

// Set method from the Auth interface
func (p *passwordHashHS256) Set(method string, key interface{}) error {
	if method != MethodPasswordHashHS256 {
		return ErrParameter
	}
	if key == nil {
		return ErrParameter
	}
	keyArr, ok := key.([]byte)
	if !ok {
		return ErrParameter
	}
	if len(keyArr) != sha256.Size {
		return ErrParameter
	}

	p.PasswordHash.method = MethodPasswordHashHS256
	p.key = keyArr
	p.initialized = true
	keyArr = nil
	return nil
}

// Create method from the Auth interface
func (p *passwordHashHS256) Create(data []byte, _ interface{}) ([]byte, error) {
	if !p.initialized {
		return nil, ErrNotInitialized
	}
	if data == nil || len(data) == 0 {
		return nil, ErrParameter
	}

	h := hmac.New(sha256.New, p.key)

	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("error in passwordHashHS256.Create - %w", err)
	}

	resultBuf := h.Sum(nil)

	return resultBuf, nil
}

// Verify method from the Auth interface
func (p *passwordHashHS256) Verify(value []byte, bias interface{}) ([]byte, interface{}, error) {
	if !p.initialized {
		return nil, nil, ErrNotInitialized
	}
	if value == nil || len(value) == 0 {
		return nil, nil, ErrParameter
	}
	if bias == nil {
		return nil, nil, ErrParameter
	}

	signatureBuf, ok := bias.([]byte)
	if !ok || len(signatureBuf) == 0 {
		return nil, nil, ErrParameter
	}

	h := hmac.New(sha256.New, p.key)

	_, err := h.Write(value)
	if err != nil {
		return nil, nil, fmt.Errorf("error in passwordHashHS256.Verify while generating Hash of the supplied value - %w", err)
	}

	inputHashBuf := h.Sum(nil)

	if hmac.Equal(inputHashBuf, signatureBuf) {
		return inputHashBuf, signatureBuf, nil
	}
	return nil, nil, fmt.Errorf("Verification failed error in passwordHashHS256.Verify")
}

// NewPasswordHash Configures the respective password Hashing algorithm and
// returns the instance which implements the Auth Interface
func NewPasswordHash(method string, key interface{}) (Auth, error) {
	switch method {
	case MethodPasswordHashHS256:
		ret := &passwordHashHS256{}
		err := ret.Set(method, key)
		if err != nil {
			return nil, fmt.Errorf(
				"error in creating Password Hash for %s - %w",
				MethodPasswordHashHS256,
				err,
			)
		}
		return ret, nil
	}
	return nil, ErrNotImplemented
}
