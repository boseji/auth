// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHash is used to generated cryptographically secure digest
// from the supplied password and also verify the digest.
type PasswordHash struct {
	method string
}

// Password Hash Methods

// MethodPasswordHashBcrypt defines password hash generation using
// bcrypt
const MethodPasswordHashBcrypt = "Password Hash using bcrypt"

const (
	// BcryptDefaultCost is the Bcrypt Default Cost where the performace is optimal
	BcryptDefaultCost int = bcrypt.DefaultCost
	// BcryptMaxCost is the Bcrypt Maximum Cost with Longest Time
	BcryptMaxCost int = bcrypt.MaxCost
	// BcryptMinCost is the Bcrypt Minimum Cost with Shortest time
	BcryptMinCost int = bcrypt.MinCost
)

// MethodPasswordHashPbkdf2S256 defines password hash generation using
// pbkdf2 with HMAC-SHA256
const MethodPasswordHashPbkdf2S256 = "Password Hash using pbkdf2 and HMAC-SHA256"

type passwordHashBcrypt struct{}

// Set method from the Auth interface
func (p *passwordHashBcrypt) Set(method string, _ interface{}) error {
	if method != MethodPasswordHashBcrypt {
		return ErrParameter
	}
	return nil
}

// Create method from the Auth interface
func (p *passwordHashBcrypt) Create(data []byte, bWeight interface{}) ([]byte, error) {
	if data == nil || len(data) == 0 {
		return nil, ErrParameter
	}
	weight := BcryptDefaultCost
	if bWeight != nil {
		value, ok := bWeight.(int)
		if !ok {
			return nil, ErrParameter
		}
		weight = value
	}

	resultBuf, err := bcrypt.GenerateFromPassword(data, weight)
	if err != nil {
		return nil, fmt.Errorf("failed to generated bcrypt of value in passwordHashBcrypt.Create - %w", err)
	}

	return resultBuf, nil
}

// Verify method from the Auth interface
func (p *passwordHashBcrypt) Verify(value []byte, digest interface{}) ([]byte, interface{}, error) {
	if value == nil || len(value) == 0 {
		return nil, nil, ErrParameter
	}
	if digest == nil {
		return nil, nil, ErrParameter
	}

	bcryptBuf, ok := digest.([]byte)
	if !ok || len(bcryptBuf) == 0 {
		return nil, nil, ErrParameter
	}
	cost, err := bcrypt.Cost(bcryptBuf)
	if err != nil {
		return nil, nil, fmt.Errorf("format error in supplied bcrypt digest in passwordHashBcrypt.Verify - %w", err)
	}

	err = bcrypt.CompareHashAndPassword(bcryptBuf, value)
	if err != nil {
		err = fmt.Errorf("validation failed in passwordHashBcrypt.Verify - %w", err)
	}

	return bcryptBuf, cost, err
}

// NewPasswordHash Configures the respective password Hashing algorithm and
// returns the instance which implements the Auth Interface
func NewPasswordHash(method string, key interface{}) (Auth, error) {
	switch method {
	case MethodPasswordHashBcrypt:
		ret := &passwordHashBcrypt{}
		err := ret.Set(method, key)
		return ret, err
	}
	return nil, ErrNotImplemented
}
