// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHash is used to generated cryptographically secure digest
// from the supplied password and also verify the digest.

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

// MethodPasswordHashPbkdf2HS256 defines password hash generation using
// pbkdf2 with HMAC-SHA256
const MethodPasswordHashPbkdf2HS256 = "Password Hash using pbkdf2 and HMAC-SHA256"

const (
	// Pbkdf2DefaultRounds Default number of rounds to be used for PBKDF2
	Pbkdf2DefaultRounds int = 4096
	// Pbkdf2MaxRounds Maximum number of rounds to be used for PBKDF2
	Pbkdf2MaxRounds int = 8192
	// Pbkdf2MinRounds Minimum number of rounds to be used for PBKDF2
	Pbkdf2MinRounds int = 1024
)

////////////////////////////////////////////////////////////////////////////////

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
		if !ok || value <= 0 {
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

////////////////////////////////////////////////////////////////////////////////

type passwordHashPbkdf2HS256 struct{}

// Set method from the Auth interface
func (p *passwordHashPbkdf2HS256) Set(method string, _ interface{}) error {
	if method != MethodPasswordHashPbkdf2HS256 {
		return ErrParameter
	}
	return nil
}

// Create method from the Auth interface
func (p *passwordHashPbkdf2HS256) Create(data []byte, bRounds interface{}) ([]byte, error) {
	if data == nil || len(data) == 0 {
		return nil, ErrParameter
	}
	rounds := Pbkdf2DefaultRounds
	if bRounds != nil {
		value, ok := bRounds.(int)
		if !ok || value <= 0 {
			return nil, ErrParameter
		}
		rounds = value
	}

	dk, salt, err := Pbkdf2HS256(data, rounds)
	if err != nil {
		return nil, fmt.Errorf("failed in PBKDF2 generation in passwordHashPbkdf2HS256.Create - %w", err)
	}

	// Prepare for Result Array
	result := bytes.NewBuffer(nil)
	resultRound := uint64(rounds)

	// Fill the Rounds
	for i := 0; i < Pbkdf2RoundsSize; i++ {
		err = result.WriteByte(byte(resultRound & uint64(0x0FF)))
		if err != nil {
			return nil, fmt.Errorf("error in writing rounds in passwordHashPbkdf2HS256.Create -%w", err)
		}
		resultRound >>= 8 // LSByte first so shifting down
	}

	_, err = result.Write(salt)
	if err != nil {
		return nil, fmt.Errorf("error in writing salt in passwordHashPbkdf2HS256.Create -%w", err)
	}
	_, err = result.Write(dk)
	if err != nil {
		return nil, fmt.Errorf("error in writing derived key in passwordHashPbkdf2HS256.Create -%w", err)
	}

	return result.Bytes(), nil
}

// Verify method from the Auth interface
func (p *passwordHashPbkdf2HS256) Verify(value []byte, digest interface{}) ([]byte, interface{}, error) {
	if value == nil || len(value) == 0 {
		return nil, nil, ErrParameter
	}
	if digest == nil {
		return nil, nil, ErrParameter
	}

	sourceBuf, ok := digest.([]byte)
	if !ok || len(sourceBuf) != (sha256.Size+Pbkdf2SaltSize+Pbkdf2RoundsSize) {
		return nil, nil, ErrParameter
	}

	source := bytes.NewReader(sourceBuf)
	bRounds := uint64(0)
	// Read Rounds
	for i := 0; i < Pbkdf2RoundsSize; i++ {
		bRounds >>= 8 // To Move the Upper byte Down
		b, err := source.ReadByte()
		if err != nil {
			return nil, nil, fmt.Errorf("error in reading rounds in passwordHashPbkdf2HS256.Verify -%w", err)
		}
		bRounds |= uint64(b) << 56 // Initially fix the Data the top most byte
	}

	sourceRounds := int(bRounds)

	sourceSalt := make([]byte, Pbkdf2SaltSize)
	n, err := source.Read(sourceSalt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read salt in passwordHashPbkdf2HS256.Verify - %w", err)
	}
	if n != Pbkdf2SaltSize {
		return nil, nil, fmt.Errorf("incorrect salt in passwordHashPbkdf2HS256.Verify - %w", err)
	}

	sourceDerviedKey := make([]byte, sha256.Size)
	n, err = source.Read(sourceDerviedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read derived key in passwordHashPbkdf2HS256.Verify - %w", err)
	}
	if n != sha256.Size {
		return nil, nil, fmt.Errorf("incorrect derived key in passwordHashPbkdf2HS256.Verify - %w", err)
	}

	err = CheckPbkdf2HS256(value, sourceDerviedKey, sourceSalt, sourceRounds)
	if err != nil {
		return nil, nil, fmt.Errorf("verification failed in passwordHashPbkdf2HS256.Verify - %w", err)
	}

	return sourceBuf, sourceRounds, err
}

////////////////////////////////////////////////////////////////////////////////

// NewPasswordHash Configures the respective password Hashing algorithm and
// returns the instance which implements the Auth Interface
func NewPasswordHash(method string, key interface{}) (Auth, error) {
	var ret Auth

	switch method {
	case MethodPasswordHashBcrypt:
		ret = &passwordHashBcrypt{}
	case MethodPasswordHashPbkdf2HS256:
		ret = &passwordHashPbkdf2HS256{}
	default:
		return nil, ErrNotImplemented
	}

	err := ret.Set(method, key)
	return ret, err
}
