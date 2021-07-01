// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// pbkdf2 implementation with Easy to use functions

// pbkdf2Fn helps to perform the PBKDF2 key derivation. It implements the Auth
// interface
type pbkdf2Fn struct {
	rounds int
	size   int
	salt   []byte
}

// Pbkdf2Options type provides a way to create functional options for PBKDF2
type Pbkdf2Options func(*pbkdf2Fn) *pbkdf2Fn

const (
	// Pbkdf2MinSize defines the minimum size of the Salt and Output
	Pbkdf2MinSize = 8
	// Pbkdf2MinRounds defines the minimum number of iterations for the
	// PBKDF2 key derivation process
	Pbkdf2MinRounds = 8
)

// check method helps to verify that the options set are correct
func (p *pbkdf2Fn) check() (err error) {
	if p.rounds < Pbkdf2MinRounds {
		p.rounds = Pbkdf2MinRounds
	}
	if p.size < Pbkdf2MinSize {
		p.size = Pbkdf2MinSize
	}
	if p.salt != nil && len(p.salt) < Pbkdf2MinSize {
		return ErrParameter
	}
	if p.salt == nil {
		p.salt, err = GetRandom(Pbkdf2MinSize)
	}
	return err
}

// Pbkdf2With sets the number of rounds and output size of the PBKDF2
func Pbkdf2With(rounds, size int) Pbkdf2Options {
	return func(p *pbkdf2Fn) *pbkdf2Fn {
		p.rounds = rounds
		p.size = size
		return p
	}
}

// Pbkdf2Salt sets a fixed salt for PBKDF2 Key derivation
func Pbkdf2Salt(buf []byte) Pbkdf2Options {
	return func(p *pbkdf2Fn) *pbkdf2Fn {
		if buf != nil {
			p.salt = make([]byte, len(buf))
			copy(p.salt, buf)
		}
		return p
	}
}

// Pbkdf2 function performs the PBKDF2 operation with given optional functions
func Pbkdf2(password []byte, d DigestIt, opt ...Pbkdf2Options) (
	result []byte,
	salt []byte,
	err error,
) {
	if len(password) == 0 {
		return nil, nil, ErrParameter
	}

	// Default Hash
	h := Sha256

	if d != nil {
		switch d.Name() {
		case MethodSHA1, MethodSHA224, MethodSHA256:
			fallthrough
		case MethodSHA384, MethodSHA512:
			ht, ok := d.(*hashFn)
			if !ok {
				return nil, nil, fmt.Errorf("failed to get hash function for Pbkdf2")
			}
			h = ht
		default:
			return nil, nil, ErrNotSupported
		}
	}

	options := &pbkdf2Fn{}
	if len(opt) > 0 {
		for _, oFn := range opt {
			options = oFn(options)
		}
	}
	err = options.check()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify options for Pbkdf2 - %w", err)
	}

	dk := pbkdf2.Key(password, options.salt, options.rounds, options.size, h.New)

	return dk, options.salt, nil
}
