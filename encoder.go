// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
)

// EncodeIt is the String format encode function for byte Array encoders
type EncodeIt struct {
	Name string
	// To(EncodeToString) converts the Supplied byte array to the specific
	// encode Format string
	To func(src []byte) string

	// From(DecodeString) converts the Supplied string back to its byte array form
	From func(s string) ([]byte, error)
}

// List of Encoders -
var encoders = map[string]*EncodeIt{}

// Lock for the Encoder List
var encodersLock = new(sync.RWMutex)

// RegisterEncoder updates the list of Encoders available.
// This is typically called during init() stage.
func RegisterEncoder(f *EncodeIt) {
	encodersLock.Lock()
	defer encodersLock.Unlock()

	encoders[f.Name] = f
}

// GetEncoder fetches the specific encoder from the List of Encoders
func GetEncoder(name string) (f *EncodeIt) {
	encodersLock.RLock()
	defer encodersLock.RUnlock()

	if encodeF, ok := encoders[name]; ok {
		f = encodeF
	}
	return f
}

// List of Encoders Supported
var (
	Hex       *EncodeIt
	Base64    *EncodeIt
	Base64URL *EncodeIt
)

func init() {
	Hex = &EncodeIt{
		Name: "Hex",
		To:   hex.EncodeToString,
		From: hex.DecodeString,
	}
	RegisterEncoder(Hex)

	Base64 = &EncodeIt{
		Name: "Base64STD",
		To:   base64.StdEncoding.EncodeToString,
		From: base64.StdEncoding.DecodeString,
	}
	RegisterEncoder(Base64)

	Base64URL = &EncodeIt{
		Name: "Base64URL",
		To:   base64.URLEncoding.EncodeToString,
		From: base64.URLEncoding.DecodeString,
	}
	RegisterEncoder(Base64URL)
}

// Encode is Generic EncodeToString function for All byte Arrays
func Encode(f *EncodeIt, data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Helps to Mock the Functions
	e := GetEncoder(f.Name)
	if e == nil {
		return ""
	}

	return e.To(data)
}

// Decode is the Generic DecodeFromString function for all encoded values supported
func Decode(f *EncodeIt, value string) ([]byte, error) {
	if value == "" {
		return nil, ErrParameter
	}

	// Helps to Mock the Functions
	e := GetEncoder(f.Name)
	if e == nil {
		return nil, ErrNotImplemented
	}

	return e.From(value)
}

// Create method from the Auth Interface
func (e *EncodeIt) Create(data []byte, encode interface{}) (output []byte, err error) {
	en, ok := encode.(bool)
	if !ok {
		return nil, ErrParameter
	}

	if en {
		result := Encode(e, data)
		if result == "" {
			return nil, fmt.Errorf("failed to encode in EncodeIt.Create")
		}
		return []byte(result), nil
	}
	return Decode(e, string(data))
}

// Verify method from the Auth Interface
func (e *EncodeIt) Verify(value []byte, bias interface{}) (data []byte, iBias interface{}, err error) {
	return nil, nil, ErrNotSupported
}

// Set Method from the Auth Interface
func (e *EncodeIt) Set(method string, key interface{}) error {
	return ErrNotSupported
}
