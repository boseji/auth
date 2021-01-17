// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

// Package dec provides an easy way to decide data from multiple
// commonly used formats such as Hex and Base64. It wraps the standard library
// packages such as encoding/base32 and encoding/base64 into easy to use
// functions.
package dec

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/boseji/auth"
)

// Base64 function decodes the supplied Base64 Standard encoding
// formatted string to its source data.
func Base64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// Base64URL function decodes the Base64 URL encoded string
// to its source data.
func Base64URL(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

// Base32 function decodes the supplied standard base32 encoded string
// back to its source data.
func Base32(s string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(s)
}

// Base32Hex function decodes the supplied "Extended Hex Alphabet" based
// base32 encoded string back to its source data.
func Base32Hex(s string) ([]byte, error) {
	return base32.HexEncoding.DecodeString(s)
}

// Hex function decodes the supplied Hex encoded string back to its source data
func Hex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// JSON function decodes the supplied JSON string to fill result storage
// provided by reference. In case the size of reference in case of slice
// is not sufficient it would reallocated.
// The Reference provided here must be a pointer to the type of data
// representted in the JSON string.
// The decoded value is returned in the reference 'result' variable.
func JSON(s string, result interface{}) error {
	if result == nil {
		return auth.ErrParameter
	}
	err := json.Unmarshal([]byte(s), result)
	if err != nil {
		return err
	}

	return nil
}
