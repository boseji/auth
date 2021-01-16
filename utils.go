// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/gofrs/uuid/v3"
)

// For Mock
var readFull = io.ReadFull

// GetRandom returns a cryptographically safe randome numbers byte array
// with the size specified
func GetRandom(size int) ([]byte, error) {
	if size <= 0 {
		return nil, ErrParameter
	}

	buf := make([]byte, size)
	_, err := readFull(rand.Reader, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Random numbers - %w", err)
	}

	return buf, nil
}

// For Mock
var uuidFn = uuid.NewV4

// UUIDv4 function helps to generate UUID using V4 algorithm
func UUIDv4() (string, error) {
	u, err := uuidFn()
	if err != nil {
		return "", fmt.Errorf("failed to generate new UUID in UUIDv4 - %w", err)
	}
	return u.String(), nil
}
