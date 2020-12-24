// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

// Package auth is a authentication helper that supports multiple types of
// applications.
package auth

import (
	"fmt"
)

// Auth is the generic interface that would be implemented by the various
// authentication algorithms and classifications.
//
// The term "Authentication Entity" refers to a token, pass, or a Unique piece
// of information that provides Identity, and Authorization status of the
// bearer.
type Auth interface {

	// Create function generates the Authentication Entity by processing
	// incoming data and the specific 'bias'.
	Create(data []byte, bias interface{}) ([]byte, error)

	// Verify function checks the Authentication Entity by processing
	// it with the optional incoming 'bias'. It also recovers the original
	// 'data' and 'bias' used to create the Authentication Entity.
	Verify(value []byte, bias interface{}) ([]byte, interface{}, error)

	// Set function configures the Authentication Entity creation and
	// verification process. It also accepts the static "Key" that needs
	// to be employed while processing the Authentication Entity.
	Set(method string, key interface{}) error
}

// ErrParameter occurs when there are issues with the supplied parameter
// in any function.
var ErrParameter = fmt.Errorf("error in supplied parameters")

// ErrNotInitialized occurs when an Authentication process or function
// tries to access an un-initialized data parameter or construct.
var ErrNotInitialized = fmt.Errorf("error this construct is not initialized")

// ErrNotImplemented occurs when an Un-implemented feature is called on
var ErrNotImplemented = fmt.Errorf("error functionality not implemented yet")
