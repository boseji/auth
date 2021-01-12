// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

// PasswordHash is used to generated cryptographically secure digest
// from the supplied password and also verify the digest.
func PasswordHash(d DigestIt, pass string, opts ...DigestOptions) ([]byte, error) {
	return Digest(d, []byte(pass), opts...)
}

// PasswordCheck function is used to verify the password against the precalculated
// digest.
func PasswordCheck(d DigestIt, pass string, dig []byte, opts ...DigestOptions) error {
	if opts == nil {
		opts = []DigestOptions{}
	}
	opt := make([]DigestOptions, len(opts)+1)
	copy(opt, opts)

	// Add the Digest at the End
	opt[len(opts)] = WithDigest(dig)

	_, err := Digest(d, []byte(pass), opt...)
	return err
}
