// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"fmt"
	"time"

	"gopkg.in/dgrijalva/jwt-go.v3"
)

// hsTokenFn Implements the JWT for HS256, HS384 and HS512 type tokens
type hsTokenFn struct {
	*hashFn
	timeout    time.Duration
	expiry     time.Time
	withExpiry bool
	ID         string
	Audience   string
	Issuer     string
	Subject    string
}

// HSTokenClaims provides the required storage for JWT claims
type HSTokenClaims struct {
	Session string `json:"session"`
	jwt.StandardClaims
}

// HSTokenOptions provides the functional options for the GetHSToken function
type HSTokenOptions func(*hsTokenFn) *hsTokenFn

const (

	// HSTokenDefaultExpiry specifies the Minimum duration for which HSToken is valid
	HSTokenDefaultExpiry = 1 * time.Minute
)

// valid method verifies the data and assign default values
func (h *hsTokenFn) valid() error {
	if h.timeout == 0 && !h.withExpiry {
		h.timeout = HSTokenDefaultExpiry
	}
	// Supplied Expiry time is in the past
	if h.withExpiry && time.Now().After(h.expiry) {
		return ErrParameter
	}
	return nil
}

// getAlgorithm method to obtain the Signing algorithm using hashing method
func (h *hsTokenFn) getAlgorithm() (*jwt.SigningMethodHMAC, error) {
	if h.hashFn == nil {
		return nil, ErrParameter
	}

	switch h.hashFn.Name() {
	case MethodSHA256:
		return jwt.SigningMethodHS256, nil
	case MethodSHA384:
		return jwt.SigningMethodHS384, nil
	case MethodSHA512:
		return jwt.SigningMethodHS512, nil
	default:
		return nil, fmt.Errorf("failed to get Hash function in GetHSToken - %w", ErrNotSupported)
	}
}

// GetClaims function copies the data and generates a custom token for JWT
func (h *hsTokenFn) getClaims(session string) (*HSTokenClaims, error) {
	t := &HSTokenClaims{
		Session: session,
	}

	err := h.valid()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	t.IssuedAt = now.Unix()
	if h.withExpiry {
		t.ExpiresAt = h.expiry.Unix()
	} else {
		t.ExpiresAt = now.Add(h.timeout).Unix()
	}

	if h.ID != "" {
		t.Id = h.ID
	}

	if h.Audience != "" {
		t.Audience = h.Audience
	}

	if h.Issuer != "" {
		t.Issuer = h.Issuer
	}

	if h.Subject != "" {
		t.Subject = h.Subject
	}

	return t, nil
}

// Valid method for the `jwt.Claims` Interface
func (c *HSTokenClaims) Valid() error {
	ex := c.ExpiresAt
	t := time.Unix(ex, 0)
	if time.Now().After(t) {
		return fmt.Errorf("token has already expired")
	}
	return nil
}

// HSTokenExpiry functional option sets the Exact Expiry time of the token
func HSTokenExpiry(ex time.Time) HSTokenOptions {
	return func(tf *hsTokenFn) *hsTokenFn {
		tf.expiry = ex
		tf.withExpiry = true
		return tf
	}
}

// HSTokenDuration functional option sets the Duration after which the token expires
func HSTokenDuration(d time.Duration) HSTokenOptions {
	return func(tf *hsTokenFn) *hsTokenFn {
		tf.timeout = d
		tf.withExpiry = false
		return tf
	}
}

// HSTokenWith functional option sets the additional parameters in the JWT token
func HSTokenWith(ID, audience, issuer, subject string) HSTokenOptions {
	return func(tf *hsTokenFn) *hsTokenFn {
		tf.ID = ID
		tf.Audience = audience
		tf.Issuer = issuer
		tf.Subject = subject
		return tf
	}
}

// For Mock
var getHSTokenSigned = newHSTokenSigned

// newHSTokenSigned helps to Moc the Errors in Signing
func newHSTokenSigned(method jwt.SigningMethod, claims jwt.Claims, key []byte) (string, error) {
	tok := jwt.NewWithClaims(method, claims)
	return tok.SignedString(key)
}

// GetHSToken function Provides a way to generate a JWT of HS256, HS384 and HS512 type tokens
func GetHSToken(session string, key []byte, d DigestIt, opt ...HSTokenOptions) (string, error) {

	if len(key) == 0 {
		return "", ErrParameter
	}

	// Default HS256
	h := &hsTokenFn{
		hashFn: Sha256,
	}

	// Get the Passed Hash method
	if d != nil {
		t, ok := d.(*hashFn)
		if !ok {
			return "", fmt.Errorf("failed to get Hash function in GetHSToken")
		}
		h.hashFn = t
	}

	// Find the Signing Algorithm
	alg, err := h.getAlgorithm()
	if err != nil {
		return "", fmt.Errorf("failed to get Hash algorithm in CheckHSToken - %w", err)
	}

	// Process the hsTokenFn with Options
	if len(opt) > 0 {
		for _, oFn := range opt {
			h = oFn(h)
		}
	}

	// Create the Claims
	claims, err := h.getClaims(session)
	if err != nil {
		return "", fmt.Errorf("failed to get claims in GetHSToken - %w", err)
	}

	signedToken, err := getHSTokenSigned(alg, claims, key)
	if err != nil {
		return "", fmt.Errorf("failed to sign Token in GetHSToken - %w", err)
	}

	return signedToken, nil
}

// CheckHSToken function provides a way to verify the signed token and decode
//  the underlying data.
func CheckHSToken(signedToken string, key []byte, d DigestIt) (
	session string,
	claim *HSTokenClaims,
	err error,
) {

	if signedToken == "" || key == nil || len(key) == 0 || d == nil {
		return "", nil, ErrParameter
	}

	// Default
	h := &hsTokenFn{
		hashFn: Sha256,
	}

	// Get the Passed Hash method
	if d != nil {
		t, ok := d.(*hashFn)
		if !ok {
			return "", nil, fmt.Errorf("failed to get Hash function in CheckHSToken")
		}
		h.hashFn = t
	}

	// Find the Signing Algorithm
	alg, err := h.getAlgorithm()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get Hash algorithm in CheckHSToken - %w", err)
	}

	// Get the Token
	t, err := jwt.ParseWithClaims(
		signedToken,
		&HSTokenClaims{},
		func(tok *jwt.Token) (interface{}, error) {
			if tok.Method.Alg() != alg.Alg() {
				return nil, fmt.Errorf("invalid signing method")
			}
			return key, nil
		},
	)
	if err != nil {
		return "", nil, fmt.Errorf("failed to process the token in CheckHSToken - %w", err)
	}

	// Check the Validity
	if !t.Valid {
		return "", nil, fmt.Errorf("failed to process the token in CheckHSToken - Not valid")
	}

	// Convert the Claims
	claim, ok := t.Claims.(*HSTokenClaims)
	if !ok {
		return "", nil, fmt.Errorf("failed to process the token in CheckHSToken")
	}

	return claim.Session, claim, nil
}
