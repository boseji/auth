// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"sync"
	"time"
)

// JwtAlgorithm defines the way in which the JWT is calculated and verified
type JwtAlgorithm interface {

	// CreateToken helps to Create a token using supplied data in the from of map of string
	// and supplied options.
	CreateToken(string, ...func(JwtAlgorithm) JwtAlgorithm) (string, error)
	VerifyToken(string, ...func(JwtAlgorithm) JwtAlgorithm) (string, error)
}

// JwtAlgorithmOptions is used to implement the JWT Option for Functional parameters
// of each Algorithm
type JwtAlgorithmOptions func(JwtAlgorithm) JwtAlgorithm

// JWTDefaultIDSize defines the default size for the JWT ID
const JWTDefaultIDSize int = 32

// JWTDefaultDuration defines the default duration for a Token
const JWTDefaultDuration = 1 * time.Minute

// JwtMethod defines the way in which the JWT is Calculated
type JwtMethod Auth

// Global Array of Methods - Useful for Mock
var jwtMethods = map[string]func() JwtMethod{}

// Exclusion Framework
var jwtMethodsLock = new(sync.RWMutex)

// RegisterJwtMethod registers a given Method name and a factory function for
// registering into the list JWT processing methods.
// This is only called during init.
func RegisterJwtMethod(name string, f func() JwtMethod) {
	jwtMethodsLock.Lock()
	defer jwtMethodsLock.Unlock()

	jwtMethods[name] = f
}

// GetJwtMethod helps to fetch the JWT Method via its name
func GetJwtMethod(name string) (method JwtMethod) {
	jwtMethodsLock.RLock()
	defer jwtMethodsLock.Unlock()

	if methodF, ok := jwtMethods[name]; ok {
		method = methodF()
	}

	return nil
}

// // MethodJwtHS256 defines the process of JWT generation and verification using
// // HMAC SHA-256
// const MethodJwtHS256 = "JWT using HMAC SHA-256"

// // JwtOptions stores the parameters that govern the JWT Creation and Verification
// type JwtOptions struct {
// 	jwt.StandardClaims
// 	validFor time.Duration
// }

// // GenerateID implements the Random unique ID generation or using UUID-V4 Algorithm
// func (j *JwtOptions) GenerateID(byUUID bool, size int) error {
// 	if byUUID {
// 		u, err := uuidV4()
// 		if err != nil {
// 			return fmt.Errorf("failed to generate uuid in JwtOptions.GenerateID - %w", err)
// 		}
// 		j.Id = u
// 		return nil
// 	}

// 	if size <= 0 {
// 		return ErrParameter
// 	}

// 	uid, err := getRandom(size)
// 	if err != nil {
// 		return fmt.Errorf("failed to generated random UID in JwtOptions.GenerateID - %w", err)
// 	}

// 	j.Id, err = toBase64(uid)
// 	if err != nil {
// 		return fmt.Errorf("failed to convert random UID to Base64 in JwtOptions.GenerateID - %w", err)
// 	}
// 	return nil
// }

// // SetValidity sets the period of validity for the JWT
// func (j *JwtOptions) SetValidity(dur time.Duration) {
// 	now := time.Now()
// 	j.validFor = dur
// 	j.NotBefore = now.Unix()
// 	j.IssuedAt = now.Unix()
// 	j.ExpiresAt = now.Add(dur).Unix()
// }

// // UpdateValidity updates the time parameters of the JWT
// func (j *JwtOptions) UpdateValidity() {
// 	if j.validFor != 0 {
// 		j.SetValidity(j.validFor)
// 	}
// }

// // NewJwtOptions creates the JwtOptions data with specific parameters
// func NewJwtOptions(generateByUUID bool, validity time.Duration) (*JwtOptions, error) {
// 	ret := &JwtOptions{}
// 	err := ret.GenerateID(generateByUUID, JwtDefaultIDSize)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to Generate ID in NewJwtOptions - %w", err)
// 	}
// 	ret.SetValidity(validity)
// 	return ret, nil
// }

// ////////////////////////////////////////////////////////////////////////////////

// // CustomClaims - Claims for HS256
// type CustomClaims struct {
// 	Session string `json:"session"`
// 	jwt.StandardClaims
// }

// // Valid method Data validation for Custom Claims as per Claims Interface
// func (j *CustomClaims) Valid() error {
// 	if j.Session == "" || j.Id == "" || j.ExpiresAt == 0 || j.IssuedAt == 0 {
// 		return ErrNotInitialized
// 	}
// 	return nil
// }

// ////////////////////////////////////////////////////////////////////////////////

// // JwtHS256 - JWT Implementation using HS256
// type JwtHS256 struct {
// 	key []byte
// }

// // Set method implementation from Auth interface
// func (j *JwtHS256) Set(method string, key interface{}) error {
// 	if method != MethodJwtHS256 || key == nil {
// 		return ErrParameter
// 	}

// 	keyArray, ok := key.([]byte)
// 	if !ok || len(keyArray) != sha256.Size {
// 		return ErrParameter
// 	}

// 	j.key = keyArray
// 	return nil
// }

// // Create method from the Auth interface
// func (j *JwtHS256) Create(data []byte, bOptions interface{}) ([]byte, error) {
// 	if data == nil || bOptions == nil || len(data) == 0 || j.key == nil {
// 		return nil, ErrParameter
// 	}

// 	options, ok := bOptions.(*JwtOptions)
// 	if !ok {
// 		return nil, ErrParameter
// 	}

// 	bString, err := toBase64(data)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to base64 data in JwtHS256.Create - %w", err)
// 	}

// 	claims := &CustomClaims{
// 		Session:        bString,
// 		StandardClaims: options.StandardClaims,
// 	}
// 	if err := claims.Valid(); err != nil {
// 		return nil, fmt.Errorf("invalid options in JwtHS256.Create - %w", err)
// 	}

// 	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

// 	signedStr, err := t.SignedString(j.key)
// 	if err != nil {
// 		return nil, fmt.Errorf("couldn't get Signed String in JwtHS256.Create - %w", err)
// 	}
// 	return []byte(signedStr), nil
// }

// // Test function used during verification of Token
// func (j *JwtHS256) testTokenKey(token *jwt.Token) (interface{}, error) {
// 	// Check Alg Type
// 	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
// 	}
// 	// Check the Actual Algorithm
// 	if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
// 		return nil, fmt.Errorf("Wrong signing method")
// 	}
// 	// Get the Key
// 	key := j.key
// 	return key, nil
// }

// // Verify method from the Auth interface
// func (j *JwtHS256) Verify(value []byte, _ interface{}) ([]byte, interface{}, error) {
// 	if value == nil || string(value) == "" || j.key == nil {
// 		return nil, nil, ErrParameter
// 	}
// 	strToken := string(value)

// 	token, err := jwt.ParseWithClaims(
// 		strToken,
// 		&CustomClaims{},
// 		j.testTokenKey,
// 	)
// 	if err != nil {
// 		return nil, nil,
// 			fmt.Errorf("failed to parse token in JwtHS256.Verify - %w", err)
// 	}
// 	if !token.Valid {
// 		return nil, nil,
// 			fmt.Errorf("filed to verify token in JwtHS256.Verify - %w", err)
// 	}

// 	claims := token.Claims.(*CustomClaims)

// 	if err := claims.Valid(); err != nil {
// 		return nil, nil,
// 			fmt.Errorf("claims invalid in JwtHS256.Verify - %w", err)
// 	}

// 	dur := time.Since(time.Unix(claims.ExpiresAt, 0)) -
// 		time.Since(time.Unix(claims.IssuedAt, 0))

// 	options := &JwtOptions{
// 		StandardClaims: claims.StandardClaims,
// 		validFor:       dur,
// 	}

// 	data, err := fromBase64(claims.Session)
// 	if err != nil {
// 		return nil, options,
// 			fmt.Errorf("failed to process data from token in JwtHS256.Verify - %w", err)
// 	}

// 	return data, options, nil
// }

// ////////////////////////////////////////////////////////////////////////////////

// // NewJWT function creates a New JWT generation and verification unit
// // that follows the Auth interface
// func NewJWT(method string, key interface{}) (Auth, error) {
// 	var ret Auth
// 	switch method {
// 	case MethodJwtHS256:
// 		ret = &JwtHS256{}
// 	default:
// 		return nil, ErrNotImplemented
// 	}

// 	err := ret.Set(method, key)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create JWT unit in NewJWT - %w", err)
// 	}

// 	return ret, err
// }

// ////////////////////////////////////////////////////////////////////////////////

// // CreateJwtHS256 provides a Quick way to generate a JWT using HMAC SHA-256
// func CreateJwtHS256(data string, key []byte, dur time.Duration) (string, error) {
// 	var err error

// 	if key == nil || len(key) == 0 || dur == 0*time.Second {
// 		return "", ErrParameter
// 	}

// 	signKey := key
// 	if len(key) != sha256.Size {
// 		signKey, err = createSHA256(key)
// 		if err != nil {
// 			return "", fmt.Errorf("failed to SHA256 the key in JwtHS256 - %w", err)
// 		}
// 	}

// 	opt, err := NewJwtOptions(true, dur)
// 	if err != nil {
// 		return "", fmt.Errorf("couldn't create options in CreateJwtHS256 - %w", err)
// 	}

// 	j, err := NewJWT(MethodJwtHS256, signKey)
// 	if err != nil {
// 		return "", fmt.Errorf("couldn't create JWT in CreateJwtHS256 - %w", err)
// 	}

// 	buf, err := j.Create([]byte(data), opt)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to JWT sign the token in JwtHS256 - %w", err)
// 	}

// 	return string(buf), nil
// }

// // VerifyJwtHS256 provides a Quick way to Verify the JWT using HMAC SHA-256
// func VerifyJwtHS256(signedStr string, key []byte) (ret []string, err error) {

// 	if signedStr == "" || key == nil || len(key) == 0 {
// 		return nil, ErrParameter
// 	}

// 	signKey := key
// 	if len(key) != sha256.Size {
// 		signKey, err = createSHA256(key)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to SHA256 the key in VerifyJwtHS256 - %w", err)
// 		}
// 	}

// 	j, err := NewJWT(MethodJwtHS256, signKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("couldn't create JWT in VerifyJwtHS256 - %w", err)
// 	}

// 	buf, opt, err := j.Verify([]byte(signedStr), nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("couldn't verify JWT in VerifyJwtHS256 - %w", err)
// 	}

// 	options, ok := opt.(*JwtOptions)
// 	if !ok {
// 		return nil, fmt.Errorf("couldn't fetch options in VerifyJwtHS256 - %w", err)
// 	}

// 	ret = append(ret, string(buf), options.Id)

// 	return ret, nil
// }
