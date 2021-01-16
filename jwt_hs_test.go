// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"reflect"
	"testing"
	"time"

	"gopkg.in/dgrijalva/jwt-go.v3"
)

func mockGetHSTokenSigned(method jwt.SigningMethod, claims jwt.Claims, key []byte) (string, error) {
	return "", ErrNotSupported
}

func TestHSToken_Basic(t *testing.T) {
	key := []byte("your-256-bit-secret")
	session := "Test"
	type args struct {
		session string
		key     []byte
		d       DigestIt
		opt     []HSTokenOptions
	}
	type fields struct {
		ID       string
		Audience string
		Issuer   string
		Subject  string
	}
	tests := []struct {
		name        string
		args        args
		fieldsCheck bool
		fields      fields
	}{
		{
			name: "SHA256 no Arguments",
			args: args{
				session: session,
				key:     key,
				d:       Sha256,
			},
		},
		{
			name: "SHA384 no Arguments",
			args: args{
				session: session,
				key:     key,
				d:       Sha384,
			},
		},
		{
			name: "SHA512 no Arguments",
			args: args{
				session: session,
				key:     key,
				d:       Sha512,
			},
		},
		{
			name: "SHA256 with Expiry",
			args: args{
				session: session,
				key:     key,
				d:       Sha256,
				opt: []HSTokenOptions{
					HSTokenExpiry(time.Now().Add(1 * time.Second)),
				},
			},
		},
		{
			name: "SHA256 with Duration",
			args: args{
				session: session,
				key:     key,
				d:       Sha256,
				opt: []HSTokenOptions{
					HSTokenDuration(1 * time.Second),
				},
			},
		},
		{
			name: "SHA256 with Custom Fields",
			args: args{
				session: session,
				key:     key,
				d:       Sha256,
				opt: []HSTokenOptions{
					HSTokenWith("ID", "Aud", "Test", "Testing"),
				},
			},
			fieldsCheck: true,
			fields: fields{
				ID:       "ID",
				Audience: "Aud",
				Issuer:   "Test",
				Subject:  "Testing",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := GetHSToken(tt.args.session, tt.args.key, tt.args.d, tt.args.opt...)
			if err != nil {
				t.Errorf("Failed to get Token - %w", err)
				return
			}
			st, claims, err := CheckHSToken(s, tt.args.key, tt.args.d)
			if err != nil {
				t.Errorf("Failed to check Token - %w", err)
				return
			}
			if !reflect.DeepEqual(st, tt.args.session) {
				t.Errorf("Error in GetHSToken() and CheckHSToken() - Expected %v , Got %v", session, st)
				return
			}
			if claims == nil {
				t.Errorf("Error in CheckHSToken() did not get the claims")
				return
			}
			if tt.fieldsCheck && !reflect.DeepEqual(tt.fields.ID, claims.Id) {
				t.Errorf("Error in CheckHSToken() Claims ID - Expected %v , Got %v", tt.fields.ID, claims.Id)
				return
			}
			if tt.fieldsCheck && !reflect.DeepEqual(tt.fields.Audience, claims.Audience) {
				t.Errorf("Error in CheckHSToken() Claims Audience - Expected %v , Got %v", tt.fields.Audience, claims.Audience)
				return
			}
			if tt.fieldsCheck && !reflect.DeepEqual(tt.fields.Issuer, claims.Issuer) {
				t.Errorf("Error in CheckHSToken() Claims Issuer - Expected %v , Got %v", tt.fields.Issuer, claims.Issuer)
				return
			}
			if tt.fieldsCheck && !reflect.DeepEqual(tt.fields.Subject, claims.Subject) {
				t.Errorf("Error in CheckHSToken() Claims Subject - Expected %v , Got %v", tt.fields.Subject, claims.Subject)
				return
			}
		})
	}
}

func TestGetHSToken(t *testing.T) {
	key := []byte("your-256-bit-secret")
	type args struct {
		session string
		key     []byte
		d       DigestIt
		opt     []HSTokenOptions
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "No Key",
			wantErr: true,
		},
		{
			name: "Empty Key",
			args: args{
				key: []byte{},
			},
			wantErr: true,
		},
		{
			name: "Unsupported Hash Function",
			args: args{
				key: key,
				d:   Bcrypt,
			},
			wantErr: true,
		},
		{
			name: "Bad Hash Function",
			args: args{
				key: key,
				d:   Sha1,
			},
			wantErr: true,
		},
		{
			name: "Expired time Error",
			args: args{
				key: key,
				d:   Sha256,
				opt: []HSTokenOptions{
					HSTokenExpiry(time.Now().Add(-1 * time.Minute)),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetHSToken(tt.args.session, tt.args.key, tt.args.d, tt.args.opt...)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHSToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetHSToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetHSToken_Misc(t *testing.T) {
	t.Run("Failure in Claims", func(t *testing.T) {
		// Mock the Creation function
		orig := getHSTokenSigned
		getHSTokenSigned = mockGetHSTokenSigned
		defer func() { getHSTokenSigned = orig }()

		_, err := GetHSToken("", []byte("test"), Sha256)
		if err == nil {
			t.Errorf("GetHSToken() Got Nil, Expected error")
		}
	})
}

func TestCheckHSToken(t *testing.T) {
	key := []byte("your-256-bit-secret")
	type argsGen struct {
		key   []byte
		alg   jwt.SigningMethod
		claim jwt.Claims
	}
	type args struct {
		signedToken string
		key         []byte
		d           DigestIt
	}
	tests := []struct {
		name        string
		args        args
		usingGen    bool
		argsGen     argsGen
		wantSession string
		wantClaim   *HSTokenClaims
		wantErr     bool
		checkClaims bool
	}{
		{
			name: "Blank Signed string",
			args: args{
				signedToken: "",
			},
			wantErr: true,
		},
		{
			name:     "No Key",
			usingGen: true,
			argsGen: argsGen{
				key:   key,
				alg:   jwt.SigningMethodHS256,
				claim: &jwt.StandardClaims{},
			},
			wantErr: true,
		},
		{
			name: "Empty Key",
			args: args{
				key: []byte{},
			},
			usingGen: true,
			argsGen: argsGen{
				key:   key,
				alg:   jwt.SigningMethodHS256,
				claim: &jwt.StandardClaims{},
			},
			wantErr: true,
		},
		{
			name: "No Digest method",
			args: args{
				key: key,
			},
			usingGen: true,
			argsGen: argsGen{
				key:   key,
				alg:   jwt.SigningMethodHS256,
				claim: &jwt.StandardClaims{},
			},
			wantErr: true,
		},
		{
			name: "Bad Digest method",
			args: args{
				key: key,
				d:   Bcrypt,
			},
			usingGen: true,
			argsGen: argsGen{
				key:   key,
				alg:   jwt.SigningMethodHS256,
				claim: &jwt.StandardClaims{},
			},
			wantErr: true,
		},
		{
			name: "Unsupported method",
			args: args{
				key: key,
				d:   Sha1,
			},
			usingGen: true,
			argsGen: argsGen{
				key:   key,
				alg:   jwt.SigningMethodHS256,
				claim: &jwt.StandardClaims{},
			},
			wantErr: true,
		},
		{
			name: "Wrong Algorithm type",
			args: args{
				key: key,
				d:   Sha384,
			},
			usingGen: true,
			argsGen: argsGen{
				key: key,
				alg: jwt.SigningMethodHS256,
				claim: &jwt.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Second).Unix(),
				},
			},
			wantErr: true,
		},
		{
			name: "Expired Token",
			args: args{
				key: key,
				d:   Sha256,
			},
			usingGen: true,
			argsGen: argsGen{
				key: key,
				alg: jwt.SigningMethodHS256,
				claim: &jwt.StandardClaims{
					ExpiresAt: time.Now().Add(-1 * time.Minute).Unix(),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := tt.args.signedToken
			if tt.usingGen {
				var err error
				tok := jwt.NewWithClaims(tt.argsGen.alg, tt.argsGen.claim)
				ss, err = tok.SignedString(tt.argsGen.key)
				if err != nil {
					t.Errorf("Failed to Generate Signed Token")
					return
				}
			}
			gotSession, gotClaim, err := CheckHSToken(ss, tt.args.key, tt.args.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckHSToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotSession != tt.wantSession {
				t.Errorf("CheckHSToken() gotSession = %v, want %v", gotSession, tt.wantSession)
			}
			if tt.checkClaims && !reflect.DeepEqual(gotClaim, tt.wantClaim) {
				t.Errorf("CheckHSToken() gotClaim = %v, want %v", gotClaim, tt.wantClaim)
			}
		})
	}
}
