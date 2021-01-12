// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"crypto/sha256"
	"reflect"
	"testing"
)

func TestPbkdf2(t *testing.T) {
	testPassword := []byte("Test Password")
	givenSalt := decHex("b2e9411ad9533410")
	type args struct {
		password []byte
		d        DigestIt
		opt      []Pbkdf2Options
	}
	tests := []struct {
		name       string
		args       args
		wantResult []byte
		wantSalt   []byte
		wantErr    bool
		noCheck    bool
	}{
		{
			name: "No Password",
			args: args{
				password: nil,
			},
			wantErr: true,
		},
		{
			name: "Empty Password",
			args: args{
				password: []byte{},
			},
			wantErr: true,
		},
		{
			name: "No Method",
			args: args{
				password: testPassword,
			},
			noCheck: true,
		},
		{
			name: "With Method SHA1",
			args: args{
				password: testPassword,
				d:        Sha1,
			},
			noCheck: true,
		},
		{
			name: "Wrong or Unsupported HASH function",
			args: args{
				password: testPassword,
				d:        Md5,
			},
			wantErr: true,
		},
		{
			name: "With Rounds and Size using SHA1",
			args: args{
				password: testPassword,
				d:        Sha1,
				opt: []Pbkdf2Options{
					Pbkdf2With(10, 20),
				},
			},
			noCheck: true,
		},
		{
			name: "With Given Salt",
			args: args{
				password: testPassword,
				d:        Sha1,
				opt: []Pbkdf2Options{
					Pbkdf2With(10, 20),
					Pbkdf2Salt(givenSalt),
				},
			},
			noCheck: true,
		},
		{
			name: "With Given Nil Salt",
			args: args{
				password: testPassword,
				d:        Sha1,
				opt: []Pbkdf2Options{
					Pbkdf2With(10, 20),
					Pbkdf2Salt(nil),
				},
			},
			noCheck: true,
		},
		{
			name: "Very Short Salt",
			args: args{
				password: testPassword,
				d:        Sha1,
				opt: []Pbkdf2Options{
					Pbkdf2With(10, 20),
					Pbkdf2Salt(givenSalt[:6]),
				},
			},
			wantErr: true,
		},
		{
			name: "With Given Salt All Correct Verify",
			args: args{
				password: testPassword,
				d:        Sha256,
				opt: []Pbkdf2Options{
					Pbkdf2With(4096, sha256.Size),
					Pbkdf2Salt(givenSalt),
				},
			},
			wantSalt:   givenSalt,
			wantResult: decHex("e19d4969505371a8be8deec3eb6448afc928c4e1ede90ab1cd31efff6aacf103"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult, gotSalt, err := Pbkdf2(tt.args.password, tt.args.d, tt.args.opt...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Pbkdf2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.noCheck {
				if !reflect.DeepEqual(gotResult, tt.wantResult) {
					t.Errorf("Pbkdf2() gotResult = %v, want %v", gotResult, tt.wantResult)
				}
				if !reflect.DeepEqual(gotSalt, tt.wantSalt) {
					t.Errorf("Pbkdf2() gotSalt = %v, want %v", gotSalt, tt.wantSalt)
				}
			}
		})
	}
}

func TestPbkdf2_Misc(t *testing.T) {
	t.Run("Bad Method Registered", func(t *testing.T) {
		var eHash bcryptFn
		eHash.FnName = MethodSHA1
		// Mock the Sha1 Hash type
		RegisterDigestFunction(MethodSHA1, &eHash)
		defer func() { RegisterDigestFunction(MethodSHA1, Sha1) }()
		_, _, err := Pbkdf2([]byte("Test"), &eHash)
		if err == nil {
			t.Errorf("Pbkdf2() - Expected Error got Nil instead")
		}
	})
}
