// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"crypto"
	"crypto/sha1"
	"fmt"
	"hash"
	"reflect"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type errHash uint

type badMockDigest string

func (e *errHash) New() hash.Hash {
	return new(errHash)
}

func (e *errHash) Size() int {
	return 0
}

func (e *errHash) String() string {
	return "This is Error Hash Function"
}

func (e *errHash) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("This is Error Hash")
}

func (e *errHash) Sum(b []byte) []byte {
	return nil
}

func (e *errHash) Reset() {}

func (e *errHash) BlockSize() int {
	return 0
}

func (e *badMockDigest) Name() string {
	return string(*e)
}

func (e *badMockDigest) Get([]byte) ([]byte, error) {
	return nil, ErrNotSupported
}

func (e *badMockDigest) Create(data []byte, bias interface{}) (output []byte, err error) {
	return nil, ErrNotSupported
}

func (e *badMockDigest) Verify(value []byte, bias interface{}) (data []byte, iBias interface{}, err error) {
	return nil, nil, ErrNotSupported
}

func (e *badMockDigest) Set(method string, key interface{}) error {
	return ErrNotSupported
}

func errBcryptGenerate(password []byte, cost int) ([]byte, error) {
	return nil, fmt.Errorf("Error in Bcrypt Operations")
}

func errBcryptCompare(hashedPassword []byte, password []byte) error {
	return fmt.Errorf("Error in Bcrypt Operations")
}

func TestDigest(t *testing.T) {
	testString := []byte("Test String")

	type args struct {
		d    DigestIt
		data []byte
		opts []DigestOptions
	}
	tests := []struct {
		name               string
		args               args
		want               []byte
		wantErr            bool
		wantBcryptValidate bool
		bcryptCost         int
	}{
		{
			name:    "No Digest Method",
			wantErr: true,
		},
		{
			name: "Wrong Digest Method",
			args: args{
				d:    &hashFn{FnName: "Wrong"},
				data: testString,
			},
			wantErr: true,
		},
		{
			name: "No Data",
			args: args{
				d: Sha1,
			},
			wantErr: true,
		},
		{
			name: "Correct",
			args: args{
				d:    Sha1,
				data: testString,
			},
			want: decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2"),
		},
		{
			name: "Wrong Parameter with HMAC",
			args: args{
				d:    Bcrypt,
				data: testString,
				opts: []DigestOptions{
					WithHMACKey(decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")),
				},
			},
			wantBcryptValidate: true,
		},
		{
			name: "HMAC-SHA1 No Data",
			args: args{
				d: Sha1,
				opts: []DigestOptions{
					WithHMACKey(decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")),
				},
			},
			wantErr: true,
		},
		{
			name: "HMAC-SHA1",
			args: args{
				d:    Sha1,
				data: testString,
				opts: []DigestOptions{
					WithHMACKey(decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")),
				},
			},
			want: decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5"),
		},
		{
			name: "SHA1 Verify",
			args: args{
				d:    Sha1,
				data: decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5"),
				opts: []DigestOptions{
					WithDigest(decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5")),
				},
			},
			want: decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5"),
		},
		{
			name: "HMAC-SHA1 Verify with HMAC Key",
			args: args{
				d:    Sha1,
				data: testString,
				opts: []DigestOptions{
					WithHMACKey(decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")),
					WithDigest(decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5")),
				},
			},
			want: decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5"),
		},
		{
			name: "HMAC-SHA1 Verify with HMAC Key 2",
			args: args{
				d:    Sha1,
				data: decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5"),
				opts: []DigestOptions{
					WithDigest(decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5")),
					WithHMACKey(decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")),
				},
			},
			want: decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5"),
		},
		{
			name: "Bcrypt No Data",
			args: args{
				d: Bcrypt,
			},
			wantErr: true,
		},
		{
			name: "Bcrypt Correct",
			args: args{
				d:    Bcrypt,
				data: testString,
			},
			wantBcryptValidate: true,
			bcryptCost:         bcrypt.DefaultCost,
		},
		{
			name: "Bcrypt with Very High Cost",
			args: args{
				d:    Bcrypt,
				data: testString,
				opts: []DigestOptions{
					WithBcryptCost(bcrypt.MaxCost + 1),
				},
			},
			wantBcryptValidate: true,
			bcryptCost:         bcrypt.DefaultCost,
		},
		{
			name: "Bcrypt with Very Low Cost",
			args: args{
				d:    Bcrypt,
				data: testString,
				opts: []DigestOptions{
					WithBcryptCost(bcrypt.MinCost - 1),
				},
			},
			wantBcryptValidate: true,
			bcryptCost:         bcrypt.MinCost,
		},
		{
			name: "HMAC-SHA1 with Bad Bcrypt Cost option",
			args: args{
				d:    Sha1,
				data: testString,
				opts: []DigestOptions{
					WithBcryptCost(bcrypt.MinCost - 1),
				},
			},
			want: decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2"),
		},
		{
			name: "Bcrypt with Verify No Data",
			args: args{
				d: Bcrypt,
				opts: []DigestOptions{
					WithDigest(
						decHex("24326179"),
					),
				},
			},
			wantErr: true,
		},
		{
			name: "Bcrypt with Verify",
			args: args{
				d:    Bcrypt,
				data: testString,
				opts: []DigestOptions{
					WithDigest(
						decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
					),
				},
			},
			want: decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
		},
		{
			name: "Bcrypt with Verify and Cost",
			args: args{
				d:    Bcrypt,
				data: testString,
				opts: []DigestOptions{
					WithBcryptCost(bcrypt.DefaultCost),
					WithDigest(
						decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
					),
				},
			},
			want: decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
		},
		{
			name: "Bcrypt with Verify and Cost 2",
			args: args{
				d:    Bcrypt,
				data: testString,
				opts: []DigestOptions{
					WithDigest(
						decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
					),
					WithBcryptCost(bcrypt.DefaultCost),
				},
			},
			want: decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Digest(tt.args.d, tt.args.data, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Digest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantBcryptValidate && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Digest() = %v, want %v", got, tt.want)
			}
			if tt.wantBcryptValidate {
				_, err := Digest(Bcrypt, tt.args.data, WithDigest(got))
				if (err != nil) != tt.wantErr {
					t.Errorf("Digest Validate() error = %v, wantErr %v",
						err, tt.wantErr)
					return
				}
				if tt.bcryptCost != 0 {
					cost, err := bcrypt.Cost(got)
					if err != nil {
						t.Errorf("Error in verifying cost - %w", err)
						return
					}
					if cost != tt.bcryptCost {
						t.Errorf("Digest Cost() cost = %v, want-cost %v",
							cost, tt.bcryptCost)
						return
					}
				}
			}
		})
	}
}

func TestDigest_Misc(t *testing.T) {
	t.Run("Hash func", func(t *testing.T) {
		got := Sha1.HashFunc()
		want := crypto.SHA1
		if !reflect.DeepEqual(got, want) {
			t.Errorf("HashFunc() got = %v, want = %v", got, want)
		}
	})
	t.Run("Size func", func(t *testing.T) {
		got := Sha1.Size()
		want := sha1.Size
		if !reflect.DeepEqual(got, want) {
			t.Errorf("HashFunc() got = %v, want = %v", got, want)
		}
	})
	t.Run("Err Hash func", func(t *testing.T) {
		var eHash errHash
		// Mock the SHA1 to generate write Errors
		crypto.RegisterHash(crypto.SHA1, eHash.New)
		defer crypto.RegisterHash(crypto.SHA1, sha1.New)

		_, err := Sha1.Get([]byte{1, 2, 3})
		if err == nil {
			t.Errorf("HashFunc() got = nil, want error")
		}
	})
	t.Run("Err Hash func Digest", func(t *testing.T) {
		var b badMockDigest
		b = "BadMock"
		RegisterDigestFunction("BadMock", &b)
		defer func() { delete(digestFuncs, "BadMock") }()

		_, err := Digest(&b, nil, WithDigest([]byte{1, 2, 3}))
		if err == nil {
			t.Errorf("HashFunc() got = nil, want error")
		}
	})

	t.Run("Good Create Fn", func(t *testing.T) {
		testString := []byte("Test String")
		got, err := Sha1.Create(testString, nil)
		if err != nil {
			t.Errorf("Create() got = %w, want No error", err)
			return
		}
		expected := decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Create() = %v, want %v", got, expected)
		}
	})
	t.Run("Err in Set Function", func(t *testing.T) {
		err := Sha1.Set("SHA3", nil)
		if err == nil {
			t.Errorf("Set() got = nil, want error")
		}
	})
	t.Run("Good Set Function", func(t *testing.T) {
		err := Sha1.Set("SHA1", nil)
		if err != nil {
			t.Errorf("Set() got = %w, want No error", err)
		}
	})
	t.Run("Err Hmac func", func(t *testing.T) {
		var eHash errHash
		// Mock the SHA1 to generate write Errors
		crypto.RegisterHash(crypto.SHA1, eHash.New)
		defer crypto.RegisterHash(crypto.SHA1, sha1.New)

		_, err := Digest(Sha1, []byte{1, 2, 3}, WithHMACKey([]byte{1, 2, 3}))
		if err == nil {
			t.Errorf("HashFunc() got = nil, want error")
		}
	})
	t.Run("Err Hmac Verify", func(t *testing.T) {
		var eHash errHash
		// Mock the SHA1 to generate write Errors
		crypto.RegisterHash(crypto.SHA1, eHash.New)
		defer crypto.RegisterHash(crypto.SHA1, sha1.New)

		_, err := Digest(Sha1, []byte{1, 2, 3},
			WithHMACKey([]byte{1, 2, 3}),
			WithDigest(decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5")),
		)
		if err == nil {
			t.Errorf("HashFunc() got = nil, want error")
		}
	})

	t.Run("Err Bcrypt Generate func", func(t *testing.T) {

		// Mock
		bcryptGenerate = errBcryptGenerate
		defer func() { bcryptGenerate = bcrypt.GenerateFromPassword }()

		_, err := Digest(Bcrypt, []byte{1, 2, 3})
		if err == nil {
			t.Errorf("HashFunc() got = nil, want error")
		}
	})

	t.Run("Err Bcrypt Verify func", func(t *testing.T) {

		// Mock
		bcryptCompare = errBcryptCompare
		defer func() { bcryptCompare = bcrypt.CompareHashAndPassword }()

		_, err := Digest(Bcrypt, []byte{1, 2, 3}, WithDigest(
			decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
		))
		if err == nil {
			t.Errorf("HashFunc() got = nil, want error")
		}
	})
	t.Run("Err in Set Function - bcrypt", func(t *testing.T) {
		err := Bcrypt.Set("SHA3", nil)
		if err == nil {
			t.Errorf("Set() got = nil, want error")
		}
	})
	t.Run("Good Set Function - bcrypt", func(t *testing.T) {
		err := Bcrypt.Set("bcrypt", nil)
		if err != nil {
			t.Errorf("Set() got = %w, want No error", err)
		}
	})
}

func TestHashFn_Verify(t *testing.T) {
	//testString := []byte("Test String")
	expected := decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")
	type args struct {
		value []byte
		other interface{}
	}
	tests := []struct {
		name      string
		h         *hashFn
		args      args
		wantData  []byte
		wantInput interface{}
		wantErr   bool
	}{
		{
			name: "No Data",
			h:    Sha1,
			args: args{
				value: nil,
				other: nil,
			},
			wantErr: true,
		},
		{
			name: "Empty Data",
			h:    Sha1,
			args: args{
				value: []byte{},
				other: nil,
			},
			wantErr: true,
		},
		{
			name: "No Other",
			h:    Sha1,
			args: args{
				value: expected,
				other: nil,
			},
			wantErr: true,
		},
		{
			name: "Wrong Other",
			h:    Sha1,
			args: args{
				value: expected,
				other: "Other",
			},
			wantErr: true,
		},
		{
			name: "Wrong Other Length",
			h:    Sha1,
			args: args{
				value: expected,
				other: expected[1:],
			},
			wantErr: true,
		},
		{
			name: "Correct",
			h:    Sha1,
			args: args{
				value: expected,
				other: expected,
			},
			wantData:  expected,
			wantInput: expected,
		},
		{
			name: "Failed Comparison",
			h:    Sha1,
			args: args{
				value: expected,
				other: func() []byte {
					buf := make([]byte, len(expected))
					copy(buf, expected)
					buf[0] = 0xFF
					return buf
				}(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, gotInput, err := tt.h.Verify(tt.args.value, tt.args.other)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashFn.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotData, tt.wantData) {
				t.Errorf("HashFn.Verify() gotData = %v, want %v", gotData, tt.wantData)
			}
			if !reflect.DeepEqual(gotInput, tt.wantInput) {
				t.Errorf("HashFn.Verify() gotInput = %v, want %v", gotInput, tt.wantInput)
			}
		})
	}
}

func TestBcryptFn_Create(t *testing.T) {
	type args struct {
		password []byte
		bCost    interface{}
	}
	tests := []struct {
		name    string
		b       *bcryptFn
		args    args
		wantErr bool
	}{
		{
			name: "No Cost",
			b:    Bcrypt,
			args: args{
				password: nil,
				bCost:    nil,
			},
			wantErr: true,
		},
		{
			name: "Cost of Wrong type",
			b:    Bcrypt,
			args: args{
				password: nil,
				bCost:    "Low Cost",
			},
			wantErr: true,
		},
		{
			name: "Very High Cost",
			b:    Bcrypt,
			args: args{
				password: nil,
				bCost:    bcrypt.MaxCost + 1,
			},
			wantErr: true,
		},
		{
			name: "Very Low Cost",
			b:    Bcrypt,
			args: args{
				password: nil,
				bCost:    bcrypt.MinCost - 1,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.b.Create(tt.args.password, tt.args.bCost)
			if (err != nil) != tt.wantErr {
				t.Errorf("BcryptFn.Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestBcryptFn_Verify(t *testing.T) {
	type args struct {
		password []byte
		bDig     interface{}
	}
	tests := []struct {
		name    string
		b       *bcryptFn
		args    args
		wantErr bool
	}{
		{
			name: "No Digest",
			b:    Bcrypt,
			args: args{
				password: nil,
				bDig:     nil,
			},
			wantErr: true,
		},
		{
			name: "Wrong Digest",
			b:    Bcrypt,
			args: args{
				password: nil,
				bDig:     "wrong",
			},
			wantErr: true,
		},
		{
			name: "Empty Digest",
			b:    Bcrypt,
			args: args{
				password: nil,
				bDig:     []byte{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := tt.b.Verify(tt.args.password, tt.args.bDig)
			if (err != nil) != tt.wantErr {
				t.Errorf("BcryptFn.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
