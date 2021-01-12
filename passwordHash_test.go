// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"reflect"
	"testing"
)

func decHex(in string) []byte {
	result, _ := Decode(Hex, in)
	return result
}

func TestPasswordHash(t *testing.T) {
	testString := "Test String"
	type args struct {
		d    DigestIt
		pass string
		opts []DigestOptions
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Check digest",
			args: args{
				d:    Sha1,
				pass: testString,
			},
			want: decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PasswordHash(tt.args.d, tt.args.pass, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PasswordHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPasswordCheck(t *testing.T) {
	testString := "Test String"
	type args struct {
		d    DigestIt
		pass string
		dig  []byte
		opts []DigestOptions
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Check supplied Digest",
			args: args{
				d:    Sha1,
				pass: testString,
				dig:  decHex("4cb416e15626c26ebac03cee046d63b8c0deeee5"),
				opts: []DigestOptions{
					WithHMACKey(decHex("a5103f9c0b7d5ff69ddc38607c74e53d4ac120f2")),
				},
			},
		},
		{
			name: "Check auto Digest",
			args: args{
				d:    Bcrypt,
				pass: testString,
				dig:  decHex("243261243130244d654432424559733253796a374446673436306c4e65515459537131735545716c42474c48734e77414a366e4c6550762f41757379"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := PasswordCheck(tt.args.d, tt.args.pass, tt.args.dig, tt.args.opts...); (err != nil) != tt.wantErr {
				t.Errorf("PasswordCheck() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
