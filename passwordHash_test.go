// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"reflect"
	"testing"
)

func decHex(in string) []byte {
	result, _ := FromHex(in)
	return result
}

func Test_passwordHashBcrypt_Set(t *testing.T) {
	type args struct {
		method string
		in1    interface{}
	}
	tests := []struct {
		name    string
		p       *passwordHashBcrypt
		args    args
		wantErr bool
	}{
		{
			name: "Incorrect Method",
			p:    &passwordHashBcrypt{},
			args: args{
				method: "Wrong Method Passed",
			},
			wantErr: true,
		},
		{
			name: "Correct Method",
			p:    &passwordHashBcrypt{},
			args: args{
				method: MethodPasswordHashBcrypt,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashBcrypt{}
			if err := p.Set(tt.args.method, tt.args.in1); (err != nil) != tt.wantErr {
				t.Errorf("passwordHashBcrypt.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_passwordHashBcrypt_Create(t *testing.T) {
	type args struct {
		data    []byte
		bWeight interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No Data",
			args: args{
				data:    nil,
				bWeight: nil,
			},
			wantErr: true,
		},
		{
			name: "Empty Data",
			args: args{
				data:    []byte{},
				bWeight: nil,
			},
			wantErr: true,
		},
		{
			name: "Correct Data",
			args: args{
				data:    []byte("Test Password"),
				bWeight: nil,
			},
		},
		{
			name: "Wrong weight",
			args: args{
				data:    []byte("Test Password"),
				bWeight: "test",
			},
			wantErr: true,
		},
		{
			name: "Correct Weight",
			args: args{
				data:    []byte("Test Password"),
				bWeight: BcryptDefaultCost,
			},
		},
		{
			name: "Wrong negative weight",
			args: args{
				data:    []byte("Test Password"),
				bWeight: -5,
			},
			wantErr: true,
		},
		{
			name: "Wrong zero weight",
			args: args{
				data:    []byte("Test Password"),
				bWeight: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashBcrypt{}
			_, err := p.Create(tt.args.data, tt.args.bWeight)
			if (err != nil) != tt.wantErr {
				t.Errorf("passwordHashBcrypt.Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_passwordHashBcrypt_Verify(t *testing.T) {
	type args struct {
		value  []byte
		digest interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		want1   interface{}
		wantErr bool
	}{
		{
			name: "No Value",
			args: args{
				value: nil,
			},
			wantErr: true,
		},
		{
			name: "Empty Value",
			args: args{
				value: []byte{},
			},
			wantErr: true,
		},
		{
			name: "No Digest",
			args: args{
				value: []byte{1, 2},
			},
			wantErr: true,
		},
		{
			name: "Wrong Digest type",
			args: args{
				value:  []byte{1, 2},
				digest: 25,
			},
			wantErr: true,
		},
		{
			name: "Empty Digest",
			args: args{
				value:  []byte{1, 2},
				digest: []byte{},
			},
			wantErr: true,
		},
		{
			name: "Correct Digest",
			args: args{
				value:  []byte("Test Password"),
				digest: decHex("2432612431302430646359484566793038486d65353944456c646947756f523856424b566234676f662f3974373038624a3156526e52733366775469"),
			},
			want:  decHex("2432612431302430646359484566793038486d65353944456c646947756f523856424b566234676f662f3974373038624a3156526e52733366775469"),
			want1: BcryptDefaultCost,
		},
		{
			name: "Corrupt Digest",
			args: args{
				value:  []byte("Test Password"),
				digest: decHex("2532612431302430646359484566793038486d65353944456c646947756f523856424b566234676f662f3974373038624a3156526e52733366775469"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashBcrypt{}
			got, got1, err := p.Verify(tt.args.value, tt.args.digest)
			if (err != nil) != tt.wantErr {
				t.Errorf("passwordHashBcrypt.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("passwordHashBcrypt.Verify() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("passwordHashBcrypt.Verify() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_passwordHashPbkdf2HS256_Set(t *testing.T) {
	type args struct {
		method string
		in1    interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Incorrect Method",
			args: args{
				method: "Wrong Method Passed",
			},
			wantErr: true,
		},
		{
			name: "Correct Method",
			args: args{
				method: MethodPasswordHashPbkdf2HS256,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashPbkdf2HS256{}
			if err := p.Set(tt.args.method, tt.args.in1); (err != nil) != tt.wantErr {
				t.Errorf("passwordHashPbkdf2HS256.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_passwordHashPbkdf2HS256_Create(t *testing.T) {
	type args struct {
		data    []byte
		bRounds interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No Data",
			args: args{
				data:    nil,
				bRounds: nil,
			},
			wantErr: true,
		},
		{
			name: "Empty Data",
			args: args{
				data:    []byte{},
				bRounds: nil,
			},
			wantErr: true,
		},
		{
			name: "Correct Data",
			args: args{
				data:    []byte("Test Password"),
				bRounds: nil,
			},
		},
		{
			name: "Wrong negative rounds",
			args: args{
				data:    []byte("Test Password"),
				bRounds: -5,
			},
			wantErr: true,
		},
		{
			name: "Wrong zero rounds",
			args: args{
				data:    []byte("Test Password"),
				bRounds: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashPbkdf2HS256{}
			_, err := p.Create(tt.args.data, tt.args.bRounds)
			if (err != nil) != tt.wantErr {
				t.Errorf("passwordHashPbkdf2HS256.Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_passwordHashPbkdf2HS256_Verify(t *testing.T) {
	type args struct {
		value  []byte
		digest interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		want1   interface{}
		wantErr bool
	}{
		{
			name: "No Value",
			args: args{
				value: nil,
			},
			wantErr: true,
		},
		{
			name: "Empty Value",
			args: args{
				value: []byte{},
			},
			wantErr: true,
		},
		{
			name: "No Digest",
			args: args{
				value: []byte{1, 2},
			},
			wantErr: true,
		},
		{
			name: "Wrong Digest type",
			args: args{
				value:  []byte{1, 2},
				digest: 25,
			},
			wantErr: true,
		},
		{
			name: "Empty Digest",
			args: args{
				value:  []byte{1, 2},
				digest: []byte{},
			},
			wantErr: true,
		},
		{
			name: "Correct Digest",
			args: args{
				value:  []byte("Test Password"),
				digest: decHex("001000000000000062657e7a8bf62f9feef5ecb2bf5af70db916555a76d23ea6481be869ceec0bb880b74d66a88e9de2"),
			},
			want:  decHex("001000000000000062657e7a8bf62f9feef5ecb2bf5af70db916555a76d23ea6481be869ceec0bb880b74d66a88e9de2"),
			want1: Pbkdf2DefaultRounds,
		},
		{
			name: "Corrupt Digest",
			args: args{
				value:  []byte("Test Password"),
				digest: decHex("001000000000000062657e7a8bf62f9beef5ecb2bf5af70db916555a76d23ea6481be869ceec0bb880b74d66a88e9de2"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashPbkdf2HS256{}
			got, got1, err := p.Verify(tt.args.value, tt.args.digest)
			if (err != nil) != tt.wantErr {
				t.Errorf("passwordHashPbkdf2HS256.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("passwordHashPbkdf2HS256.Verify() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("passwordHashPbkdf2HS256.Verify() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestNewPasswordHash(t *testing.T) {
	type args struct {
		method string
		key    interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    Auth
		wantErr bool
	}{
		{
			name: "Wrong Type",
			args: args{
				method: "Wrong Type",
			},
			wantErr: true,
		},
		{
			name: "Correct Type Bcrypt",
			args: args{
				method: MethodPasswordHashBcrypt,
			},
			want: &passwordHashBcrypt{},
		},
		{
			name: "Correct Type PBKDF2 HS256",
			args: args{
				method: MethodPasswordHashPbkdf2HS256,
			},
			want: &passwordHashPbkdf2HS256{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPasswordHash(tt.args.method, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPasswordHash() = %v, want %v", got, tt.want)
			}
		})
	}
}
