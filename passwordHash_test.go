// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

package auth

import (
	"reflect"
	"testing"
)

func Test_passwordHashHS256_Set(t *testing.T) {
	type fields struct {
		PasswordHash PasswordHash
		initialized  bool
		key          []byte
	}
	type args struct {
		method string
		key    interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "Test Wrong Method",
			fields: fields{},
			args: args{
				method: "No Method",
				key:    nil,
			},
			wantErr: true,
		},
		{
			name:   "Test No Key",
			fields: fields{},
			args: args{
				method: MethodPasswordHashHS256,
				key:    nil,
			},
			wantErr: true,
		},
		{
			name:   "Test Wrong Key Type",
			fields: fields{},
			args: args{
				method: MethodPasswordHashHS256,
				key:    "123",
			},
			wantErr: true,
		},
		{
			name:   "Test Empty Key",
			fields: fields{},
			args: args{
				method: MethodPasswordHashHS256,
				key:    []byte{},
			},
			wantErr: true,
		},
		{
			name:   "Test Key with Wrong Size",
			fields: fields{},
			args: args{
				method: MethodPasswordHashHS256,
				key:    []byte{12, 13, 14, 15, 16},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashHS256{
				PasswordHash: tt.fields.PasswordHash,
				initialized:  tt.fields.initialized,
				key:          tt.fields.key,
			}
			if err := p.Set(tt.args.method, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("passwordHashHS256.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_passwordHashHS256_Create(t *testing.T) {
	type fields struct {
		PasswordHash PasswordHash
		initialized  bool
		key          []byte
	}
	type args struct {
		data []byte
		in1  interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashHS256{
				PasswordHash: tt.fields.PasswordHash,
				initialized:  tt.fields.initialized,
				key:          tt.fields.key,
			}
			got, err := p.Create(tt.args.data, tt.args.in1)
			if (err != nil) != tt.wantErr {
				t.Errorf("passwordHashHS256.Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("passwordHashHS256.Create() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_passwordHashHS256_Verify(t *testing.T) {
	type fields struct {
		PasswordHash PasswordHash
		initialized  bool
		key          []byte
	}
	type args struct {
		value []byte
		bias  interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		want1   interface{}
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &passwordHashHS256{
				PasswordHash: tt.fields.PasswordHash,
				initialized:  tt.fields.initialized,
				key:          tt.fields.key,
			}
			got, got1, err := p.Verify(tt.args.value, tt.args.bias)
			if (err != nil) != tt.wantErr {
				t.Errorf("passwordHashHS256.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("passwordHashHS256.Verify() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("passwordHashHS256.Verify() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
