// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"reflect"
	"testing"
)

// For Error Cases
var badMockEncoder = &EncodeIt{
	Name: "bad",
}

// Used only for Test Cases
func removeEncoder(name string) {
	encodersLock.Lock()
	defer encodersLock.Unlock()

	delete(encoders, name)
}

func TestEncode(t *testing.T) {

	type args struct {
		f    *EncodeIt
		data []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "No Data",
			args: args{
				f:    Hex,
				data: nil,
			},
			want: "",
		},
		{
			name: "Empty Data",
			args: args{
				f:    Hex,
				data: []byte{},
			},
			want: "",
		},
		{
			name: "Bad Encoder",
			args: args{
				f:    badMockEncoder,
				data: []byte("user:pass"),
			},
			want: "",
		},
		{
			name: "Positive",
			args: args{
				f:    Base64,
				data: []byte("user:pass"),
			},
			want: "dXNlcjpwYXNz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Encode(tt.args.f, tt.args.data); got != tt.want {
				t.Errorf("Encode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	type args struct {
		f     *EncodeIt
		value string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Empty Data",
			args: args{
				f:     Hex,
				value: "",
			},
			wantErr: true,
		},
		{
			name: "Bad Encoder",
			args: args{
				f:     badMockEncoder,
				value: "dXNlcjpwYXNz",
			},
			wantErr: true,
		},
		{
			name: "Positive",
			args: args{
				f:     Base64,
				value: "dXNlcjpwYXNz",
			},
			want: []byte("user:pass"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.args.f, tt.args.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decode() = %v, want %v", got, tt.want)
			}
		})
	}
}
