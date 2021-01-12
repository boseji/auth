// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package auth

import (
	"io"
	"testing"

	"github.com/gofrs/uuid/v3"
)

func badMockReadFull(r io.Reader, buf []byte) (n int, err error) {
	return 0, ErrNotSupported
}

func badMockNewV4() (uuid.UUID, error) {
	return uuid.UUID{}, ErrNotSupported
}

func TestGetRandom(t *testing.T) {
	type args struct {
		size int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Bad Size",
			args: args{
				size: 0,
			},
			wantErr: true,
		},
		{
			name: "Negative Size",
			args: args{
				size: -5,
			},
			wantErr: true,
		},
		{
			name: "Good Case",
			args: args{
				size: 5,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRandom(tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRandom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.args.size && !tt.wantErr {
				t.Errorf(
					"GetRandom() Size of Output= %v, want %v",
					len(got),
					tt.args.size,
				)
			}
		})
	}
}

func TestGetRandom_IOErr(t *testing.T) {
	orig := readFull
	readFull = badMockReadFull
	defer func() { readFull = orig }()

	_, err := GetRandom(5)
	if err == nil {
		t.Errorf("GetRandom() error = %v, wantErr %v", err, ErrNotSupported)
	}
}

func TestUUIDv4(t *testing.T) {
	tests := []struct {
		name    string
		wantMoc bool
		wantErr bool
	}{
		{
			name:    "Failed UUID",
			wantMoc: true,
			wantErr: true,
		},
		{
			name: "Ok Test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantMoc {
				orig := uuidFn
				uuidFn = badMockNewV4
				defer func() { uuidFn = orig }()
			}
			got, err := UUIDv4()
			if (err != nil) != tt.wantErr {
				t.Errorf("UUIDv4() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == "" {
				t.Errorf("UUIDv4() = %v, want UUID", got)
			}
		})
	}
}
