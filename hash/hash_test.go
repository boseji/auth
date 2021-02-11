// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

// Package hash provides an easy way to generate digest or one way hash.
// It wraps the standard library packages such as crypt/sha1
// and crypt/sha256 into easy to use functions.
package hash

import (
	"reflect"
	"testing"
)

func TestSum(t *testing.T) {
	testData := []byte{1, 2, 3}
	testMD5 := []byte{82, 137, 223, 115, 125, 245, 115, 38, 252, 221, 34, 89, 122, 251, 31, 172}
	type args struct {
		hf Hashit
		p  []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "Nil Data",
			args: args{
				hf: MD5,
				p:  nil,
			},
			want: nil,
		},
		{
			name: "Empty Data",
			args: args{
				hf: MD5,
				p:  []byte{},
			},
			want: nil,
		},
		{
			name: "Basic Data",
			args: args{
				hf: MD5,
				p:  testData,
			},
			want: testMD5,
		},
		{
			name: "Data With Space",
			args: args{
				hf: MD5,
				p: func() []byte {
					b := make([]byte, 0, MD5().Size()+len(testData))
					b = append(b, testData...)
					return b
				}(),
			},
			want: append(
				append([]byte(nil), testData...),
				testMD5...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sum(tt.args.hf, tt.args.p); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Sum() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShakeSum(t *testing.T) {
	testData := []byte{1, 2, 3}
	testSize := 32
	testResult := []byte{218, 239, 167, 7, 93, 32, 41, 187, 214, 105, 12, 86, 166, 83, 123, 154, 218, 108, 92, 47, 146, 196, 24, 130, 197, 19, 229, 190, 132, 201, 11, 244}

	type args struct {
		s    ShakeHashit
		p    []byte
		size int
	}
	tests := []struct {
		name  string
		args  args
		wantR []byte
	}{
		{
			name: "Nil Data",
			args: args{
				s:    SHAKE128,
				p:    nil,
				size: testSize,
			},
			wantR: nil,
		},
		{
			name: "Empty Data",
			args: args{
				s:    SHAKE128,
				p:    []byte{},
				size: testSize,
			},
			wantR: nil,
		},
		{
			name: "Zero Size",
			args: args{
				s:    SHAKE128,
				p:    testData,
				size: 0,
			},
			wantR: nil,
		},
		{
			name: "Basic data",
			args: args{
				s:    SHAKE128,
				p:    testData,
				size: testSize,
			},
			wantR: testResult,
		},
		{
			name: "Data with Space",
			args: args{
				s:    SHAKE128,
				p:    append(make([]byte, 0, len(testData)+testSize), testData...),
				size: testSize,
			},
			wantR: append(
				append(make([]byte, 0, len(testData)+testSize), testData...),
				testResult...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotR := ShakeSum(tt.args.s, tt.args.p, tt.args.size); !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("ShakeSum() = %v, want %v", gotR, tt.wantR)
			}
		})
	}
}

func TestHMAC(t *testing.T) {
	testData := []byte{1, 2, 3}
	testKey := []byte{23, 4, 2, 77, 21, 3, 9, 28, 87}
	testHmacMD5 := []byte{202, 159, 143, 125, 191, 212, 177, 8, 157, 114, 198, 151, 50, 229, 249, 36}
	type args struct {
		hf  Hashit
		p   []byte
		key []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "No method",
			args: args{
				hf:  nil,
				p:   testData,
				key: testKey,
			},
			wantErr: true,
		},
		{
			name: "Empty data",
			args: args{
				hf:  MD5,
				p:   []byte{},
				key: testKey,
			},
			wantErr: true,
		},
		{
			name: "No Key",
			args: args{
				hf:  MD5,
				p:   testData,
				key: nil,
			},
			wantErr: true,
		},
		{
			name: "HMAC for MD5",
			args: args{
				hf:  MD5,
				p:   testData,
				key: testKey,
			},
			want: testHmacMD5,
		},
		{
			name: "HMAC for MD5 with Data Capacity",
			args: args{
				hf:  MD5,
				p:   append(make([]byte, 0, len(testData)+len(testHmacMD5)), testData...),
				key: testKey,
			},
			want: append(
				append([]byte(nil), testData...),
				testHmacMD5...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HMAC(tt.args.hf, tt.args.p, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("HMAC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("HMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShakeMAC(t *testing.T) {
	testData := []byte{1, 2, 3}
	testSize := 32
	testKey := []byte{23, 4, 2, 77, 21, 3, 9, 28, 87}
	testResult := []byte{245, 236, 74, 132, 185, 114, 79, 38, 242, 141, 18, 163, 173, 127, 207, 21, 102, 119, 141, 8, 51, 243, 114, 66, 231, 145, 85, 32, 229, 136, 107, 236}
	type args struct {
		s    ShakeHashit
		p    []byte
		key  []byte
		size int
	}
	tests := []struct {
		name    string
		args    args
		wantMac []byte
		wantErr bool
	}{
		{
			name: "No Method",
			args: args{
				s:    nil,
				p:    testData,
				key:  testKey,
				size: testSize,
			},
			wantErr: true,
		},
		{
			name: "No Data",
			args: args{
				s:    SHAKE128,
				p:    []byte{},
				key:  testKey,
				size: testSize,
			},
			wantErr: true,
		},
		{
			name: "No Key",
			args: args{
				s:    SHAKE128,
				p:    testData,
				key:  nil,
				size: testSize,
			},
			wantErr: true,
		},
		{
			name: "Wrong size",
			args: args{
				s:    SHAKE128,
				p:    testData,
				key:  testKey,
				size: -5,
			},
			wantErr: true,
		},
		{
			name: "Shake128 MAC",
			args: args{
				s:    SHAKE128,
				p:    testData,
				key:  testKey,
				size: testSize,
			},
			wantMac: testResult,
		},
		{
			name: "Shake128 MAC with Space",
			args: args{
				s:    SHAKE128,
				p:    append(make([]byte, 0, len(testData)+testSize), testData...),
				key:  testKey,
				size: testSize,
			},
			wantMac: append(
				append([]byte(nil), testData...),
				testResult...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMac, err := ShakeMAC(tt.args.s, tt.args.p, tt.args.key, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("ShakeMAC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotMac, tt.wantMac) {
				t.Errorf("ShakeMAC() = %v, want %v", gotMac, tt.wantMac)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	testData1 := []byte{1, 2, 3}
	testData2 := []byte{2, 3, 6}
	type args struct {
		x []byte
		y []byte
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "No First Argument",
			args: args{
				x: nil,
				y: testData2,
			},
			want: false,
		},
		{
			name: "Empty Argument",
			args: args{
				x: testData1,
				y: []byte{},
			},
			want: false,
		},
		{
			name: "Empty Argument and Nil are equal",
			args: args{
				x: []byte{},
				y: nil,
			},
			want: true,
		},
		{
			name: "Empty Argument equal",
			args: args{
				x: []byte{},
				y: []byte{},
			},
			want: true,
		},
		{
			name: "Nil Argument equal",
			args: args{
				x: nil,
				y: nil,
			},
			want: true,
		},
		{
			name: "Fail",
			args: args{
				x: testData1,
				y: testData2,
			},
			want: false,
		},
		{
			name: "Success",
			args: args{
				x: testData1,
				y: testData1,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
