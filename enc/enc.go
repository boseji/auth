// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

// Package enc provides an easy way to encode data in multiple
// commonly used formats such as Hex and Base64. It wraps the standard library
// packages such as encoding/base32 and encoding/base64 into easy to use
// functions.
package enc

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// option stores the JSON Encoding options
type option struct {
	htmlEsc bool
	format  bool
	prefix  string
	indent  string
}

// Options is the functional options for JSON Encoding
type Options func(*option) *option

// HTMLEscaped functional option enables HTML Escaping for JSON
func HTMLEscaped() Options {
	return func(o *option) *option {
		o.htmlEsc = true
		return o
	}
}

// Format functional option provides a way to pretty format the JSON output
func Format(prefix, indent string) Options {
	return func(o *option) *option {
		o.format = true
		o.prefix = prefix
		o.indent = indent
		return o
	}
}

// Base64 function converts the supplied data to a Base64 Standard encoding
// formatted string as defined in RFC 4648.
func Base64(p []byte) string {
	return base64.StdEncoding.EncodeToString(p)
}

// Base64URL function converts the supplied data to a Base64 URL encoding
// formatted string as defined for URLs and file names.
func Base64URL(p []byte) string {
	return base64.URLEncoding.EncodeToString(p)
}

// Base32 function converts the supplied data to standard base32 encoded string
// as per RFC 4648
func Base32(p []byte) string {
	return base32.StdEncoding.EncodeToString(p)
}

// Base32Hex function converts the supplied data to "Extended Hex Alphabet" based
// base32 encoded string as defined in RFC 4648
func Base32Hex(p []byte) string {
	return base32.HexEncoding.EncodeToString(p)
}

// Hex function converts the supplied data to Hex encoded string it is in ways
// similar to fmt.Printf("%x", p)
func Hex(p []byte) string {
	return hex.EncodeToString(p)
}

// JSON function converts the supplied data to a JSON formated string. In case
// it fails to interpret the data it would return an empty string.
// This function also accepts functional options in a list that can change the
// encoded output.
func JSON(v interface{}, opt ...Options) string {
	buf, err := json.Marshal(v)
	if err != nil {
		return ""
	}

	o := &option{}
	if opt != nil {
		for _, ofn := range opt {
			o = ofn(o)
		}
	}

	if o.htmlEsc {
		var out bytes.Buffer
		json.HTMLEscape(&out, buf)
		buf = out.Bytes()
	}

	if o.format {
		var out bytes.Buffer
		err := json.Indent(&out, buf, o.prefix, o.indent)
		if err != nil {
			return ""
		}
		buf = out.Bytes()
	}

	return string(buf)
}

// JSONhtml function converts the supplies data to JSON formated string and
// HTML Escapes it. This makes the string safe to be used embedded in HTML.
func JSONhtml(v interface{}) string {
	buf, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var out bytes.Buffer
	json.HTMLEscape(&out, buf)
	return out.String()
}

// JSONformat function converts the supplied data to JSON formatted string and
// adds additional pretty print formatting using prefix & indent inputs.
func JSONformat(v interface{}, prefix, indent string) string {
	buf, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var out bytes.Buffer
	err = json.Indent(&out, buf, prefix, indent)
	if err != nil {
		return ""
	}
	return out.String()
}
