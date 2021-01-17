// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package enc_test

import (
	"fmt"

	"github.com/boseji/auth/enc"
)

func ExampleBase64() {

	testInput := []byte("Silence is the divine secret to success ...")

	fmt.Println(enc.Base64(testInput))

	// Output: U2lsZW5jZSBpcyB0aGUgZGl2aW5lIHNlY3JldCB0byBzdWNjZXNzIC4uLg==
}

func ExampleBase64URL() {

	testInput := []byte("Silence is the divine secret to success ...")

	fmt.Println(enc.Base64URL(testInput))

	// Output: U2lsZW5jZSBpcyB0aGUgZGl2aW5lIHNlY3JldCB0byBzdWNjZXNzIC4uLg==
}

func ExampleBase32() {

	testInput := []byte("Silence is the divine secret to success ...")

	fmt.Println(enc.Base32(testInput))

	// Output: KNUWYZLOMNSSA2LTEB2GQZJAMRUXM2LOMUQHGZLDOJSXIIDUN4QHG5LDMNSXG4ZAFYXC4===
}

func ExampleBase32Hex() {

	testInput := []byte("Silence is the divine secret to success ...")

	fmt.Println(enc.Base32Hex(testInput))

	// Output: ADKMOPBECDII0QBJ41Q6GP90CHKNCQBECKG76PB3E9IN883KDSG76TB3CDIN6SP05ON2S===
}

func ExampleHex() {

	testInput := []byte("Silence is the divine secret to success ...")

	fmt.Println(enc.Hex(testInput))

	// Output: 53696c656e63652069732074686520646976696e652073656372657420746f2073756363657373202e2e2e
}

func ExampleJSON() {

	// Make sure the the structure fields are exported. Add meaningful JSON
	// names that match your target using tags.
	testInput := []struct {
		Name string `json:"name"`
		Age  int    `json:"ageOf"`
	}{
		{"Mohit", 30},
		{"Deepti", 22},
	}

	fmt.Println(enc.JSON(testInput))

	// Output: [{"name":"Mohit","ageOf":30},{"name":"Deepti","ageOf":22}]
}

func ExampleFormat() {

	// Make sure the the structure fields are exported. Add meaningful JSON
	// names that match your target using tags.
	testInput := []struct {
		Name string `json:"name"`
		Age  int    `json:"ageOf"`
	}{
		{"Mohit", 30},
		{"Deepti", 22},
	}

	fmt.Println(enc.JSON(testInput, enc.Format("", "\t")))

	// Output:
	// [
	// 	{
	// 		"name": "Mohit",
	// 		"ageOf": 30
	// 	},
	// 	{
	// 		"name": "Deepti",
	// 		"ageOf": 22
	// 	}
	// ]
}

func ExampleJSONhtml() {
	testInput := []struct {
		Name    string
		Message string
	}{
		{
			Name:    "The old Yoda",
			Message: "<h1>Speak last,<br>Show Respect,<br>power and Wisdom shall follow.</h1>",
		},
	}

	fmt.Println(enc.JSONhtml(testInput))

	// Output: [{"Name":"The old Yoda","Message":"\u003ch1\u003eSpeak last,\u003cbr\u003eShow Respect,\u003cbr\u003epower and Wisdom shall follow.\u003c/h1\u003e"}]
}

func ExampleHTMLEscaped() {
	testInput := []struct {
		Name    string
		Message string
	}{
		{
			Name:    "The old Yoda",
			Message: "<h1>Speak last,<br>Show Respect,<br>power and Wisdom shall follow.</h1>",
		},
	}

	fmt.Println(enc.JSON(testInput, enc.HTMLEscaped()))

	// Output: [{"Name":"The old Yoda","Message":"\u003ch1\u003eSpeak last,\u003cbr\u003eShow Respect,\u003cbr\u003epower and Wisdom shall follow.\u003c/h1\u003e"}]
}

func ExampleJSONformat() {

	// Make sure the the structure fields are exported. Add meaningful JSON
	// names that match your target using tags.
	testInput := []struct {
		Name string `json:"name"`
		Age  int    `json:"ageOf"`
	}{
		{"Keshav", 25},
		{"Mohan", 15},
	}

	fmt.Println(enc.JSONformat(testInput, "", "\t"))

	// Output:
	// [
	// 	{
	// 		"name": "Keshav",
	// 		"ageOf": 25
	// 	},
	// 	{
	// 		"name": "Mohan",
	// 		"ageOf": 15
	// 	}
	// ]
}
