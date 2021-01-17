// Copyright 2020 Abhijit Bose. All rights reserved.
// Use of this source code is governed by a Apache 2.0 license that can be found
// in the LICENSE file.

package dec_test

import (
	"fmt"

	"github.com/boseji/auth/dec"
)

func ExampleBase64() {

	testInput := "U2lsZW5jZSBpcyB0aGUgZGl2aW5lIHNlY3JldCB0byBzdWNjZXNzIC4uLg=="

	buf, err := dec.Base64(testInput)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%q", string(buf))

	// Output: "Silence is the divine secret to success ..."
}

func ExampleBase64URL() {

	testInput := "U2lsZW5jZSBpcyB0aGUgZGl2aW5lIHNlY3JldCB0byBzdWNjZXNzIC4uLg=="

	buf, err := dec.Base64URL(testInput)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%q", string(buf))

	// Output: "Silence is the divine secret to success ..."
}

func ExampleBase32() {

	testInput := "KNUWYZLOMNSSA2LTEB2GQZJAMRUXM2LOMUQHGZLDOJSXIIDUN4QHG5LDMNSXG4ZAFYXC4==="

	buf, err := dec.Base32(testInput)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%q", string(buf))

	// Output: "Silence is the divine secret to success ..."
}

func ExampleBase32Hex() {

	testInput := "ADKMOPBECDII0QBJ41Q6GP90CHKNCQBECKG76PB3E9IN883KDSG76TB3CDIN6SP05ON2S==="

	buf, err := dec.Base32Hex(testInput)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%q", string(buf))

	// Output: "Silence is the divine secret to success ..."
}

func ExampleHex() {

	testInput := "53696c656e63652069732074686520646976696e652073656372657420746f2073756363657373202e2e2e"

	buf, err := dec.Hex(testInput)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%q", string(buf))

	// Output: "Silence is the divine secret to success ..."
}

func ExampleJSON() {

	testInput := `
	[
		{
			"name": "Keshav",
			"ageOf": 25
		},
		{
			"name": "Mohan",
			"ageOf": 15
		}
	]
	`

	// Make sure that supplied reference also has the correct fields
	// and JSON tags for the type. Also incase the data is an array or slice
	// the same needs to be created for filling data from JSON string.
	// In this case we are using a slice of struct of the corresponding
	// type.
	ref := []struct {
		Name string `json:"name"`
		Age  int    `json:"ageOf"`
	}{}

	// Note the use of Reference even in case of slice, struct, or array
	err := dec.JSON(testInput, &ref)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(ref)

	// Output: [{Keshav 25} {Mohan 15}]
}
