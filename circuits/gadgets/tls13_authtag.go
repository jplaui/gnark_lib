/*
Copyright 2023 Jan Lauinger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gadgets

import (
	"github.com/consensys/gnark/frontend"
)

// authtag evaluation
type AuthTagWrapper struct {
	Key       [16]frontend.Variable
	IvCounter [16]frontend.Variable `gnark:",public"`
	Zeros     [16]frontend.Variable `gnark:",public"`
	ECB0      [16]frontend.Variable `gnark:",public"`
	ECBK      [16]frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *AuthTagWrapper) Define(api frontend.API) error {

	tag := NewTls13AuthTag(api)

	// type conversion
	tag.SetParams(
		circuit.Key,
		circuit.IvCounter,
		circuit.Zeros,
		circuit.ECB0,
		circuit.ECBK,
	)

	// verify tag
	tag.Assert()

	return nil
}

type Tls13AuthTag struct {
	api       frontend.API
	Key       [16]frontend.Variable
	IvCounter [16]frontend.Variable // `gnark:",public"`
	Zeros     [16]frontend.Variable // `gnark:",public"`
	ECB0      [16]frontend.Variable // `gnark:",public"`
	ECBK      [16]frontend.Variable // `gnark:",public"`
}

func NewTls13AuthTag(api frontend.API) Tls13AuthTag {
	return Tls13AuthTag{api: api}
}

func (circuit *Tls13AuthTag) SetParams(key, ivCounter, zeros, ecb0, ecbk [16]frontend.Variable) {
	circuit.Key = key
	circuit.IvCounter = ivCounter
	circuit.Zeros = zeros
	circuit.ECB0 = ecb0
	circuit.ECBK = ecbk
}

// Define declares the circuit's constraints
func (circuit *Tls13AuthTag) Assert() error {

	// aes circuit
	aes := NewAES128(circuit.api)

	// encrypt zeros
	ecbk := aes.Encrypt(circuit.Key, circuit.Zeros)

	// constraint check
	for i := 0; i < len(circuit.ECBK); i++ {
		circuit.api.AssertIsEqual(circuit.ECBK[i], ecbk[i])
	}

	// encrypt iv||counter=0
	ecb0 := aes.Encrypt(circuit.Key, circuit.IvCounter)

	// constraints check
	for i := 0; i < len(circuit.ECB0); i++ {
		circuit.api.AssertIsEqual(circuit.ECB0[i], ecb0[i])
	}

	return nil
}
