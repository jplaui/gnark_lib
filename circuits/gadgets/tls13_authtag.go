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
	ECB1      [16]frontend.Variable `gnark:",public"`
	ECB0      [16]frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *AuthTagWrapper) Define(api frontend.API) error {

	tag := NewTls13AuthTag(api)

	// type conversion
	tag.SetParams(
		circuit.Key,
		circuit.IvCounter,
		circuit.Zeros,
		circuit.ECB1,
		circuit.ECB0,
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
	ECB1      [16]frontend.Variable // `gnark:",public"`
	ECB0      [16]frontend.Variable // `gnark:",public"`
}

func NewTls13AuthTag(api frontend.API) Tls13AuthTag {
	return Tls13AuthTag{api: api}
}

func (circuit *Tls13AuthTag) SetParams(key, ivCounter, zeros, ecb1, ecb0 [16]frontend.Variable) {
	circuit.Key = key
	circuit.IvCounter = ivCounter
	circuit.Zeros = zeros
	circuit.ECB1 = ecb1
	circuit.ECB0 = ecb0
}

// Define declares the circuit's constraints
func (circuit *Tls13AuthTag) Assert() error {

	// aes circuit
	// aes := NewAES128(circuit.api) // for groth16
	aes := NewLookUpAES128(circuit.api) // for lookup plonk

	// encrypt zeros
	ecb0 := aes.Encrypt(circuit.Key[:], circuit.Zeros)

	// constraint check
	for i := 0; i < len(circuit.ECB0); i++ {
		circuit.api.AssertIsEqual(circuit.ECB0[i], ecb0[i])
	}

	// encrypt iv||counter=0
	ecb1 := aes.Encrypt(circuit.Key[:], circuit.IvCounter)

	// constraints check
	for i := 0; i < len(circuit.ECB1); i++ {
		circuit.api.AssertIsEqual(circuit.ECB1[i], ecb1[i])
	}

	return nil
}
