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

type KdcWrapper struct {
	DHSin                  [64]frontend.Variable
	IntermediateHashHSopad [32]frontend.Variable `gnark:",public"`
	MSin                   [32]frontend.Variable `gnark:",public"`
	XATSin                 [32]frontend.Variable `gnark:",public"`
	TkXAPPin               [32]frontend.Variable `gnark:",public"`
	TkXAPP                 [16]frontend.Variable `gnark:",public"`
}

func (circuit *KdcWrapper) Define(api frontend.API) error {

	tls13_kdc := NewTls13Kdc(api)
	tls13_kdc.SetParams(
		circuit.IntermediateHashHSopad,
		circuit.MSin,
		circuit.XATSin,
		circuit.TkXAPPin,
		circuit.DHSin,
	)
	tk := tls13_kdc.Derive()

	for i := 0; i < 16; i++ {
		api.AssertIsEqual(tk[i], circuit.TkXAPP[i])
	}

	return nil
}

type Tls13Kdc struct {
	api                    frontend.API
	DHSin                  [64]frontend.Variable
	IntermediateHashHSopad [32]frontend.Variable // `gnark:",public"`
	MSin                   [32]frontend.Variable // `gnark:",public"`
	XATSin                 [32]frontend.Variable // `gnark:",public"`
	TkXAPPin               [32]frontend.Variable // `gnark:",public"`
}

func NewTls13Kdc(api frontend.API) Tls13Kdc {
	return Tls13Kdc{api: api}
}

func (circuit *Tls13Kdc) SetParams(IntermediateHashHSopad, MSin, XATSin, TkXAPPin [32]frontend.Variable, DHSin [64]frontend.Variable) {
	circuit.DHSin = DHSin
	circuit.IntermediateHashHSopad = IntermediateHashHSopad
	circuit.MSin = MSin
	circuit.XATSin = XATSin
	circuit.TkXAPPin = TkXAPPin
}

// Define declares the circuit's constraints
func (circuit *Tls13Kdc) Derive() []frontend.Variable {

	// gadget imports
	sha := NewSHA256(circuit.api)

	// optimized shacal2
	shacal := NewSHA256WithIV(circuit.api, circuit.IntermediateHashHSopad, 64)
	dHS := shacal.WriteReturn(circuit.DHSin[:])

	// dHS xor opad, and concatenate with MSIn
	dHSopadConcatMSin := OpadConcat(circuit.api, dHS, circuit.MSin)

	// compute MS
	sha.Write(dHSopadConcatMSin)
	MS := sha.Sum()
	sha.Reset()

	// MS xor opad, and concatenate with XATSin
	MSopadConcatXATSin := OpadConcat(circuit.api, MS, circuit.XATSin)

	// compute XATS
	sha.Write(MSopadConcatXATSin)
	XATS := sha.Sum()
	sha.Reset()

	// XATS xor opad, and concatenate with tkXAPPin
	XATSopadConcattkXAPPin := OpadConcat(circuit.api, XATS, circuit.TkXAPPin)

	// traffic key
	sha.Write(XATSopadConcattkXAPPin)
	tkXAPP := sha.Sum()

	return tkXAPP[:16]
}
