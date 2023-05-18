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

package tls13_session_commit

import (
	sha256 "gnark_circuits/sha256"
	tag13 "gnark_circuits/tls13_authtag"
	kdc "gnark_circuits/tls13_kdc"

	"github.com/consensys/gnark/frontend"
)

type Tls13SessionCommit struct {
	api frontend.API

	// kdc params
	DHSin                  [64]frontend.Variable
	IntermediateHashHSopad [32]frontend.Variable // `gnark:",public"`
	MSin                   [32]frontend.Variable // `gnark:",public"`
	XATSin                 [32]frontend.Variable // `gnark:",public"`
	TkXAPPin               [32]frontend.Variable // `gnark:",public"`
	TkCommit               [32]frontend.Variable // `gnark:",public"`

	// authtag params
	IvCounter [16]frontend.Variable // `gnark:",public"`
	Zeros     [16]frontend.Variable // `gnark:",public"`
	ECB0      [16]frontend.Variable // `gnark:",public"`
	ECBK      [16]frontend.Variable // `gnark:",public"`
}

func New(api frontend.API) Tls13SessionCommit {
	return Tls13SessionCommit{api: api}
}

func (circuit *Tls13SessionCommit) SetKdcParams(IntermediateHashHSopad, MSin, XATSin, TkXAPPin, TkCommit [32]frontend.Variable, DHSin [64]frontend.Variable) {
	circuit.IntermediateHashHSopad = IntermediateHashHSopad
	circuit.MSin = MSin
	circuit.XATSin = XATSin
	circuit.TkXAPPin = TkXAPPin
	circuit.TkCommit = TkCommit
	circuit.DHSin = DHSin
}

func (circuit *Tls13SessionCommit) SetAuthtagParams(ivCounter, zeros, ecb0, ecbk [16]frontend.Variable) {
	circuit.IvCounter = ivCounter
	circuit.Zeros = zeros
	circuit.ECB0 = ecb0
	circuit.ECBK = ecbk
}

// Define declares the circuit's constraints
func (circuit *Tls13SessionCommit) Assert() {

	// kdc verification

	// derive key
	tls13_kdc := kdc.New(circuit.api)
	tls13_kdc.SetParams(
		circuit.IntermediateHashHSopad,
		circuit.MSin,
		circuit.XATSin,
		circuit.TkXAPPin,
		circuit.DHSin,
	)
	tk := tls13_kdc.Derive()

	// compute key commitment
	sha := sha256.New(circuit.api)
	sha.Write(tk)
	commit := sha.Sum()

	// constraints check
	for i := 0; i < 32; i++ {
		circuit.api.AssertIsEqual(circuit.TkCommit[i], commit[i])
	}

	// authtag verification

	// init
	tag := tag13.New(circuit.api)

	// type conversion
	var tk16 [16]frontend.Variable
	copy(tk16[:], tk)
	tag.SetParams(tk16, circuit.IvCounter, circuit.Zeros, circuit.ECB0, circuit.ECBK)

	// verify tag
	tag.Assert()
}
