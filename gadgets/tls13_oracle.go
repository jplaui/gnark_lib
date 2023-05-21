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

type Tls13OracleWrapper struct {
	// kdc params
	DHSin                  [64]frontend.Variable
	IntermediateHashHSopad [32]frontend.Variable `gnark:",public"`
	MSin                   [32]frontend.Variable `gnark:",public"`
	SATSin                 [32]frontend.Variable `gnark:",public"`
	TkSAPPin               [32]frontend.Variable `gnark:",public"`
	// TkCommit               [32]frontend.Variable `gnark:",public"`
	// authtag params
	IvCounter [16]frontend.Variable `gnark:",public"`
	Zeros     [16]frontend.Variable `gnark:",public"`
	ECB0      [16]frontend.Variable `gnark:",public"`
	ECBK      [16]frontend.Variable `gnark:",public"`
	// record params
	PlainChunks    []frontend.Variable
	Iv             [12]frontend.Variable `gnark:",public"`
	CipherChunks   []frontend.Variable   `gnark:",public"`
	ChunkIndex     frontend.Variable     `gnark:",public"`
	Substring      []frontend.Variable   `gnark:",public"`
	SubstringStart int                   `gnark:",public"`
	SubstringEnd   int                   `gnark:",public"`
	ValueStart     int                   `gnark:",public"`
	ValueEnd       int                   `gnark:",public"`
	Threshold      frontend.Variable     `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *Tls13OracleWrapper) Define(api frontend.API) error {

	// initialize circuit struct
	oracle := NewTls13Oracle(api)

	// set data
	oracle.SetKdcParams(
		circuit.IntermediateHashHSopad,
		circuit.MSin,
		circuit.SATSin,
		circuit.TkSAPPin,
		// circuit.TkCommit,
		circuit.DHSin,
	)

	oracle.SetAuthtagParams(
		circuit.IvCounter,
		circuit.Zeros,
		circuit.ECB0,
		circuit.ECBK,
	)

	oracle.SetRecordParams(
		circuit.Iv,
		circuit.PlainChunks,
		circuit.CipherChunks,
		circuit.Substring,
		circuit.ChunkIndex,
		circuit.Threshold,
		circuit.SubstringStart,
		circuit.SubstringEnd,
		circuit.ValueStart,
		circuit.ValueEnd,
	)

	// verify commitment
	oracle.Assert()

	return nil
}

type Tls13Oracle struct {
	api frontend.API

	// kdc params
	DHSin                  [64]frontend.Variable
	IntermediateHashHSopad [32]frontend.Variable // `gnark:",public"`
	MSin                   [32]frontend.Variable // `gnark:",public"`
	XATSin                 [32]frontend.Variable // `gnark:",public"`
	TkXAPPin               [32]frontend.Variable // `gnark:",public"`
	// TkCommit               [32]frontend.Variable // `gnark:",public"`

	// authtag params
	IvCounter [16]frontend.Variable // `gnark:",public"`
	Zeros     [16]frontend.Variable // `gnark:",public"`
	ECB0      [16]frontend.Variable // `gnark:",public"`
	ECBK      [16]frontend.Variable // `gnark:",public"`

	// record params
	PlainChunks    []frontend.Variable
	Iv             [12]frontend.Variable // `gnark:",public"`
	CipherChunks   []frontend.Variable   // `gnark:",public"`
	ChunkIndex     frontend.Variable     // `gnark:",public"`
	Substring      []frontend.Variable   // `gnark:",public"`
	SubstringStart int                   // `gnark:",public"`
	SubstringEnd   int                   // `gnark:",public"`
	ValueStart     int                   // `gnark:",public"`
	ValueEnd       int                   // `gnark:",public"`
	Threshold      frontend.Variable     // `gnark:",public"`
}

func NewTls13Oracle(api frontend.API) Tls13Oracle {
	return Tls13Oracle{api: api}
}

func (circuit *Tls13Oracle) SetKdcParams(IntermediateHashHSopad, MSin, XATSin, TkXAPPin [32]frontend.Variable, DHSin [64]frontend.Variable) {
	circuit.IntermediateHashHSopad = IntermediateHashHSopad
	circuit.MSin = MSin
	circuit.XATSin = XATSin
	circuit.TkXAPPin = TkXAPPin
	// circuit.TkCommit = TkCommit
	circuit.DHSin = DHSin
}

func (circuit *Tls13Oracle) SetAuthtagParams(ivCounter, zeros, ecb0, ecbk [16]frontend.Variable) {
	circuit.IvCounter = ivCounter
	circuit.Zeros = zeros
	circuit.ECB0 = ecb0
	circuit.ECBK = ecbk
}

func (circuit *Tls13Oracle) SetRecordParams(iv [12]frontend.Variable, plainChunks, cipherChunks, substring []frontend.Variable, chunkIndex, threshold frontend.Variable, substringStart, substringEnd, valueStart, valueEnd int) {
	circuit.PlainChunks = plainChunks
	circuit.Iv = iv
	circuit.CipherChunks = cipherChunks
	circuit.ChunkIndex = chunkIndex
	circuit.Substring = substring
	circuit.Threshold = threshold
	circuit.SubstringStart = substringStart
	circuit.SubstringEnd = substringEnd
	circuit.ValueStart = valueStart
	circuit.ValueEnd = valueEnd
}

// Define declares the circuit's constraints
func (circuit *Tls13Oracle) Assert() {

	// kdc verification

	// derive key
	tls13_kdc := NewTls13Kdc(circuit.api)
	tls13_kdc.SetParams(
		circuit.IntermediateHashHSopad,
		circuit.MSin,
		circuit.XATSin,
		circuit.TkXAPPin,
		circuit.DHSin,
	)
	tk := tls13_kdc.Derive()

	// authtag verification

	// init
	tag := NewTls13AuthTag(circuit.api)

	// type conversion
	var tk16 [16]frontend.Variable
	copy(tk16[:], tk)
	tag.SetParams(tk16, circuit.IvCounter, circuit.Zeros, circuit.ECB0, circuit.ECBK)

	// verify tag
	tag.Assert()

	// policy-based data verification

	// init
	record := NewTls13Record(circuit.api)

	// insert data
	record.SetParams(
		tk16,
		circuit.Iv,
		circuit.PlainChunks,
		circuit.CipherChunks,
		circuit.Substring,
		circuit.ChunkIndex,
		circuit.Threshold,
		circuit.SubstringStart,
		circuit.SubstringEnd,
		circuit.ValueStart,
		circuit.ValueEnd,
	)

	// verify
	record.Assert()
}
