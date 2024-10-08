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

type Tls13DecoProxyWrapper struct {
	// record params
	Key            [16]frontend.Variable
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
	// commit params
	TkCommit [32]frontend.Variable `gnark:",public"`
	// authtag params
	IvCounter [16]frontend.Variable `gnark:",public"`
	Zeros     [16]frontend.Variable `gnark:",public"`
	ECB0      [16]frontend.Variable `gnark:",public"`
	ECBK      [16]frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *Tls13DecoProxyWrapper) Define(api frontend.API) error {

	// initialize circuit struct
	session_data := NewTls13DecoProxy(api)

	// set data
	session_data.SetCommitParams(circuit.TkCommit)
	session_data.SetAuthtagParams(
		circuit.IvCounter,
		circuit.Zeros,
		circuit.ECB0,
		circuit.ECBK,
	)
	session_data.SetRecordParams(
		circuit.Key,
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

	// verify everything
	session_data.Assert()

	return nil
}

type Tls13DecoProxy struct {
	api frontend.API

	// record params
	Key            [16]frontend.Variable
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

	// authtag params
	IvCounter [16]frontend.Variable // `gnark:",public"`
	Zeros     [16]frontend.Variable // `gnark:",public"`
	ECB0      [16]frontend.Variable // `gnark:",public"`
	ECBK      [16]frontend.Variable // `gnark:",public"`

	// commitment params
	TkCommit [32]frontend.Variable // `gnark:",public"`
}

func NewTls13DecoProxy(api frontend.API) Tls13DecoProxy {
	return Tls13DecoProxy{api: api}
}

func (circuit *Tls13DecoProxy) SetRecordParams(key [16]frontend.Variable, iv [12]frontend.Variable, plainChunks, cipherChunks, substring []frontend.Variable, chunkIndex, threshold frontend.Variable, substringStart, substringEnd, valueStart, valueEnd int) {
	circuit.Key = key
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

func (circuit *Tls13DecoProxy) SetAuthtagParams(ivCounter, zeros, ecb0, ecbk [16]frontend.Variable) {
	circuit.IvCounter = ivCounter
	circuit.Zeros = zeros
	circuit.ECB0 = ecb0
	circuit.ECBK = ecbk
}

func (circuit *Tls13DecoProxy) SetCommitParams(tkCommit [32]frontend.Variable) {
	circuit.TkCommit = tkCommit
}

// Define declares the circuit's constraints
func (circuit *Tls13DecoProxy) Assert() {

	// commit verification

	// init
	sha := NewSHA256(circuit.api)
	sha.Write(circuit.Key[:])
	keyCommit := sha.Sum()

	// constraints check
	for i := 0; i < len(circuit.TkCommit); i++ {
		circuit.api.AssertIsEqual(circuit.TkCommit[i], keyCommit[i])
	}

	// authtag verification

	// init
	tag := NewTls13AuthTag(circuit.api)

	// type conversion
	tag.SetParams(circuit.Key, circuit.IvCounter, circuit.Zeros, circuit.ECB0, circuit.ECBK)

	// verify tag
	tag.Assert()

	// policy-based record verification

	// init
	record := NewTls13Record(circuit.api)

	// insert data
	record.SetParams(
		circuit.Key,
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
