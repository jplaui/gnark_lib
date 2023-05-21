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

type Tls13SessionDataWrapper struct {
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
	TkCommit       [32]frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *Tls13SessionDataWrapper) Define(api frontend.API) error {

	// initialize circuit struct
	session_data := NewTls13SessionData(api)

	// set data
	session_data.SetCommitParams(circuit.TkCommit)
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

type Tls13SessionData struct {
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

	// commitment params
	TkCommit [32]frontend.Variable // `gnark:",public"`
}

func NewTls13SessionData(api frontend.API) Tls13SessionData {
	return Tls13SessionData{api: api}
}

func (circuit *Tls13SessionData) SetRecordParams(key [16]frontend.Variable, iv [12]frontend.Variable, plainChunks, cipherChunks, substring []frontend.Variable, chunkIndex, threshold frontend.Variable, substringStart, substringEnd, valueStart, valueEnd int) {
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

func (circuit *Tls13SessionData) SetCommitParams(tkCommit [32]frontend.Variable) {
	circuit.TkCommit = tkCommit
}

// Define declares the circuit's constraints
func (circuit *Tls13SessionData) Assert() {

	// commit verification

	// commit function
	sha := NewSHA256(circuit.api)
	sha.Write(circuit.Key[:])
	keyCommit := sha.Sum()

	// constraints check
	for i := 0; i < len(circuit.TkCommit); i++ {
		circuit.api.AssertIsEqual(circuit.TkCommit[i], keyCommit[i])
	}

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
