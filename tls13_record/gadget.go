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

package tls13_record

import (
	aes "gnark_circuits/aes128"
	u "gnark_circuits/utils"

	"github.com/consensys/gnark/frontend"
)

type Tls13Record struct {
	api            frontend.API
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
}

func New(api frontend.API) Tls13Record {
	return Tls13Record{api: api}
}

func (circuit *Tls13Record) SetParams(key [16]frontend.Variable, iv [12]frontend.Variable, plainChunks, cipherChunks, substring []frontend.Variable, chunkIndex, threshold frontend.Variable, substringStart, substringEnd, valueStart, valueEnd int) {
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

// Define declares the circuit's constraints
func (circuit *Tls13Record) Assert() error {

	// aes circuit
	aesAPI := aes.New(circuit.api)

	// verify aes gcm of chunks
	aesAPI.GCM(circuit.Key, circuit.Iv, circuit.ChunkIndex, circuit.PlainChunks, circuit.CipherChunks)

	// continue with verified plaintext, extract substring from it, and perform constraint check
	extractedSubstring := circuit.PlainChunks[circuit.SubstringStart:circuit.SubstringEnd]
	u.SubstringMatch(circuit.api, circuit.Substring, extractedSubstring, 0, len(circuit.Substring))

	// convert string value to integer
	valueString := circuit.PlainChunks[circuit.ValueStart:circuit.ValueEnd]
	circuit.api.Println("valueString:", valueString[:])
	valueInteger := u.StringToInt(circuit.api, valueString)
	circuit.api.Println("valueInteger:", valueInteger)

	// data constraint checks
	u.GreaterThan(circuit.api, valueInteger, circuit.Threshold)

	return nil
}
