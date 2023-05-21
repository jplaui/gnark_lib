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
	"encoding/hex"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// execution of circuit function of program
func EvaluateSessionData(backend string, compile bool) (map[string]time.Duration, error) {

	// record params
	key := "2872658573f95e87550cb26374e5f667"
	iv := "a54613bf2801a84ce693d0a0"
	chipherChunks := "419a031754a4897806533c6020e9130f6088747b9f9a1e1eba4cb0518a6d5692"
	plainChunks := "302c353631204575726f227d2c227072696365223a2233383030322e32222c22"
	chunkIndex := 32
	substring := "\"price\""
	substringStart := 13
	substringEnd := 20
	valueStart := 22
	valueEnd := 27
	threshold := 38001

	// commit params
	tkCommit := "e9c300234adbf690e81334e79d0c82b4e3a76a77d647c8d19df5968dc57248ba" // tkHash

	// record to bytes
	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(iv)
	ivByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(chipherChunks)
	chipherChunksByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(plainChunks)
	plainChunksByteLen := len(byteSlice)
	substringByteLen := len(substring)
	byteSlice, _ = hex.DecodeString(tkCommit)
	tkCommitByteLen := len(byteSlice)

	// witness definition
	keyAssign := StrToIntSlice(key, true)
	ivAssign := StrToIntSlice(iv, true)
	chipherChunksAssign := StrToIntSlice(chipherChunks, true)
	plainChunksAssign := StrToIntSlice(plainChunks, true)
	substringAssign := StrToIntSlice(substring, false)
	tkCommitAssign := StrToIntSlice(tkCommit, true)

	// witness values preparation
	assignment := Tls13SessionDataWrapper{
		// commit params
		TkCommit: [32]frontend.Variable{},
		// record params
		Key:            [16]frontend.Variable{},
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		Iv:             [12]frontend.Variable{},
		CipherChunks:   make([]frontend.Variable, chipherChunksByteLen),
		ChunkIndex:     chunkIndex,
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
		ValueStart:     valueStart,
		ValueEnd:       valueEnd,
		Threshold:      threshold,
	}

	// kdc assign
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < plainChunksByteLen; i++ {
		assignment.PlainChunks[i] = plainChunksAssign[i]
	}
	for i := 0; i < ivByteLen; i++ {
		assignment.Iv[i] = ivAssign[i]
	}
	for i := 0; i < chipherChunksByteLen; i++ {
		assignment.CipherChunks[i] = chipherChunksAssign[i]
	}
	for i := 0; i < substringByteLen; i++ {
		assignment.Substring[i] = substringAssign[i]
	}
	for i := 0; i < tkCommitByteLen; i++ {
		assignment.TkCommit[i] = tkCommitAssign[i]
	}

	// var circuit kdcServerKey
	circuit := Tls13SessionDataWrapper{
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		CipherChunks:   make([]frontend.Variable, chipherChunksByteLen),
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
		ValueStart:     valueStart,
		ValueEnd:       valueEnd,
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}
