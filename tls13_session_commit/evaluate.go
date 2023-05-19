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
	"encoding/hex"
	"strings"
	"time"

	u "gnark_lib/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type Tls13SessionCommitWrapper struct {
	// kdc params
	DHSin                  [64]frontend.Variable
	IntermediateHashHSopad [32]frontend.Variable `gnark:",public"`
	MSin                   [32]frontend.Variable `gnark:",public"`
	SATSin                 [32]frontend.Variable `gnark:",public"`
	TkSAPPin               [32]frontend.Variable `gnark:",public"`
	TkCommit               [32]frontend.Variable `gnark:",public"`
	// authtag params
	IvCounter [16]frontend.Variable `gnark:",public"`
	Zeros     [16]frontend.Variable `gnark:",public"`
	ECB0      [16]frontend.Variable `gnark:",public"`
	ECBK      [16]frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *Tls13SessionCommitWrapper) Define(api frontend.API) error {

	// initialize circuit struct
	session_commit := New(api)

	// set data
	session_commit.SetKdcParams(
		circuit.IntermediateHashHSopad,
		circuit.MSin,
		circuit.SATSin,
		circuit.TkSAPPin,
		circuit.TkCommit,
		circuit.DHSin,
	)

	session_commit.SetAuthtagParams(
		circuit.IvCounter,
		circuit.Zeros,
		circuit.ECB0,
		circuit.ECBK,
	)

	// verify commitment
	session_commit.Assert()

	return nil
}

// execution of circuit function of program
func Evaluate(backend string, compile bool) (map[string]time.Duration, error) {

	// kdc params
	intermediateHashHSopad := "5113c2d6533a74ea90392417f726dc79c180819ad8a55bd809a5b38a0858b12f"
	dHSin := "dbd41fabc139fdc0252db510d6d61c4dd09bf913bf4b4534e7a3910d21a13b6b"
	MSin := "9be88f33141755dcc1846795217f8cd632559771fbd75fb45033ae0e3adfeefa"
	SATSin := "dae6d4b1df8df6e1ccb7d90463601475c70c4958ad98c2de07141f8baf77390b"
	tkSAPPin := "2feeba2461c64d98bd39a71ee1f20e59e7d85b3d99ad6a0e4fc8e29c3d9e8e0a"
	tkCommit := "e9c300234adbf690e81334e79d0c82b4e3a76a77d647c8d19df5968dc57248ba" // tkHash

	// authtag params
	iv := "a54613bf2801a84ce693d0a0"
	zeros := "00000000000000000000000000000000"
	ecb0 := "a5cd49b7c29ad21fedbcedc01e0f13e8"
	ecbk := "1c9c7c260c39bcb8dcfa5fbc9330b9fa"

	// add counter to iv bytes
	var sb strings.Builder
	for i := 0; i < len(iv); i++ {
		sb.WriteString(string(iv[i]))
	}
	for i := 0; i < 7; i++ {
		sb.WriteString("0")
	}
	sb.WriteString("1")
	ivCounter := sb.String()

	// kdc to bytes
	byteSlice, _ := hex.DecodeString(intermediateHashHSopad)
	intermediateHashHSopadByteLen := len(byteSlice)
	dHSSlice, _ := hex.DecodeString(dHSin)
	dHSinByteLen := len(dHSSlice)
	byteSlice, _ = hex.DecodeString(MSin)
	MSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(SATSin)
	SATSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(tkSAPPin)
	tkSAPPinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(tkCommit)
	tkCommitByteLen := len(byteSlice)

	// authtag to bytes
	byteSlice, _ = hex.DecodeString(ivCounter)
	ivCounterByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecb0)
	ecb0ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecbk)
	ecbkByteLen := len(byteSlice)

	// add padding out of circuit
	pad := u.PadSha256(96)
	dHSinPadded := make([]byte, 32+len(pad))
	copy(dHSinPadded, dHSSlice)
	copy(dHSinPadded[32:], pad)
	newdHSin := hex.EncodeToString(dHSinPadded)
	dHSinByteLen += 32

	// witness definition kdc
	intermediateHashHSopadAssign := u.StrToIntSlice(intermediateHashHSopad, true)
	dHSinAssign := u.StrToIntSlice(newdHSin, true)
	MSinAssign := u.StrToIntSlice(MSin, true)
	SATSinAssign := u.StrToIntSlice(SATSin, true)
	tkSAPPinAssign := u.StrToIntSlice(tkSAPPin, true)
	tkCommitAssign := u.StrToIntSlice(tkCommit, true)

	// witness definition authtag
	ivCounterAssign := u.StrToIntSlice(ivCounter, true)
	zerosAssign := u.StrToIntSlice(zeros, true)
	ecb0Assign := u.StrToIntSlice(ecb0, true)
	ecbkAssign := u.StrToIntSlice(ecbk, true)

	// witness values preparation
	assignment := Tls13SessionCommitWrapper{
		// kdc params
		IntermediateHashHSopad: [32]frontend.Variable{},
		DHSin:                  [64]frontend.Variable{},
		MSin:                   [32]frontend.Variable{},
		SATSin:                 [32]frontend.Variable{},
		TkSAPPin:               [32]frontend.Variable{},
		TkCommit:               [32]frontend.Variable{},
		// authtag params
		IvCounter: [16]frontend.Variable{},
		Zeros:     [16]frontend.Variable{},
		ECB0:      [16]frontend.Variable{},
		ECBK:      [16]frontend.Variable{},
	}

	// kdc assign
	for i := 0; i < intermediateHashHSopadByteLen; i++ {
		assignment.IntermediateHashHSopad[i] = intermediateHashHSopadAssign[i]
	}
	for i := 0; i < dHSinByteLen; i++ {
		assignment.DHSin[i] = dHSinAssign[i]
	}
	for i := 0; i < MSinByteLen; i++ {
		assignment.MSin[i] = MSinAssign[i]
	}
	for i := 0; i < SATSinByteLen; i++ {
		assignment.SATSin[i] = SATSinAssign[i]
	}
	for i := 0; i < tkSAPPinByteLen; i++ {
		assignment.TkSAPPin[i] = tkSAPPinAssign[i]
	}
	for i := 0; i < tkCommitByteLen; i++ {
		assignment.TkCommit[i] = tkCommitAssign[i]
	}

	// authtag assign
	for i := 0; i < ivCounterByteLen; i++ {
		assignment.IvCounter[i] = ivCounterAssign[i]
	}
	for i := 0; i < zerosByteLen; i++ {
		assignment.Zeros[i] = zerosAssign[i]
	}
	for i := 0; i < ecbkByteLen; i++ {
		assignment.ECBK[i] = ecbkAssign[i]
	}
	for i := 0; i < ecb0ByteLen; i++ {
		assignment.ECB0[i] = ecb0Assign[i]
	}

	// witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	// if err != nil {
	// 	log.Error().Msg("frontend.NewWitness")
	// 	return err
	// }
	// publicWitness, _ := witness.Public()

	// var circuit kdcServerKey
	var circuit Tls13SessionCommitWrapper

	data, err := u.ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}
