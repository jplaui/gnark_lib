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
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

// execution of circuit function of program
func EvaluateShacal2(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateShacal2")

	// kdc params
	intermediateHashHSopad := "5113c2d6533a74ea90392417f726dc79c180819ad8a55bd809a5b38a0858b12f"
	dHSin := "dbd41fabc139fdc0252db510d6d61c4dd09bf913bf4b4534e7a3910d21a13b6b"
	dHS := "383a915709aab199b4fed15bb09178d92353e4c60a7447efd3ad1742ca43ffa9"

	// kdc to bytes
	byteSlice, _ := hex.DecodeString(intermediateHashHSopad)
	intermediateHashHSopadByteLen := len(byteSlice)
	dHSSlice, _ := hex.DecodeString(dHSin)
	dHSinByteLen := len(dHSSlice)
	byteSlice, _ = hex.DecodeString(dHS)
	dHSByteLen := len(byteSlice)

	// add padding out of circuit
	pad := PadSha256(96)
	dHSinPadded := make([]byte, 32+len(pad))
	copy(dHSinPadded, dHSSlice)
	copy(dHSinPadded[32:], pad)
	newdHSin := hex.EncodeToString(dHSinPadded)
	dHSinByteLen += 32

	// witness definition kdc
	intermediateHashHSopadAssign := StrToIntSlice(intermediateHashHSopad, true)
	dHSinAssign := StrToIntSlice(newdHSin, true)
	dHSAssign := StrToIntSlice(dHS, true)

	// witness values preparation
	assignment := Shacal2Wrapper{
		IntermediateHashHSopad: [32]frontend.Variable{},
		DHSin:                  [64]frontend.Variable{},
		DHS:                    [32]frontend.Variable{},
	}

	// kdc assign
	for i := 0; i < intermediateHashHSopadByteLen; i++ {
		assignment.IntermediateHashHSopad[i] = intermediateHashHSopadAssign[i]
	}
	for i := 0; i < dHSinByteLen; i++ {
		assignment.DHSin[i] = dHSinAssign[i]
	}
	for i := 0; i < dHSByteLen; i++ {
		assignment.DHS[i] = dHSAssign[i]
	}

	// var circuit kdcServerKey
	var circuit Shacal2Wrapper

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

// execution of circuit function of program
func EvaluateSha256(backend string, compile bool, in, hash string) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateSha256")

	// kdc to bytes
	byteSlice, _ := hex.DecodeString(in)
	inByteLen := len(byteSlice)

	log.Debug().Str("length", strconv.Itoa(inByteLen)).Msg("sha256 input size")

	byteSlice, _ = hex.DecodeString(hash)
	hashByteLen := len(byteSlice)

	// witness definition kdc
	inAssign := StrToIntSlice(in, true)
	hashAssign := StrToIntSlice(hash, true)

	// witness values preparation
	assignment := Sha256Wrapper{
		In:   make([]frontend.Variable, inByteLen),
		Hash: [32]frontend.Variable{},
	}

	// kdc assign
	for i := 0; i < inByteLen; i++ {
		assignment.In[i] = inAssign[i]
	}
	for i := 0; i < hashByteLen; i++ {
		assignment.Hash[i] = hashAssign[i]
	}

	// var circuit kdcServerKey
	circuit := Sha256Wrapper{
		In: make([]frontend.Variable, inByteLen),
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

// execution of circuit function of program
func EvaluateMimc(backend string, compile bool, in []big.Int, hash []byte) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateMimc")

	// kdc to bytes
	// byteSlice, _ := hex.DecodeString(in)
	inByteLen := len(in)

	log.Debug().Str("length", strconv.Itoa(inByteLen)).Msg("mimc input size")

	// byteSlice, _ = hex.DecodeString(hash)
	// hashByteLen := len(byteSlice)

	// s := "a"
	// i := new(big.Int)
	// i.SetString(s, 16)
	// fmt.Println(i)

	// witness definition kdc
	// inAssign := StrToIntSlice(in, true)
	// hashAssign := StrToIntSlice(hash, true)

	// witness values preparation
	assignment := MimcWrapper{
		In:   make([]frontend.Variable, inByteLen),
		Hash: hash,
	}

	// kdc assign
	for i := 0; i < inByteLen; i++ {
		assignment.In[i] = in[i].String()
	}

	// var circuit kdcServerKey
	circuit := MimcWrapper{
		In: make([]frontend.Variable, inByteLen),
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateAES128(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateAES128")

	key := "2872658573f95e87550cb26374e5f667"
	zeros := "00000000000000000000000000000000"
	ecb0 := "1c9c7c260c39bcb8dcfa5fbc9330b9fa"

	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecb0)
	ecb0ByteLen := len(byteSlice)

	// witness definition kdc
	keyAssign := StrToIntSlice(key, true)
	zerosAssign := StrToIntSlice(zeros, true)
	ecb0Assign := StrToIntSlice(ecb0, true)

	// witness values preparation
	assignment := AES128Wrapper{
		Plain:  [16]frontend.Variable{},
		Key:    [16]frontend.Variable{},
		Cipher: [16]frontend.Variable{},
	}

	// kdc assign
	for i := 0; i < zerosByteLen; i++ {
		assignment.Plain[i] = zerosAssign[i]
	}
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < ecb0ByteLen; i++ {
		assignment.Cipher[i] = ecb0Assign[i]
	}

	// var circuit kdcServerKey
	var circuit AES128Wrapper

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateAuthTag(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateAuthTag")

	// aes data
	key := "2872658573f95e87550cb26374e5f667"
	iv := "a54613bf2801a84ce693d0a0"

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

	zeros := "00000000000000000000000000000000"
	ecb0 := "a5cd49b7c29ad21fedbcedc01e0f13e8"
	ecbk := "1c9c7c260c39bcb8dcfa5fbc9330b9fa"

	// convert to bytes
	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	dHSSlice, _ := hex.DecodeString(ivCounter)
	ivCounterByteLen := len(dHSSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecb0)
	ecb0ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ecbk)
	ecbkByteLen := len(byteSlice)

	// witness definition
	keyAssign := StrToIntSlice(key, true)
	ivCounterAssign := StrToIntSlice(ivCounter, true)
	zerosAssign := StrToIntSlice(zeros, true)
	ecb0Assign := StrToIntSlice(ecb0, true)
	ecbkAssign := StrToIntSlice(ecbk, true)

	// witness values preparation
	assignment := AuthTagWrapper{
		Key:       [16]frontend.Variable{},
		IvCounter: [16]frontend.Variable{},
		Zeros:     [16]frontend.Variable{},
		ECB0:      [16]frontend.Variable{},
		ECBK:      [16]frontend.Variable{},
	}

	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
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

	// var circuit kdcServerKey
	var circuit AuthTagWrapper

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateGCM(backend string, compile bool, key string, chunkIndex int, nonce, plaintext, ciphertext string) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateGCM")

	// convert to bytes
	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(nonce)
	nonceByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(plaintext)
	ptByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ciphertext)
	ctByteLen := len(byteSlice)

	log.Debug().Str("length", strconv.Itoa(ptByteLen)).Msg("GCM computation of length bytes")

	// witness definition
	keyAssign := StrToIntSlice(key, true)
	nonceAssign := StrToIntSlice(nonce, true)
	ptAssign := StrToIntSlice(plaintext, true)
	ctAssign := StrToIntSlice(ciphertext, true)

	// witness values preparation
	assignment := GCMWrapper{
		PlainChunks:  make([]frontend.Variable, ptByteLen),
		CipherChunks: make([]frontend.Variable, ctByteLen),
		ChunkIndex:   chunkIndex, // frontend.Variable(chunkIdx),
		Iv:           [12]frontend.Variable{},
		Key:          [16]frontend.Variable{}, // make([]frontend.Variable, 16), //[16]frontend.Variable{},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < ptByteLen; i++ {
		assignment.PlainChunks[i] = ptAssign[i]
	}
	for i := 0; i < ctByteLen; i++ {
		assignment.CipherChunks[i] = ctAssign[i]
	}
	for i := 0; i < nonceByteLen; i++ {
		assignment.Iv[i] = nonceAssign[i]
	}
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}

	// var circuit kdcServerKey
	circuit := GCMWrapper{
		PlainChunks:  make([]frontend.Variable, ptByteLen),
		CipherChunks: make([]frontend.Variable, ctByteLen),
		ChunkIndex:   chunkIndex,
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateKdc(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateKdc")

	// data
	dHSin := "3352927e78c6f8ff6e09a9cdbd13f22f94467f85316bb1d4be826c449d2c7f9f"
	MSin := "36d9ab5e3faed3958c2ed545c7529426d766b2d5cd9422dccb7ca90c7a62579d"
	SATSin := "a274333afcd102039bb1bc0632e1488858375420a55937c878a6fbdb1915ca94"
	intermediateHashHSopad := "4b666cdc720a74082b1594c95367f3c71f5124db03add4877e959c6c50c7e3b5"
	tkSAPPin := "b7c39a10f4650ad160dfe8161ad74020ac50447768894252f7504aafb0c11d36"
	sk := "58e95f7a4abe43fa68c785039f09dce8"

	byteSlice, _ := hex.DecodeString(intermediateHashHSopad)
	intermediateHashHSopadByteLen := len(byteSlice)
	dHSSlice, _ := hex.DecodeString(dHSin)
	dHSinByteLen := len(dHSSlice)
	byteSlice, _ = hex.DecodeString(MSin)
	MSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(SATSin)
	XATSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(tkSAPPin)
	tkXAPPinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(sk)
	skByteLen := len(byteSlice)

	// add padding
	pad := PadSha256(96)
	dHSinPadded := make([]byte, 32+len(pad))
	copy(dHSinPadded, dHSSlice)
	copy(dHSinPadded[32:], pad)
	newdHSin := hex.EncodeToString(dHSinPadded)
	dHSinByteLen += 32

	// witness definition
	intermediateHashHSopadAssign := StrToIntSlice(intermediateHashHSopad, true)
	dHSinAssign := StrToIntSlice(newdHSin, true)
	MSinAssign := StrToIntSlice(MSin, true)
	XATSinAssign := StrToIntSlice(SATSin, true)
	tkXAPPinAssign := StrToIntSlice(tkSAPPin, true)
	skAssign := StrToIntSlice(sk, true)

	// witness values preparation
	assignment := KdcWrapper{
		IntermediateHashHSopad: [32]frontend.Variable{},
		DHSin:                  [64]frontend.Variable{},
		MSin:                   [32]frontend.Variable{},
		XATSin:                 [32]frontend.Variable{},
		TkXAPPin:               [32]frontend.Variable{},
		TkXAPP:                 [16]frontend.Variable{},
	}

	for i := 0; i < intermediateHashHSopadByteLen; i++ {
		assignment.IntermediateHashHSopad[i] = intermediateHashHSopadAssign[i]
	}
	for i := 0; i < dHSinByteLen; i++ {
		assignment.DHSin[i] = dHSinAssign[i]
	}
	for i := 0; i < MSinByteLen; i++ {
		assignment.MSin[i] = MSinAssign[i]
	}
	for i := 0; i < XATSinByteLen; i++ {
		assignment.XATSin[i] = XATSinAssign[i]
	}
	for i := 0; i < tkXAPPinByteLen; i++ {
		assignment.TkXAPPin[i] = tkXAPPinAssign[i]
	}
	for i := 0; i < skByteLen; i++ {
		assignment.TkXAPP[i] = skAssign[i]
	}

	// var circuit kdcServerKey
	var circuit KdcWrapper

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateRecord(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateRecord")

	key := "2872658573f95e87550cb26374e5f667"
	iv := "a54613bf2801a84ce693d0a0"
	chipherChunks := "419a031754a4897806533c6020e9130f6088747b9f9a1e1eba4cb0518a6d5692"
	plainChunks := "302c353631204575726f227d2c227072696365223a2233383030322e32222c22"
	chunkIndex := 32
	substring := "\"price\""
	substringStart := 13
	substringEnd := 20
	valueStart := 23
	valueEnd := 28
	threshold := 38003

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

	log.Debug().Str("length", strconv.Itoa(plainChunksByteLen)).Msg("record proof length plaintext/ciphertext")

	// witness definition
	keyAssign := StrToIntSlice(key, true)
	ivAssign := StrToIntSlice(iv, true)
	chipherChunksAssign := StrToIntSlice(chipherChunks, true)
	plainChunksAssign := StrToIntSlice(plainChunks, true)
	substringAssign := StrToIntSlice(substring, false)

	// witness values preparation
	assignment := RecordWrapper{
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

	// var circuit kdcServerKey
	circuit := RecordWrapper{
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

func EvaluateXor(backend string, compile bool, in, mask, out string) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateXor")

	// convert to bytes
	byteSlice, _ := hex.DecodeString(in)
	inByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(mask)
	maskByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(out)
	outByteLen := len(byteSlice)

	log.Debug().Str("length", strconv.Itoa(inByteLen)).Msg("XOR bytes length")

	// witness definition
	inAssign := StrToIntSlice(in, true)
	maskAssign := StrToIntSlice(mask, true)
	outAssign := StrToIntSlice(out, true)

	// witness values preparation
	assignment := XorWrapper{
		In:   make([]frontend.Variable, inByteLen),
		Mask: make([]frontend.Variable, maskByteLen),
		Out:  make([]frontend.Variable, outByteLen),
	}

	// assign values here because required to use make in assignment
	for i := 0; i < inByteLen; i++ {
		assignment.In[i] = inAssign[i]
	}
	for i := 0; i < maskByteLen; i++ {
		assignment.Mask[i] = maskAssign[i]
	}
	for i := 0; i < outByteLen; i++ {
		assignment.Out[i] = outAssign[i]
	}

	// var circuit kdcServerKey
	circuit := XorWrapper{
		In:   make([]frontend.Variable, inByteLen),
		Mask: make([]frontend.Variable, maskByteLen),
		Out:  make([]frontend.Variable, outByteLen),
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateSubstring(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateSubstring")

	plainChunks := "302c353631204575726f227d2c227072696365223a2233383030322e32222c22"
	substring := "\"price\""
	substringStart := 13
	substringEnd := 20

	// convert to bytes
	byteSlice, _ := hex.DecodeString(plainChunks)
	plainChunksByteLen := len(byteSlice)
	substringByteLen := len(substring)

	log.Debug().Str("length", strconv.Itoa(substringByteLen)).Msg("Substring bytes length")

	// witness definition
	plainChunksAssign := StrToIntSlice(plainChunks, true)
	substringAssign := StrToIntSlice(substring, false)

	// witness values preparation
	assignment := SubstringWrapper{
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
	}

	// assign values here because required to use make in assignment
	for i := 0; i < plainChunksByteLen; i++ {
		assignment.PlainChunks[i] = plainChunksAssign[i]
	}
	for i := 0; i < substringByteLen; i++ {
		assignment.Substring[i] = substringAssign[i]
	}

	// var circuit kdcServerKey
	circuit := SubstringWrapper{
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateStr2Int(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateStr2Int")

	plainChunks := "302c353631204575726f227d2c227072696365223a2233383030322e32222c22"
	valueStart := 22
	valueEnd := 27
	value := 38002

	// convert to bytes
	byteSlice, _ := hex.DecodeString(plainChunks)
	plainChunksByteLen := len(byteSlice)

	log.Debug().Str("length", strconv.Itoa(valueEnd-valueStart)).Msg("Substring bytes length")

	// witness definition
	plainChunksAssign := StrToIntSlice(plainChunks, true)

	// witness values preparation
	assignment := Str2IntWrapper{
		PlainChunks: make([]frontend.Variable, plainChunksByteLen),
		Value:       value,
		ValueStart:  valueStart,
		ValueEnd:    valueEnd,
	}

	// assign values here because required to use make in assignment
	for i := 0; i < plainChunksByteLen; i++ {
		assignment.PlainChunks[i] = plainChunksAssign[i]
	}

	// var circuit kdcServerKey
	circuit := Str2IntWrapper{
		PlainChunks: make([]frontend.Variable, plainChunksByteLen),
		Value:       value,
		ValueStart:  valueStart,
		ValueEnd:    valueEnd,
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}

func EvaluateGTLT(backend string, compile bool) (map[string]time.Duration, error) {

	log.Debug().Msg("EvaluateGTLT")

	value := 38002
	threshold := 38001

	// witness values preparation
	assignment := GTLTWrapper{
		Value:     value,
		Threshold: threshold,
	}

	// var circuit kdcServerKey
	circuit := GTLTWrapper{
		Value:     value,
		Threshold: threshold,
	}

	data, err := ProofWithBackend(backend, compile, &circuit, &assignment, ecc.BN254)

	return data, err
}
