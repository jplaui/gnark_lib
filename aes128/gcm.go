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

package aes128

import (
	"github.com/consensys/gnark/frontend"
)

// aes gcm encryption
func (aes *AES128) GCM(key [16]frontend.Variable, iv [12]frontend.Variable, chunkIndex frontend.Variable, plaintext, ciphertext []frontend.Variable) {

	inputSize := len(plaintext)
	numberBlocks := int(inputSize / 16)
	var epoch int
	for epoch = 0; epoch < numberBlocks; epoch++ {

		idx := aes.api.Add(chunkIndex, frontend.Variable(epoch))
		eIndex := epoch * 16

		var ptBlock [16]frontend.Variable
		var ctBlock [16]frontend.Variable

		for j := 0; j < 16; j++ {
			ptBlock[j] = plaintext[eIndex+j]
			ctBlock[j] = ciphertext[eIndex+j]
		}

		ivCounter := aes.GetIV(iv, idx)
		intermediate := aes.Encrypt(key, ivCounter)
		ct := aes.Xor16(intermediate, ptBlock)

		// check ciphertext to plaintext constraints
		for i := 0; i < 16; i++ {
			aes.api.AssertIsEqual(ctBlock[i], ct[i])
		}
	}
}

// required for aes_gcm
func (aes *AES128) GetIV(nonce [12]frontend.Variable, ctr frontend.Variable) [16]frontend.Variable {

	var out [16]frontend.Variable
	var i int
	for i = 0; i < len(nonce); i++ {
		out[i] = nonce[i]
	}
	bits := aes.api.ToBinary(ctr, 32)
	remain := 12
	for j := 3; j >= 0; j-- {
		start := 8 * j
		// little endian order chunk parsing from back to front
		out[remain] = aes.api.FromBinary(bits[start : start+8]...)
		remain += 1
	}

	return out
}

// required for plaintext xor encrypted counter blocks
func (aes *AES128) Xor16(a [16]frontend.Variable, b [16]frontend.Variable) [16]frontend.Variable {

	var out [16]frontend.Variable
	for i := 0; i < 16; i++ {
		out[i] = aes.variableXor(a[i], b[i], 8)
	}
	return out
}
