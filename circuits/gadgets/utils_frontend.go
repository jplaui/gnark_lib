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

// this function expects encoding of 2hex/1byte per frontend.Variable
func ZeroPadding(api frontend.API, key []frontend.Variable) [64]frontend.Variable {
	var paddedKey [64]frontend.Variable
	keyLen := len(key)
	paddingLen := 64 - keyLen
	var i int
	for i = 0; i < keyLen; i++ {
		paddedKey[i] = key[i]
	}
	for ; i < keyLen+paddingLen; i++ {
		paddedKey[i] = frontend.Variable(0)
	}
	return paddedKey
}

// inp1 xor opad and concatenates with inp2
func OpadConcat(api frontend.API, inp1 [32]frontend.Variable, inp2 [32]frontend.Variable) []frontend.Variable {
	var i int
	var paddedKey [64]frontend.Variable
	for i = 0; i < 32; i++ {
		paddedKey[i] = inp1[i]
	}
	for ; i < 32+32; i++ {
		paddedKey[i] = frontend.Variable(0)
	}
	// xor opad
	dHSopadConcatMSin := make([]frontend.Variable, 64+32)
	for i = 0; i < 64; i++ {
		dHSopadConcatMSin[i] = VariableXor(api, paddedKey[i], frontend.Variable(0x5c), 8)
	}
	// concatenate
	for ; i < 64+32; i++ {
		dHSopadConcatMSin[i] = inp2[i-64]
	}
	return dHSopadConcatMSin
}

// adjustable bitwise xor operation on frontend.Variables
func VariableXor(api frontend.API, a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := api.ToBinary(a, size)
	bitsB := api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = api.Xor(bitsA[i], bitsB[i])
	}
	return api.FromBinary(x...)
}

// gnark zero padding
func ZeroPadOpad(api frontend.API, inp [32]frontend.Variable) [64]frontend.Variable {
	var i int
	var padOpadKey [64]frontend.Variable
	for i = 0; i < 32; i++ {
		padOpadKey[i] = inp[i]
	}
	for ; i < 64; i++ {
		padOpadKey[i] = 0
	}
	var res [64]frontend.Variable
	for i := 0; i < 64; i++ {
		res[i] = VariableXor(api, padOpadKey[i], frontend.Variable(0x5c), 8)
	}
	return res
}
