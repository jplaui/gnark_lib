/*
MIT License

Copyright (c) Jan Lauinger, 2023 zkCollective, Celer Network

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package gadgets

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestSha256All(t *testing.T) {
	assert := test.NewAssert(t)

	input := "68656c6c6f20776f726c64"
	output := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	// 'hello-world-hello-world-hello-world-hello-world-hello-world-12345' as hex
	// input := "68656c6c6f2d776f726c642d68656c6c6f2d776f726c642d68656c6c6f2d776f726c642d68656c6c6f2d776f726c642d68656c6c6f2d776f726c642d3132333435"
	// output := "34caf9dcd6b137c56c59f81e071a4b77a11329f26c80d7023ac7dfc485dcd780"

	byteSlice, _ := hex.DecodeString(input)
	inputByteLen := len(byteSlice)

	byteSlice, _ = hex.DecodeString(output)
	outputByteLen := len(byteSlice)

	// witness definition
	preImageAssign := StrToIntSlice(input, true)
	outputAssign := StrToIntSlice(output, true)

	// witness values preparation
	//assignment := Sha256Circuit{
	//	PreImage:       make([]frontend.Variable, inputByteLen),
	//	ExpectedResult: [32]frontend.Variable{},
	//}

	assignment := Sha256Circuit{
		In:             make([]frontend.Variable, inputByteLen),
		ExpectedResult: [32]frontend.Variable{},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < inputByteLen; i++ {
		assignment.In[i] = preImageAssign[i]
	}
	for i := 0; i < outputByteLen; i++ {
		assignment.ExpectedResult[i] = outputAssign[i]
	}

	circuit := Sha256Circuit{
		In: make([]frontend.Variable, inputByteLen),
	}

	// Currently, this version of SHA256 only works with groth16
	assert.SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16))
}
