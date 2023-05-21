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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// uint64api performs binary operations on xuint64 variables. In the
// future possibly using lookup tables.
//
// TODO: we could possibly optimise using hints if working over many inputs. For
// example, if we OR many bits, then the result is 0 if the sum of the bits is
// larger than 1. And AND is 1 if the sum of bits is the number of inputs. BUt
// this probably helps only if we have a lot of similar operations in a row
// (more than 4). We could probably unroll the whole permutation and expand all
// the formulas to see. But long term tables are still better.
type uint64api struct {
	api frontend.API
}

func newUint64API(api frontend.API) *uint64api {
	return &uint64api{
		api: api,
	}
}

// varUint64 represents 64-bit unsigned integer. We use this type to ensure that
// we work over constrained bits. Do not initialize directly, use [wideBinaryOpsApi.asUint64].
type xuint64 [64]frontend.Variable

func constUint64(a uint64) xuint64 {
	var res xuint64
	for i := 0; i < 64; i++ {
		res[i] = (a >> i) & 1
	}
	return res
}

func (w *uint64api) asUint64(in frontend.Variable) xuint64 {
	bits := bits.ToBinary(w.api, in, bits.WithNbDigits(64))
	var res xuint64
	copy(res[:], bits)
	return res
}

func (w *uint64api) fromUint64(in xuint64) frontend.Variable {
	return bits.FromBinary(w.api, in[:], bits.WithUnconstrainedInputs())
}

func (w *uint64api) and(in ...xuint64) xuint64 {
	var res xuint64
	for i := range res {
		res[i] = 1
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.And(res[i], v[i])
		}
	}
	return res
}

func (w *uint64api) xor(in ...xuint64) xuint64 {
	var res xuint64
	for i := range res {
		res[i] = 0
	}
	for i := range res {
		for _, v := range in {
			res[i] = w.api.Xor(res[i], v[i])
		}
	}
	return res
}

func (w *uint64api) lrot(in xuint64, shift int) xuint64 {
	var res xuint64
	for i := range res {
		res[i] = in[(i-shift+64)%64]
	}
	return res
}

func (w *uint64api) not(in xuint64) xuint64 {
	// TODO: it would be better to have separate method for it. If we have
	// native API support, then in R1CS would be free (1-X) and in PLONK 1
	// constraint (1-X). But if we do XOR, then we always have a constraint with
	// R1CS (not sure if 1-2 with PLONK). If we do 1-X ourselves, then compiler
	// marks as binary which is 1-2 (R1CS-PLONK).
	var res xuint64
	for i := range res {
		res[i] = w.api.Xor(in[i], 1)
	}
	return res
}

func (w *uint64api) assertEq(a, b xuint64) {
	for i := range a {
		w.api.AssertIsEqual(a[i], b[i])
	}
}

func (w *uint64api) rshift(in xuint64, shift int) xuint64 {
	var res xuint64
	for i := 0; i < 64-shift; i++ {
		res[i] = in[i+shift]
	}
	for i := 64 - shift; i < 64; i++ {
		res[i] = 0
	}
	return res
}

func (w *uint64api) lshift(in xuint64, shift int) xuint64 {
	var res xuint64
	for i := 0; i < shift; i++ {
		res[i] = 0
	}
	for i := shift; i < 64; i++ {
		res[i] = in[i-shift]
	}
	return res
}

func (in xuint64) toxUnit8() xuint8 {
	var res xuint8
	for i := 0; i < 8; i++ {
		res[i] = in[i]
	}
	return res
}
