package gadgets

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type zkOpenWrapper2 struct {
	InMap      [][32]frontend.Variable
	DummyMask  frontend.Variable
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable   `gnark:",public"`
	Parity     [16]frontend.Variable `gnark:",public"`
	Hash       frontend.Variable     `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *zkOpenWrapper2) Define(api frontend.API) error {

	// init mimc
	mimc, _ := mimc.NewMiMC(api)

	// init parity sum
	parity1 := make([]frontend.Variable, 128)
	for i := 0; i < 128; i++ {
		parity1[i] = 0
	}

	// init ciphertext prime
	cipherPrime := make([]frontend.Variable, len(circuit.Plaintext))
	// for i := 0; i < len(circuit.Plaintext); i++ {
	// 	bitsA := api.ToBinary(circuit.In[i], 8)
	// 	bitsB := api.ToBinary(circuit.Mask[i], 8)
	// 	x := make([]frontend.Variable, 8)
	// 	for i := 0; i < 8; i++ {
	// 		x[i] = api.Xor(bitsA[i], bitsB[i])
	// 	}
	// 	out[i] = api.FromBinary(x...)
	// }

	// for i := 0; i < len(circuit.In); i++ {
	// 	api.AssertIsEqual(out[i], circuit.Out[i])
	// }

	dummyMaskBits := api.ToBinary(circuit.DummyMask, 128)

	// loop over bytes
	for i := 0; i < len(circuit.InMap); i++ {

		// rearrange input to match mimc input requirements
		ddd := make([]frontend.Variable, 256)
		for j := 0; j < 32; j++ {

			// get bits of ecb input, little endian!
			myBits := api.ToBinary(circuit.InMap[i][j], 8)

			bitsPlaintext := api.ToBinary(circuit.Plaintext[(i*32)+j], 8)
			x := make([]frontend.Variable, 8)
			for k := 7; k >= 0; k-- {
				ddd[(31-j)*8+(k)] = myBits[k]

				// xor ecb data with plaintext
				x[k] = api.Xor(bitsPlaintext[k], myBits[k])
			}

			cipherPrime[(i*32)+j] = api.FromBinary(x...)
			// api.Println(cipherPrime[(i*32)+j], circuit.Ciphertext[(i*32)+j])
		}

		// input data into mimc
		varSum := api.FromBinary(ddd...)
		mimc.Write(varSum)
		// api.Println("inner bits", ddd)
		// api.Println("varSum", varSum)
		// api.Println("inSum", circuit.In[i])

		// compute parity
		for j := 0; j < 128; j++ {
			// tmp := api.And(ddd[j])
			parity1[j] = api.Xor(parity1[j], api.And(ddd[j], dummyMaskBits[j]))
		}
		for j := 128; j < 256; j++ {
			parity1[j-128] = api.Xor(parity1[j-128], api.And(ddd[j], dummyMaskBits[j-128]))
		}
	}

	// mimc hash constraints check
	result := mimc.Sum()
	api.AssertIsEqual(circuit.Hash, result)

	// check ciphertextPrime against public input ciphertext
	for i := 0; i < len(circuit.Plaintext); i++ {
		api.AssertIsEqual(cipherPrime[i], circuit.Ciphertext[i])
	}

	// parity check
	for i := 0; i < 16; i++ {

		// add mask
		// maskBits := api.ToBinary(circuit.Mask[15-i])
		// for j := 0; j < 8; j++ {
		// 	parity1[(i*8)+j] = api.Xor(parity1[(i*8)+j], maskBits[j])
		// }

		// byte reconstruction
		bits := make([]frontend.Variable, 8)
		for j := 0; j < 8; j++ {
			idx := (i * 8) + j
			bits[j] = parity1[idx]
		}
		parityByte := api.FromBinary(bits...)
		// compare parity checksum
		api.AssertIsEqual(circuit.Parity[15-i], parityByte)
	}

	return nil
}
