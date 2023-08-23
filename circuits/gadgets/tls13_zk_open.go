package gadgets

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type zkOpenWrapper struct {
	InMap  [][32]frontend.Variable
	Mask   [16]frontend.Variable
	Parity [16]frontend.Variable `gnark:",public"`
	Hash   frontend.Variable     `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *zkOpenWrapper) Define(api frontend.API) error {

	// init mimc
	mimc, _ := mimc.NewMiMC(api)

	// init parity sum
	parity1 := make([]frontend.Variable, 128)
	for i := 0; i < 128; i++ {
		parity1[i] = 0
	}

	// loop over bytes
	for i := 0; i < len(circuit.InMap); i++ {

		// rearrange input to match mimc input requirements
		ddd := make([]frontend.Variable, 256)
		for j := 0; j < 32; j++ {
			myBits := api.ToBinary(circuit.InMap[i][j], 8)
			for k := 7; k >= 0; k-- {
				ddd[(31-j)*8+(k)] = myBits[k]
			}
		}

		// input data into mimc
		varSum := api.FromBinary(ddd...)
		mimc.Write(varSum)
		// api.Println("inner bits", ddd)
		// api.Println("varSum", varSum)
		// api.Println("inSum", circuit.In[i])

		// compute parity
		for j := 0; j < 128; j++ {
			parity1[j] = api.Xor(parity1[j], ddd[j])
		}
		for j := 128; j < 256; j++ {
			parity1[j-128] = api.Xor(parity1[j-128], ddd[j])
		}
	}

	// mimc hash constraints check
	result := mimc.Sum()
	api.AssertIsEqual(circuit.Hash, result)

	// parity check
	for i := 0; i < 16; i++ {

		// add mask
		maskBits := api.ToBinary(circuit.Mask[15-i])
		for j := 0; j < 8; j++ {
			parity1[(i*8)+j] = api.Xor(parity1[(i*8)+j], maskBits[j])
		}

		// compare parity checksum
		bits := make([]frontend.Variable, 8)
		for j := 0; j < 8; j++ {
			idx := (i * 8) + j
			bits[j] = parity1[idx]
		}
		parityByte := api.FromBinary(bits...)
		api.AssertIsEqual(circuit.Parity[15-i], parityByte)
	}

	return nil
}
