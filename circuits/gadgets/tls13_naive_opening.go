package gadgets

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type naiveOpenWrapper struct {
	InMap      [][32]frontend.Variable
	Plaintext  []frontend.Variable
	Ciphertext []frontend.Variable `gnark:",public"`
	Hash       frontend.Variable   `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *naiveOpenWrapper) Define(api frontend.API) error {

	// init mimc
	mimc, _ := mimc.NewMiMC(api)

	// init ciphertext prime
	cipherPrime := make([]frontend.Variable, len(circuit.Plaintext))

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
	}

	// mimc hash constraints check
	result := mimc.Sum()
	api.AssertIsEqual(circuit.Hash, result)

	// check ciphertextPrime against public input ciphertext
	for i := 0; i < len(circuit.Plaintext); i++ {
		api.AssertIsEqual(cipherPrime[i], circuit.Ciphertext[i])
	}

	return nil
}
