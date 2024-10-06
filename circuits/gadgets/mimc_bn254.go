package gadgets

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type MimcWrapper struct {
	In   []frontend.Variable
	Hash frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *MimcWrapper) Define(api frontend.API) error {
	// hash function
	mimc, _ := mimc.NewMiMC(api)

	// for i := 0; i < len(circuit.In); i++ {
	// 	mimc.Write(circuit.In[i])
	// }
	mimc.Write(circuit.In[:]...)

	result := mimc.Sum()
	api.AssertIsEqual(circuit.Hash, result)

	return nil
}
