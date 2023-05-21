package gadgets

import "github.com/consensys/gnark/frontend"

// xor evaluation
type XorWrapper struct {
	In   []frontend.Variable
	Mask []frontend.Variable
	Out  []frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *XorWrapper) Define(api frontend.API) error {

	out := make([]frontend.Variable, len(circuit.In))
	for i := 0; i < len(circuit.In); i++ {
		bitsA := api.ToBinary(circuit.In[i], 8)
		bitsB := api.ToBinary(circuit.Mask[i], 8)
		x := make([]frontend.Variable, 8)
		for i := 0; i < 8; i++ {
			x[i] = api.Xor(bitsA[i], bitsB[i])
		}
		out[i] = api.FromBinary(x...)
	}

	for i := 0; i < len(circuit.In); i++ {
		api.AssertIsEqual(out[i], circuit.Out[i])
	}

	return nil
}
