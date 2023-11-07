package gadgets

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MerkleProofCircuit struct {
	M    MerkleTree
	Leaf frontend.Variable
}

func (mp *MerkleProofCircuit) Define(api frontend.API) error {

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mp.M.VerifyProof(api, &h, mp.Leaf)

	return nil
}
