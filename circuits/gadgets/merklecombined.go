package gadgets

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MerkleCombined struct {
	Input     frontend.Variable
	Threshold frontend.Variable `gnark:",public"`
	Digest    frontend.Variable `gnark:",public"`

	RootHash frontend.Variable `gnark:",public"`
	Path     []frontend.Variable
	Leaf     frontend.Variable
	Depth    int
}

func (mp *MerkleCombined) Define(api frontend.API) error {

	// compare input to threshold
	api.AssertIsLessOrEqual(mp.Threshold, mp.Input)

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(mp.Input)
	sum := h.Sum()
	api.AssertIsEqual(mp.Digest, sum)

	// build merkle tree from input
	var merkleCirc MerkleProofCircuit
	merkleCirc.Leaf = mp.Leaf
	merkleCirc.M.RootHash = mp.RootHash
	merkleCirc.M.Path = make([]frontend.Variable, mp.Depth+1)
	for i := 0; i < mp.Depth+1; i++ {
		merkleCirc.M.Path[i] = mp.Path[i]
	}
	return merkleCirc.Define(api)

}
