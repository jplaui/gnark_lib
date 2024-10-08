package gadgets

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Sha2Wrapper struct {
	In       []uints.U8
	Expected [32]uints.U8 `gnark:",public"`
}

// Define declares the circuit's constraints
func (c *Sha2Wrapper) Define(api frontend.API) error {

	h, err := NewSha2(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}
