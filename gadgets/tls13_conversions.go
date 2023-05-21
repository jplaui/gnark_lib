package gadgets

import (
	"math"

	"github.com/consensys/gnark/frontend"
)

// str 2 int evaluation
type Str2IntWrapper struct {
	PlainChunks []frontend.Variable
	Value       frontend.Variable `gnark:",public"`
	ValueStart  int               `gnark:",public"`
	ValueEnd    int               `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *Str2IntWrapper) Define(api frontend.API) error {

	valueString := circuit.PlainChunks[circuit.ValueStart:circuit.ValueEnd]
	valueInteger := StringToInt(api, valueString)

	api.AssertIsEqual(valueInteger, circuit.Value)

	return nil
}

// gnark string to integer conversion
func StringToInt(api frontend.API, valueString []frontend.Variable) frontend.Variable {
	// aggregation number
	sum := frontend.Variable(0)
	// loop from back to front
	for i := len(valueString); i > 0; i-- {
		idx := len(valueString) - i

		// expanded dezimal such that shift can be applied
		// 4 bits cover numbers 0-9, little endian result, IMPORTANT: 8 required, otherwise unsatisfied constraint error
		toInt := api.Sub(api.FromBinary(api.ToBinary(valueString[i-1], 8)...), 48)
		sum = api.MulAcc(sum, toInt, int(math.Pow(float64(10), float64(idx))))
	}
	return sum
}
