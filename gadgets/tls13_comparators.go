package gadgets

import "github.com/consensys/gnark/frontend"

// substring evaluation
type SubstringWrapper struct {
	PlainChunks    []frontend.Variable
	Substring      []frontend.Variable `gnark:",public"`
	SubstringStart int                 `gnark:",public"`
	SubstringEnd   int                 `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *SubstringWrapper) Define(api frontend.API) error {

	extractedSubstring := circuit.PlainChunks[circuit.SubstringStart:circuit.SubstringEnd]
	SubstringMatch(api, circuit.Substring, extractedSubstring, 0, len(circuit.Substring))

	return nil
}

// gnark substringmatch circuit
func SubstringMatch(api frontend.API, substring, totalString []frontend.Variable, from, to int) {
	for i := 0; i < len(substring); i++ {
		api.AssertIsEqual(substring[i], totalString[i])
	}
}

// gt/ lt evaluation
type GTLTWrapper struct {
	Threshold frontend.Variable
	Value     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *GTLTWrapper) Define(api frontend.API) error {

	GreaterThan(api, circuit.Value, circuit.Threshold)

	return nil
}

// it must hold v1 > v2 for GreaterThan to succeed
// fails if v2 > v1
// valueInteger > circuit.Threshold
func GreaterThan(api frontend.API, v1, v2 frontend.Variable) {
	api.AssertIsLessOrEqual(v2, v1)
}
