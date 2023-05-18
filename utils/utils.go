/*
Copyright 2023 Jan Lauinger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/montanaflynn/stats"
	"github.com/rs/zerolog/log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/plonkfri"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

// gnark substringmatch circuit
func SubstringMatch(api frontend.API, substring, totalString []frontend.Variable, from, to int) {
	for i := 0; i < len(substring); i++ {
		api.AssertIsEqual(substring[i], totalString[i])
	}
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

// it must hold v1 > v2 for GreaterThan to succeed
// fails if v2 > v1
// valueInteger > circuit.Threshold
func GreaterThan(api frontend.API, v1, v2 frontend.Variable) {
	api.AssertIsLessOrEqual(v2, v1)
}

// this function expects encoding of 2hex/1byte per frontend.Variable
func ZeroPadding(api frontend.API, key []frontend.Variable) [64]frontend.Variable {
	var paddedKey [64]frontend.Variable
	keyLen := len(key)
	paddingLen := 64 - keyLen
	var i int
	for i = 0; i < keyLen; i++ {
		paddedKey[i] = key[i]
	}
	for ; i < keyLen+paddingLen; i++ {
		paddedKey[i] = frontend.Variable(0)
	}
	return paddedKey
}

// inp1 xor opad and concatenates with inp2
func OpadConcat(api frontend.API, inp1 [32]frontend.Variable, inp2 [32]frontend.Variable) []frontend.Variable {
	var i int
	var paddedKey [64]frontend.Variable
	for i = 0; i < 32; i++ {
		paddedKey[i] = inp1[i]
	}
	for ; i < 32+32; i++ {
		paddedKey[i] = frontend.Variable(0)
	}
	// xor opad
	dHSopadConcatMSin := make([]frontend.Variable, 64+32)
	for i = 0; i < 64; i++ {
		dHSopadConcatMSin[i] = VariableXor(api, paddedKey[i], frontend.Variable(0x5c), 8)
	}
	// concatenate
	for ; i < 64+32; i++ {
		dHSopadConcatMSin[i] = inp2[i-64]
	}
	return dHSopadConcatMSin
}

// adjustable bitwise xor operation on frontend.Variables
func VariableXor(api frontend.API, a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := api.ToBinary(a, size)
	bitsB := api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = api.Xor(bitsA[i], bitsB[i])
	}
	return api.FromBinary(x...)
}

// non-gnark padding function
func PadSha256(len uint64) []byte {
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	binary.BigEndian.PutUint64(padlen[t+0:], len)
	return padlen
}

// gnark zero padding
func ZeroPadOpad(api frontend.API, inp [32]frontend.Variable) [64]frontend.Variable {
	var i int
	var padOpadKey [64]frontend.Variable
	for i = 0; i < 32; i++ {
		padOpadKey[i] = inp[i]
	}
	for ; i < 64; i++ {
		padOpadKey[i] = 0
	}
	var res [64]frontend.Variable
	for i := 0; i < 64; i++ {
		res[i] = VariableXor(api, padOpadKey[i], frontend.Variable(0x5c), 8)
	}
	return res
}

// non-gnark str to int conversion
func StrToIntSlice(inputData string, hexRepresentation bool) []int {

	// check if inputData in hex representation
	var byteSlice []byte
	if hexRepresentation {
		hexBytes, err := hex.DecodeString(inputData)
		if err != nil {
			log.Error().Msg("hex.DecodeString error.")
		}
		byteSlice = hexBytes
	} else {
		byteSlice = []byte(inputData)
	}

	// convert byte slice to int numbers which can be passed to gnark frontend.Variable
	var data []int
	for i := 0; i < len(byteSlice); i++ {
		data = append(data, int(byteSlice[i]))
	}

	return data
}

// non-gnark zk system evalaution functions
func ProofWithBackend(backend string, compile bool, circuit frontend.Circuit, assignment frontend.Circuit, curveID ecc.ID) (map[string]time.Duration, error) {

	// time measures
	data := map[string]time.Duration{}

	// generate witness
	witness, err := frontend.NewWitness(assignment, curveID.ScalarField())
	if err != nil {
		log.Error().Msg("frontend.NewWitness")
		return nil, err
	}

	// init builders
	var builder frontend.NewBuilder
	var srs kzg.SRS
	switch backend {
	case "groth16":
		builder = r1cs.NewBuilder
	case "plonk":
		builder = scs.NewBuilder
	case "plonkFRI":
		builder = scs.NewBuilder
	}

	// generate CompiledConstraintSystem
	start := time.Now()
	ccs, err := frontend.Compile(curveID.ScalarField(), builder, circuit)
	if err != nil {
		log.Error().Msg("frontend.Compile")
		return nil, err
	}
	elapsed := time.Since(start)
	log.Debug().Str("elapsed", elapsed.String()).Msg("compile constraint system time.")

	data["compile"] = elapsed

	// kzg setup if using plonk
	if backend == "plonk" {
		srs, err = test.NewKZGSRS(ccs)
		if err != nil {
			log.Error().Msg("test.NewKZGSRS(ccs)")
			return nil, err
		}

		elapsed := time.Since(start)
		data["compile"] = elapsed
	}

	if compile {
		return nil, err
	}

	// proof system execution
	switch backend {
	case "groth16":

		// setup
		start = time.Now()
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			log.Error().Msg("groth16.Setup")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("groth16.Setup time.")

		data["setup"] = elapsed

		// prove
		start = time.Now()
		proof, err := groth16.Prove(ccs, pk, witness)
		if err != nil {
			log.Error().Msg("groth16.Prove")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("groth16.Prove time.")

		data["prove"] = elapsed

		// generate public witness
		publicWitness, _ := witness.Public()

		// verification
		start = time.Now()
		err = groth16.Verify(proof, vk, publicWitness)
		if err != nil {
			log.Error().Msg("groth16.Verify")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("groth16.Verify time.")

		data["verify"] = elapsed

	case "plonk":

		// setup
		start = time.Now()
		pk, vk, err := plonk.Setup(ccs, srs)
		if err != nil {
			log.Error().Msg("plonk.Setup")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("plonk.Setup time.")

		data["setup"] = elapsed

		// prove
		start = time.Now()
		proof, err := plonk.Prove(ccs, pk, witness)
		if err != nil {
			log.Error().Msg("plonk.Prove")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("plonk.Prove time.")

		data["prove"] = elapsed

		// generate public witness
		publicWitness, _ := witness.Public()

		// verify
		start = time.Now()
		err = plonk.Verify(proof, vk, publicWitness)
		if err != nil {
			log.Error().Msg("plonk.Verify")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("plonk.Verify time.")

		data["verify"] = elapsed

	case "plonkFRI":

		// setup
		start = time.Now()
		pk, vk, err := plonkfri.Setup(ccs)
		if err != nil {
			log.Error().Msg("plonkfri.Setup")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("plonkfri.Setup time.")

		data["setup"] = elapsed

		// prove
		start = time.Now()
		correctProof, err := plonkfri.Prove(ccs, pk, witness)
		if err != nil {
			log.Error().Msg("plonkfri.Prove")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("plonkfri.Prove time.")

		data["prove"] = elapsed

		// generate public witness
		publicWitness, _ := witness.Public()

		// verify
		start = time.Now()
		err = plonkfri.Verify(correctProof, vk, publicWitness)
		if err != nil {
			log.Error().Msg("plonkfri.Verify")
			return nil, err
		}
		elapsed = time.Since(start)
		log.Debug().Str("elapsed", elapsed.String()).Msg("plonkfri.Verify time.")

		data["verify"] = elapsed
	}

	return data, nil
}

func StoreM(jsonData map[string]string, path string, filename string) error {

	file, err := json.MarshalIndent(jsonData, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}
	err = os.WriteFile(path+filename+".json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("os.WriteFile")
		return err
	}
	return nil
}

func AddStats(data map[string]string, results []map[string]time.Duration, print2console bool) {

	// default type expected by github.com/montanaflynn/stats package
	aggrCompile := []float64{}
	aggrSetup := []float64{}
	aggrProve := []float64{}
	aggrVerify := []float64{}
	// aggregate times
	for _, mapData := range results {
		// convert all numbers to seconds as the base, take time.Milisecond if ms required
		aggrCompile = append(aggrCompile, float64(mapData["compile"].Seconds()))
		aggrSetup = append(aggrSetup, float64(mapData["setup"].Seconds()))
		aggrProve = append(aggrProve, float64(mapData["prove"].Seconds()))
		aggrVerify = append(aggrVerify, float64(mapData["verify"].Seconds()))
	}

	// check print to console
	if print2console {
		fmt.Println("compile times:", aggrCompile)
		fmt.Println("setup times:", aggrSetup)
		fmt.Println("prove times:", aggrProve)
		fmt.Println("verify times:", aggrVerify)
	}

	// adding stats
	// statistics api here https://pkg.go.dev/github.com/montanaflynn/stats#section-readme
	// float conversion options here https://yourbasic.org/golang/convert-string-to-float/
	// med, _ := stats.Median(aggrCompile)
	mean, _ := stats.Mean(aggrCompile)
	std, _ := stats.StandardDeviation(aggrCompile)
	// data["time_compile_median"] = fmt.Sprintf("%.3f", med)
	data["time_compile_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_compile_standard_deviation"] = fmt.Sprintf("%.3f", std)

	// med, _ = stats.Median(aggrSetup)
	mean, _ = stats.Mean(aggrSetup)
	std, _ = stats.StandardDeviation(aggrSetup)
	// data["time_setup_median"] = fmt.Sprintf("%.3f", med)
	data["time_setup_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_setup_standard_deviation"] = fmt.Sprintf("%.3f", std)

	// med, _ = stats.Median(aggrProve)
	mean, _ = stats.Mean(aggrProve)
	std, _ = stats.StandardDeviation(aggrProve)
	// data["time_prove_median"] = fmt.Sprintf("%.3f", med)
	data["time_prove_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_prove_standard_deviation"] = fmt.Sprintf("%.3f", std)

	// med, _ = stats.Median(aggrVerify)
	mean, _ = stats.Mean(aggrVerify)
	std, _ = stats.StandardDeviation(aggrVerify)
	// data["time_verify_median"] = fmt.Sprintf("%.3f", med)
	data["time_verify_mean"] = fmt.Sprintf("%.3f", mean)
	data["time_verify_standard_deviation"] = fmt.Sprintf("%.3f", std)
}
