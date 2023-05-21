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

package gadgets

import (
	"time"

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
