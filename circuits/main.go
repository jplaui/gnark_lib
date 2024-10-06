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

package main

import (
	g "circuits/gadgets"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"flag"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type shaData struct {
	in   string
	hash string
}

type gcmData struct {
	key        string
	chunkIndex int
	iv         string
	plaintext  string
	ciphertext string
}

type xorData struct {
	in   string
	mask string
	out  string
}

func main() {

	// logging settings
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// checks logging flag if program is called as ./main.go -debug
	debug := flag.Bool("debug", false, "sets log level to debug")

	// checks for -tls13-key-commit flag
	session_commit := flag.Bool("tls13-session-commit", false, "tls13 session commitment proof")

	// checks for -tls13-commit-data flag
	session_data := flag.Bool("tls13-session-data", false, "tls13 session data proof against existing session commitment")

	// checks for -tls13-key-data flag
	kdc_oracle := flag.Bool("tls13-oracle", false, "tls13 kdc and data proof")

	// checks for -evaluate-constraints flag
	// evalutes most of the functions, used for quick testing
	eval_constraints := flag.Bool("evaluate-constraints", false, "evaluates all circuits with different backends. use the backend flag to specify the backend")

	// individual evaluation flags
	shacal2_circuit := flag.Bool("shacal2", false, "evaluates shacal2 circuit")

	// individual evaluation flags
	sha256_circuit := flag.Bool("sha256", false, "evaluates sha256 circuit")

	// individual evaluation flags
	mimc_circuit := flag.Bool("mimc", false, "evaluates mimc circuit")

	// individual evaluation flags
	aes128_circuit := flag.Bool("aes128", false, "evaluates aes128 circuit")

	// individual evaluation flags
	authtag_circuit := flag.Bool("authtag", false, "evaluates authtag circuit")

	// individual evaluation flags
	gcm_circuit := flag.Bool("gcm", false, "evaluates gcm circuit")

	// individual evaluation flags
	kdc_circuit := flag.Bool("kdc", false, "evaluates kdc circuit")

	// individual evaluation flags
	record_circuit := flag.Bool("record", false, "evaluates record circuit")

	// individual evaluation flags
	xor_circuit := flag.Bool("xor", false, "evaluates xor circuit")

	// individual evaluation flags
	substring_circuit := flag.Bool("substring", false, "evaluates substring circuit")

	// individual evaluation flags
	str2int_circuit := flag.Bool("str2int", false, "evaluates str2int circuit")

	// individual evaluation flags
	gtlt_circuit := flag.Bool("gtlt", false, "evaluates gtlt circuit")

	// checks for -evaluate-constraints flag
	iterations := flag.Int("iterations", 0, "indicates the iterations of the same evaluation")

	// size of data in bytes to generate and evaluate in circuit (applies only to circuits with dynamic input, e.g. gcm, sha256)
	byte_size := flag.Int("byte-size", 0, "indicates size of bytes to evaluate in circuit. applies only to circuits with dynamic input (e.g. gcm, sha256). byte-size mod 16 must be zero")

	// indicate proof system
	ps := flag.String("backend", "groth16", "switch between groth16, plonk, and plonkFRI proof backends. default: groth16.")

	// indicate if circuit should be compiled only
	compile := flag.Bool("compile", false, "returns program after circuit compilation, no timing data is captured.")

	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// verify byte size
	if *byte_size%16 != 0 {
		log.Error().Msg("byte_size must be divisible by 16, e.g. byte_size=64 works.")
	}

	// activated check
	log.Debug().Msg("Debugging activated.")

	// session commit derivation: kdc + authtag + key commit
	if *session_commit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateSessionCommit(*ps, *compile)
			if err != nil {
				log.Error().Msg("g.EvaluateSessionCommit()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "sessioncommit_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// session data proof: key commit + record
	if *session_data {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateSessionData(*ps, *compile)
			if err != nil {
				log.Error().Msg("g.EvaluateSessionData()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "sessiondata_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// full circuit, kdc + authtag + record
	if *kdc_oracle {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateOracle(*ps, *compile)
			if err != nil {
				log.Error().Msg("g.EvaluateOracle()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "oracle_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// shacal2 evaluation
	if *shacal2_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateShacal2(*ps, *compile)
			if err != nil {
				log.Error().Msg("g.EvaluateShacal2()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "shacal2_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// mimc evaluation
	if *mimc_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		// generate data for evaluation
		curve := ecc.BN254
		modulus := curve.ScalarField()
		size := *byte_size / 32
		// size limit= 19360,
		// this number is divisible by 32 (19360/32=605) and size=19359 still works
		// so possible to hash 16 kb in mimc, takes 1.06s to prove
		if size%32 == 0 {
			size += 1
		}
		hashInput := make([]big.Int, size)
		hashInput[0].Sub(modulus, big.NewInt(1))
		for i := 1; i < size; i++ {
			hashInput[i].Add(&hashInput[i-1], &hashInput[i-1]).Mod(&hashInput[i], modulus)
		}

		// byteArray := make([]byte, *byte_size)
		// in := hex.EncodeToString(byteArray)
		// running MiMC (Go)
		hashFunc := hash.MIMC_BN254
		goMimc := hashFunc.New()
		for i := 0; i < size; i++ {
			goMimc.Write(hashInput[i].Bytes())
		}
		// for i := 0; i < 10; i++ {
		// }
		expectedh := goMimc.Sum(nil)
		// hash := hex.EncodeToString(expectedh)

		// fmt.Println("mimc hash:", hash)
		// fmt.Println("mimc input:", in)

		// h := sha256.New()
		// h.Write(byteArray)
		// sum := h.Sum(nil)

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateMimc(*ps, *compile, hashInput, expectedh)
			if err != nil {
				log.Error().Msg("e.EvaluateMimc()")
			}
			s = append(s, data)
		}
		if *compile {
			return
		}
		g.AddStats(data, s, false)
		filename := "mimc_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// sha256 evaluation
	if *sha256_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		// generate data for evaluation
		byteArray := make([]byte, *byte_size)
		in := hex.EncodeToString(byteArray)
		h := sha256.New()
		h.Write(byteArray)
		sum := h.Sum(nil)
		hash := hex.EncodeToString(sum)

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateSha256(*ps, *compile, in, hash)
			if err != nil {
				log.Error().Msg("e.EvaluateSha256()")
			}
			s = append(s, data)
		}
		if *compile {
			return
		}
		g.AddStats(data, s, false)
		filename := "sha256_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// aes128 evaluation
	if *aes128_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateAES128(*ps, *compile)
			if err != nil {
				log.Error().Msg("e.EvaluateAES128()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "aes128_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// authtag evaluation
	if *authtag_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateAuthTag(*ps, *compile)
			if err != nil {
				log.Error().Msg("e.EvaluateAuthTag()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "authtag_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// gcm evaluation
	if *gcm_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		// generate data, encrypting zeros
		key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")
		plaintext := make([]byte, *byte_size)
		ivBytes, _ := hex.DecodeString("54cc7dc2c37ec006bcc6d1da")

		block, _ := aes.NewCipher(key)
		nonce := ivBytes
		aesgcm, _ := cipher.NewGCM(block)
		ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)[:*byte_size]

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateGCM(*ps, *compile, hex.EncodeToString(key), 2, hex.EncodeToString(nonce), hex.EncodeToString(plaintext), hex.EncodeToString(ciphertext))
			if err != nil {
				log.Error().Msg("g.EvaluateGCM()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, true)
		filename := "gcm_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// kdc evaluation
	if *kdc_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateKdc(*ps, *compile)
			if err != nil {
				log.Error().Msg("g.EvaluateKdc()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "kdc_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// record evaluation
	if *record_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateRecord(*ps, *compile)
			if err != nil {
				log.Error().Msg("e.EvaluateRecord()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}
		g.AddStats(data, s, false)
		filename := "record_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// xor evaluation
	if *xor_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		// generate data
		// a, b := []byte("Hello"), []byte("world")
		a := make([]byte, *byte_size)
		b := make([]byte, *byte_size)
		// randomize b bytes
		rand.Read(b)
		in := hex.EncodeToString(a)
		mask := hex.EncodeToString(b)
		c := make([]byte, len(a))
		for i := range a {
			c[i] = a[i] ^ b[i]
		}
		out := hex.EncodeToString(c)

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateXor(*ps, *compile, in, mask, out)
			if err != nil {
				log.Error().Msg("g.EvaluateXor()")
			}
			s = append(s, data)
		}
		// return if only interested in circuit constraints
		if *compile {
			return
		}
		g.AddStats(data, s, false)
		filename := "xor_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// substring evaluation
	if *substring_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateSubstring(*ps, *compile)
			if err != nil {
				log.Error().Msg("e.EvaluateSubstring()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "substring_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// str2int evaluation
	if *str2int_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateStr2Int(*ps, *compile)
			if err != nil {
				log.Error().Msg("e.EvaluateStr2Int()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "str2int_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// gtlt evaluation
	if *gtlt_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(*iterations)
		data["backend"] = *ps
		if *byte_size != 0 {
			data["data_size"] = strconv.Itoa(*byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := *iterations; i > 0; i-- {
			data, err := g.EvaluateGTLT(*ps, *compile)
			if err != nil {
				log.Error().Msg("g.EvaluateGTLT()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if *compile {
			return
		}

		g.AddStats(data, s, false)
		filename := "gtlt_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		g.StoreM(data, "./jsons/", filename)
	}

	// evaluation of constraints
	if *eval_constraints {

		// shacal not needed, first evaluation of sha256 calls shacal2 once
		_, err := g.EvaluateShacal2(*ps, *compile)
		if err != nil {
			log.Error().Msg("e.EvaluateShacal2()")
		}

		// sha256 test data
		shaDataList := []shaData{
			{
				// test data for one shacal2 execution
				// 32 byte input
				in:   "fb31a8b3a6855ec77e52bdda3e3438ae2b0b9b24762f0cff4b4f8c90c4061027",
				hash: "701f1e212d0661705287ff57f11990411496496b6fc096359aef1a47a4319794",
			},
			{
				// hash on 64 byte input
				in:   "df7675e9961cf944d4ebe6cb419f847db9390914614c540461e5628abcfcd048df7675e9961cf944d4ebe6cb419f847db9390914614c540461e5628abcfcd048",
				hash: "fb31a8b3a6855ec77e52bdda3e3438ae2b0b9b24762f0cff4b4f8c90c4061027",
			},
			{
				// hash on 128 byte input
				in:   "df7675e9961cf944d4ebe6cb419f847db9390914614c540461e5628abcfcd048df7675e9961cf944d4ebe6cb419f847db9390914614c540461e5628abcfcd048df7675e9961cf944d4ebe6cb419f847db9390914614c540461e5628abcfcd048df7675e9961cf944d4ebe6cb419f847db9390914614c540461e5628abcfcd048",
				hash: "eabbf08bb393c6354aa2cd830ee97ecc2f62b991b5997b44ed4d42d48a0c478d",
			},
		}
		for _, shaData := range shaDataList {
			_, err := g.EvaluateSha256(*ps, *compile, shaData.in, shaData.hash)
			if err != nil {
				log.Error().Msg("e.EvaluateSha256()")
			}
		}

		// aes128
		_, err = g.EvaluateAES128(*ps, *compile)
		if err != nil {
			log.Error().Msg("e.EvaluateAES128()")
		}

		// authtag evaluation
		_, err = g.EvaluateAuthTag(*ps, *compile)
		if err != nil {
			log.Error().Msg("e.EvaluateAuthTag()")
		}

		// aes gcm test data
		gcmDataList := []gcmData{
			{
				iv:         "54cc7dc2c37ec006bcc6d1da",
				chunkIndex: 2,
				key:        "ab72c77b97cb5fe9a382d9fe81ffdbed",
				plaintext:  "007c5e5b3e59df24a7c355584fc1518d",
				ciphertext: "0e1bde206a07a9c2c1b65300f8c64997",
			},
			{
				key:        "fe47fcce5fc32665d2ae399e4eec72ba",
				chunkIndex: 2,
				iv:         "5adb9609dbaeb58cbd6e7275",
				plaintext:  "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429",
				ciphertext: "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269", // authtag=f5f6e7d0b3d0418b82296ac7dd951d0e

			},
		}
		for _, gcmData := range gcmDataList {
			_, err := g.EvaluateGCM(*ps, *compile, gcmData.key, gcmData.chunkIndex, gcmData.iv, gcmData.plaintext, gcmData.ciphertext)
			if err != nil {
				log.Error().Msg("g.EvaluateGCM()")
			}
		}

		// kdc evaluation
		_, err = g.EvaluateKdc(*ps, *compile)
		if err != nil {
			log.Error().Msg("g.EvaluateKdc()")
		}

		// evaluate record
		_, err = g.EvaluateRecord(*ps, *compile)
		if err != nil {
			log.Error().Msg("e.EvaluateRecord()")
		}

		// evaluate xor
		xorDataList := []xorData{
			{
				in:   "ab72c77b97cb5fe9a382d9fe81ffdbed",
				mask: "fe47fcce5fc32665d2ae399e4eec72ba",
				out:  "55353bb5c808798c712ce060cf13a957",
			},
		}
		for _, xorData := range xorDataList {
			_, err = g.EvaluateXor(*ps, *compile, xorData.in, xorData.mask, xorData.out)
			if err != nil {
				log.Error().Msg("g.EvaluateXor()")
			}
		}

		// evaluate substring
		// can also be used to prove value equality without having to convert numbers
		_, err = g.EvaluateSubstring(*ps, *compile)
		if err != nil {
			log.Error().Msg("g.EvaluateSubstring()")
		}

		// evaluate str2int
		_, err = g.EvaluateStr2Int(*ps, *compile)
		if err != nil {
			log.Error().Msg("g.EvaluateStr2Int()")
		}

		// evaluate greater than / less than
		_, err = g.EvaluateGTLT(*ps, *compile)
		if err != nil {
			log.Error().Msg("g.EvaluateGTLT()")
		}
	}
}
