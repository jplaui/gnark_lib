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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"flag"
	"strconv"
	"time"

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

var (
	debug             bool
	session_commit    bool
	session_data      bool
	kdc_oracle        bool
	eval_constraints  bool
	shacal2_circuit   bool
	sha256_circuit    bool
	aes128_circuit    bool
	authtag_circuit   bool
	gcm_circuit       bool
	kdc_circuit       bool
	record_circuit    bool
	xor_circuit       bool
	substring_circuit bool
	str2int_circuit   bool
	gtlt_circuit      bool
	iterations        int
	byte_size         int
	ps                string
	compile           bool
)

func TestMain(m *testing.M) {

	// logging settings
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// checks logging flag if program is called as ./main.go -debug
	flag.BoolVar(&debug, "debug", false, "sets log level to debug")

	// checks for -tls13-key-commit flag
	flag.BoolVar(&session_commit, "tls13-session-commit", false, "tls13 session commitment proof")

	// checks for -tls13-commit-data flag
	flag.BoolVar(&session_data, "tls13-session-data", false, "tls13 session data proof against existing session commitment")

	// checks for -tls13-key-data flag
	flag.BoolVar(&kdc_oracle, "tls13-oracle", false, "tls13 kdc and data proof")

	// checks for -evaluate-constraints flag
	// evalutes most of the functions, used for quick testing
	flag.BoolVar(&eval_constraints, "evaluate-constraints", false, "evaluates all circuits with different backends. use the backend flag to specify the backend")

	// individual evaluation flags
	flag.BoolVar(&shacal2_circuit, "shacal2", false, "evaluates shacal2 circuit")

	// individual evaluation flags
	flag.BoolVar(&sha256_circuit, "sha256", false, "evaluates sha256 circuit")

	// individual evaluation flags
	flag.BoolVar(&aes128_circuit, "aes128", false, "evaluates aes128 circuit")

	// individual evaluation flags
	flag.BoolVar(&authtag_circuit, "authtag", false, "evaluates authtag circuit")

	// individual evaluation flags
	flag.BoolVar(&gcm_circuit, "gcm", false, "evaluates gcm circuit")

	// individual evaluation flags
	flag.BoolVar(&kdc_circuit, "kdc", false, "evaluates kdc circuit")

	// individual evaluation flags
	flag.BoolVar(&record_circuit, "record", false, "evaluates record circuit")

	// individual evaluation flags
	flag.BoolVar(&xor_circuit, "xor", false, "evaluates xor circuit")

	// individual evaluation flags
	flag.BoolVar(&substring_circuit, "substring", false, "evaluates substring circuit")

	// individual evaluation flags
	flag.BoolVar(&str2int_circuit, "str2int", false, "evaluates str2int circuit")

	// individual evaluation flags
	flag.BoolVar(&gtlt_circuit, "gtlt", false, "evaluates gtlt circuit")

	// checks for -evaluate-constraints flag
	flag.IntVar(&iterations, "iterations", 0, "indicates the iterations of the same evaluation")

	// size of data in bytes to generate and evaluate in circuit (applies only to circuits with dynamic input, e.g. gcm, sha256)
	flag.IntVar(&byte_size, "byte-size", 0, "indicates size of bytes to evaluate in circuit. applies only to circuits with dynamic input (e.g. gcm, sha256). byte-size mod 16 must be zero")

	// indicate proof system
	flag.StringVar(&ps, "backend", "groth16", "switch between groth16, plonk, and plonkFRI proof backends. default: groth16.")

	// indicate if circuit should be compiled only
	flag.BoolVar(&compile, "compile", false, "returns program after circuit compilation, no timing data is captured.")

	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// verify byte size
	if byte_size%16 != 0 {
		log.Error().Msg("byte_size must be divisible by 16, e.g. byte_size=64 works.")
	}

	// activated check
	log.Debug().Msg("Debugging activated.")

	os.Exit(m.Run())
}

func TestAll(t *testing.T) {

	// session commit derivation: kdc + authtag + key commit
	if session_commit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateSessionCommit(ps, compile)
			if err != nil {
				log.Error().Msg("sc.Evaluate()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "sessioncommit_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// session data proof: key commit + record
	if session_data {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateSessionData(ps, compile)
			if err != nil {
				log.Error().Msg("iv.ClientExecute()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "sessiondata_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// full circuit, kdc + authtag + record
	if kdc_oracle {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateOracle(ps, compile)
			if err != nil {
				log.Error().Msg("kd.Evaluate()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "oracle_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// shacal2 evaluation
	if shacal2_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateShacal2(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateShacal2()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "shacal2_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// sha256 evaluation
	if sha256_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		// generate data for evaluation
		byteArray := make([]byte, byte_size)
		in := hex.EncodeToString(byteArray)
		h := sha256.New()
		h.Write(byteArray)
		sum := h.Sum(nil)
		hash := hex.EncodeToString(sum)

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateSha256(ps, compile, in, hash)
			if err != nil {
				log.Error().Msg("EvaluateSha256()")
			}
			s = append(s, data)
		}
		if compile {
			return
		}
		AddStats(data, s, false)
		filename := "sha256_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// aes128 evaluation
	if aes128_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateAES128(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateAES128()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "aes128_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// authtag evaluation
	if authtag_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateAuthTag(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateAuthTag()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "authtag_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// gcm evaluation
	if gcm_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		// generate data, encrypting zeros
		key, _ := hex.DecodeString("ab72c77b97cb5fe9a382d9fe81ffdbed")
		plaintext := make([]byte, byte_size)
		ivBytes, _ := hex.DecodeString("54cc7dc2c37ec006bcc6d1da")

		block, _ := aes.NewCipher(key)
		nonce := ivBytes
		aesgcm, _ := cipher.NewGCM(block)
		ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)[:byte_size]

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateGCM(ps, compile, hex.EncodeToString(key), 2, hex.EncodeToString(nonce), hex.EncodeToString(plaintext), hex.EncodeToString(ciphertext))
			if err != nil {
				log.Error().Msg("EvaluateGCM()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, true)
		filename := "gcm_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// kdc evaluation
	if kdc_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateKdc(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateKdc()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "kdc_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// record evaluation
	if record_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateRecord(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateRecord()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}
		AddStats(data, s, false)
		filename := "record_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// xor evaluation
	if xor_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		// generate data
		// a, b := []byte("Hello"), []byte("world")
		a := make([]byte, byte_size)
		b := make([]byte, byte_size)
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
		for i := iterations; i > 0; i-- {
			data, err := EvaluateXor(ps, compile, in, mask, out)
			if err != nil {
				log.Error().Msg("EvaluateXor()")
			}
			s = append(s, data)
		}
		// return if only interested in circuit constraints
		if compile {
			return
		}
		AddStats(data, s, false)
		filename := "xor_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// substring evaluation
	if substring_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateSubstring(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateSubstring()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "substring_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// str2int evaluation
	if str2int_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateStr2Int(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateStr2Int()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "str2int_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// gtlt evaluation
	if gtlt_circuit {
		data := map[string]string{}
		data["iterations"] = strconv.Itoa(iterations)
		data["backend"] = ps
		if byte_size != 0 {
			data["data_size"] = strconv.Itoa(byte_size)
		} else {
			data["data_size"] = "default"
		}

		var s []map[string]time.Duration
		for i := iterations; i > 0; i-- {
			data, err := EvaluateGTLT(ps, compile)
			if err != nil {
				log.Error().Msg("EvaluateGTLT()")
			}
			s = append(s, data)
		}

		// return if only interested in circuit constraints
		if compile {
			return
		}

		AddStats(data, s, false)
		filename := "gtlt_" + data["iterations"] + "_" + data["backend"] + "_" + data["data_size"]
		StoreM(data, "./jsons/", filename)
	}

	// evaluation of constraints
	if eval_constraints {

		// shacal not needed, first evaluation of sha256 calls shacal2 once
		_, err := EvaluateShacal2(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateShacal2()")
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
			_, err := EvaluateSha256(ps, compile, shaData.in, shaData.hash)
			if err != nil {
				log.Error().Msg("EvaluateSha256()")
			}
		}

		// aes128
		_, err = EvaluateAES128(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateAES128()")
		}

		// authtag evaluation
		_, err = EvaluateAuthTag(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateAuthTag()")
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
			_, err := EvaluateGCM(ps, compile, gcmData.key, gcmData.chunkIndex, gcmData.iv, gcmData.plaintext, gcmData.ciphertext)
			if err != nil {
				log.Error().Msg("EvaluateGCM()")
			}
		}

		// kdc evaluation
		_, err = EvaluateKdc(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateKdc()")
		}

		// evaluate record
		_, err = EvaluateRecord(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateRecord()")
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
			_, err = EvaluateXor(ps, compile, xorData.in, xorData.mask, xorData.out)
			if err != nil {
				log.Error().Msg("EvaluateXor()")
			}
		}

		// evaluate substring
		// can also be used to prove value equality without having to convert numbers
		_, err = EvaluateSubstring(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateSubstring()")
		}

		// evaluate str2int
		_, err = EvaluateStr2Int(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateStr2Int()")
		}

		// evaluate greater than / less than
		_, err = EvaluateGTLT(ps, compile)
		if err != nil {
			log.Error().Msg("EvaluateGTLT()")
		}
	}
}
