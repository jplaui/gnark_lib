## **TLS specific circuits in with gnark.**

The repo does not contain a go.mod file per default because the gnark_lib/circuits/gadgets folder is supposed to be imported in other modules.

### build the code
- run `make build` and run `make evaluate-constraints` or run `make evaluate-circuits`

### TODOs
- modify `zk_evaluations_test.go` file and rewrite tests according to functions only. the test functions should not produce evaluation results in json files, neither constraint numbers... cause this module is used from other repos

#### additional
(to execute plonk, run `go get github.com/consensys/gnark@develop` and `go mod tidy`)

#### how to execute the code
- download the repository and cd into the root folder of the repository. call `go mod init gnark_circuit` and run `go mod tidy`.
- run `go run main.go --help` to display possible circuits to execute
- e.g. run `go run main.go --help -tls-oracle` to execute a full oracle proof
- use the `-debug` flag if you want additional timing information
- use the `-backend` flag to indicate different zk snark backends which you want the circuit to be executed in. e.g. `go run main.go -debug -tls13-session-commit -backend plonkFRI` executes the tls session commitment circuit with the plonk FRI proof system. per default, the code uses the groth16 backend if not otherwise specified.

- example of evaluation call `go run main.go -debug -gcm -iterations 2 -byte-size 16 -backend plonk`

#### make
- if commands are written with @, then the command itself is supressed as output of calling make ...


