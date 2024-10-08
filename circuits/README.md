## **TLS specific circuits in with gnark.**

The repo does not contain a go.mod file per default because the gnark_lib/circuits/gadgets folder is supposed to be imported in other modules.

#### how to execute the code
- download the repository and cd into the `root/circuits` folder of the repository. call `go mod init circuits` and run `go mod tidy`.
- run `go run main.go --help` to display possible circuits to execute
- e.g. run `go run main.go --help -tls-oracle` to execute a full oracle proof
- use the `-debug` flag if you want additional timing information
- use the `-backend` flag to indicate different zk snark backends which you want the circuit to be executed in. e.g. `go run main.go -debug -tls13-session-commit -backend plonkFRI` executes the tls session commitment circuit with the plonk FRI proof system. per default, the code uses the groth16 backend if not otherwise specified.

- example of evaluation call `go run main.go -debug -gcm -iterations 2 -byte-size 16 -backend plonk`

#### running a test
- jump into the `circuits/gadgets` folder and run `go test -run TestLookUpAES128 .`

#### using make (not recommended because outdated)
- run `make build` and run `make evaluate-constraints` or run `make evaluate-circuits`
- if commands are written with @, then the command itself is supressed as output of calling make ...


