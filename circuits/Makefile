hello:
	@echo "Origo gnark circuit evaluation.\n"
	@echo "to run the repo, call 'make build && make evaluation'."
	@echo "use 'make clean && make develop' to reset the repo."
	@echo "to see which circuits can be evaluated, check 'make help'."
	@echo "two evaluations are supported, 1. 'make evaluate-circuits' and 2. 'make evaluate-constraints'."

build:
	go get github.com/consensys/gnark@develop
	go mod tidy
	chmod +x evaluate_constraints.sh
	chmod +x evaluate_circuits.sh
	go build .

help:
	./circuits --help

evaluate-constraints:
	./evaluate_constraints.sh

evaluate-circuits:
	./evaluate_circuits.sh

develop:
	go get github.com/consensys/gnark@develop
	go mod tidy

clean:
	rm -rf go.sum
	rm -rf go.mod
	go mod init circuits
	go mod tidy
