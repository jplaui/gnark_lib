hello:
	@echo "Origo gnark circuit evaluation.\n"
	@echo "to run the repo, call 'make build && make evaluation'."
	@echo "use 'make clean && make develop' to reset the repo."
	@echo "to see which circuits can be evaluated, check 'make help'."

build:
	go mod tidy
	chmod +x evaluate_constraints.sh
	chmod +x evaluate_circuits.sh
	go build .

help:
	./gnark_circuits --help

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
	go mod init gnark_circuits
	go mod tidy
