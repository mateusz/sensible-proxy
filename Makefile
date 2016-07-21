
build:
	go fmt
	go vet -v -race
	go test -race
	go install .
