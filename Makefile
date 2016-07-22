
build:
	go fmt
	go vet -v -race
	go test -v -race
	go install .
