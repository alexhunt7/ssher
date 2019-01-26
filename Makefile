.PHONY: clean fmt lint vet ineffassign misspell cyclo test

all: clean fmt lint vet ineffassign misspell cyclo test

clean:
	rm -f coverage.out

fmt:
	go fmt .

lint:
	golint .

vet:
	go vet .

ineffassign:
	ineffassign .

misspell:
	misspell .

cyclo:
	gocyclo .

test: clean fmt
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out
