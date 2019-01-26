.PHONY: clean fmt lint vet ineffassign misspell cyclo test

all: clean fmt lint vet ineffassign misspell cyclo test

clean:
	@rm -f coverage.out

fmt:
	@go fmt .

lint: fmt
	@golint .

vet: fmt
	@go vet .

ineffassign: fmt
	@ineffassign .

misspell: fmt
	@misspell .

cyclo: fmt
	@gocyclo .

test: clean fmt
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out
