.PHONY: clean test bench

all: clean test

clean:
	rm -f coverage.out
test:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out
