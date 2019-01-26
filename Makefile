.PHONY: clean fmt test

all: clean fmt test

clean:
	rm -f coverage.out

fmt:
	go fmt .

test: fmt
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out
