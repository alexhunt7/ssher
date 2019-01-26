PERCENT := %

.PHONY: clean fmt lint vet ineffassign misspell cyclo test

all: clean fmt lint vet ineffassign misspell cyclo test

clean:
	@rm -rf coverage.out docs "localhost:6060"

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

docs: clean fmt
	@bash -c 'godoc -http=:6060 &>/dev/null & sleep 1 && wget --quiet -e robots=off -r -np -N -E -p -k http://localhost:6060/pkg/github.com/alexhunt7/ssher/; mv "localhost:6060" docs; kill $(PERCENT)1'
	@firefox docs/pkg/github.com/alexhunt7/ssher/index.html

test: clean fmt
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out
