.PHONY: test build check helm

test:
	go test -race ./...

build:
	mkdir -p bin
	go build -trimpath -o bin/portico ./cmd/portico
	go build -trimpath -o bin/portico-models ./cmd/portico-models

check:
	go vet ./...

helm:
	helm lint deploy/chart
	helm template portico-gateway deploy/chart > /dev/null
