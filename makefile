.DEFAULT_GOAL := build

.PHONY: fmt vet build 

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

build: vet
	go build ./...

test: 
	curl -s "localhost:8080/scan" | jq -S 'del(.scan_time,.duration) | .results |= sort_by(.port)' > after.json