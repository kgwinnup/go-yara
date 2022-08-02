
.PHONY: all build example

test:
	go test -v ./...

example:
	cd example && go build -o ../yara-example main.go

build:
	mkdir -p build
	cd cmd && go build -o ../build/yara main.go
