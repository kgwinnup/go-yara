
.PHONY: all build

test:
	go test -v ./...

build:
	mkdir -p build
	cd cmd && go build -o ../build/yara main.go
