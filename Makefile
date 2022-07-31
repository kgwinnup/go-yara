
.PHONY: all

test:
	go test -v ./...

build:
	cd cmd && go build -o ../yarag main.go
