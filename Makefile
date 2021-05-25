
.PHONY: all build clean

all: build test

build:
	go build -o ./bin/ -ldflags "-X github.com/netsec-ethz/bootstrapper/config.versionString="$(git describe --tags --dirty --always)

clean:
	rm -f bin/*

