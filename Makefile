
GO111MODULE=on

build:
	cd accessregister && go build -tags="netgo" \
		-ldflags '-w -extldflags "-static"'

clean:
	find . -name '*.go' -exec gofmt -w -s {} \;
	find . -name '*.i2pkeys' -exec rm {} \;
