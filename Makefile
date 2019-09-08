
PACKAGE=accessregister
USER_GH=eyedeekay
GO111MODULE=on
VERSION := 0.32.081

GO111MODULE=on

echo:
	@echo "gothub release -s $(GITHUB_TOKEN) -u $(USER_GH) -r $(PACKAGE) -t v$(VERSION) -d Compound tunnel with pluggable access management"

tag:
	gothub release -s $(GITHUB_TOKEN) -u $(USER_GH) -r $(PACKAGE) -t v$(VERSION) -d "Compound tunnel with pluggable access management"

build:
	cd accessregister && go build -tags="netgo" \
		-ldflags '-w -extldflags "-static"'

try:
	cd accessregister && ./accessregister

clean:
	find . -name '*.go' -exec gofmt -w -s {} \;
	find . -name '*.i2pkeys' -exec rm {} \;
