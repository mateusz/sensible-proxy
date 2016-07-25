LATEST_TAG=$(shell git describe --abbrev=0 --tags)
BUILD_DIR=./_build

build:
	go fmt
	go vet -v -race
	go test -v -race
	go install .

release:
	@echo "Building for latest tag version: $(LATEST_TAG)"
	rm -rf ${BUILDDIR} && mkdir -p $(BUILD_DIR)

	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/sensible-proxy
	tar -czf ${BUILD_DIR}/sensible-proxy_$(LATEST_TAG)_darwin_amd64.tar.gz -C $(BUILD_DIR) sensible-proxy

	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/sensible-proxy
	tar -czf ${BUILD_DIR}/sensible-proxy_$(LATEST_TAG)_linux_amd64.tar.gz -C $(BUILD_DIR) sensible-proxy

	rm $(BUILD_DIR)/sensible-proxy

	ls -la $(BUILD_DIR)

