SHELL := /bin/bash
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif
BUILD_DIR=build

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)


all: helmet postrender
# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

test: fmt vet
	go test ./... -v -coverprofile cover.out

run: fmt vet  
	echo "Missing main file"

tidy: fmt vet
	find . -type f -name go.mod -execdir go mod tidy \;	

helmet: $(BUILD_DIR)
	go build -o $(BUILD_DIR)/helmet main.go

postrender: $(BUILD_DIR)
	go build -o $(BUILD_DIR)/postrender postrender/main.go

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BUILD_DIR)/helmet
	rm -f $(BUILD_DIR)/postrender

lint: 
	golangci-lint run