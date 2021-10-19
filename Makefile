IMG ?= controller:latest
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
GOLANGCI_LINT = $(PROJECT_DIR)/bin/golangci-lint
KUSTOMIZE = $(PROJECT_DIR)/bin/kustomize
GOBINDATA = $(PROJECT_DIR)/bin/go-bindata

all: build

verify-%:
	make $*
	./hack/verify-diff.sh

verify: fmt lint

# Run tests
test: verify unit

# Build operator binaries
build: operator

operator:
	go build -o bin/cluster-capi-operator cmd/cluster-capi-operator/main.go

unit:
	hack/unit-tests.sh

# Run against the configured Kubernetes cluster in ~/.kube/config
run: verify
	go run cmd/cluster-capi-operator/main.go

# Run go fmt against code
.PHONY: fmt
fmt: $(GOLANGCI_LINT)
	( GOLANGCI_LINT_CACHE=$(PROJECT_DIR)/.cache $(GOLANGCI_LINT) run --fix )

# Run go vet against code
.PHONY: vet
vet: lint

.PHONY: lint
lint: $(GOLANGCI_LINT)
	( GOLANGCI_LINT_CACHE=$(PROJECT_DIR)/.cache $(GOLANGCI_LINT) run )

# Download golangci-lint locally if necessary
$(GOLANGCI_LINT):
	$(PROJECT_DIR)/hack/go-get-tool.sh go-get-tool $(GOLANGCI_LINT) github.com/golangci/golangci-lint/cmd/golangci-lint@v1.41.1

$(KUSTOMIZE):
	$(PROJECT_DIR)/hack/go-get-tool.sh go-get-tool $(KUSTOMIZE) sigs.k8s.io/kustomize/kustomize/v3@v3.9.4

$(GOBINDATA):
	$(PROJECT_DIR)/hack/go-get-tool.sh go-get-tool $(GOBINDATA) github.com/go-bindata/go-bindata/go-bindata@v3.1.2

import-assets: $(KUSTOMIZE) $(GOBINDATA)
	$(KUSTOMIZE) build hack/import-assets/capi-operator -o assets/capi-operator/
	cd assets; $(GOBINDATA) -nometadata -pkg assets -ignore bindata.go capi-operator/
	cd hack/import-assets; go run . move-rbac-manifests

# Run go mod
.PHONY: vendor
vendor:
	go mod tidy
	go mod vendor
	go mod verify

# Build the docker image
.PHONY: image
image:
	docker build -t ${IMG} .

# Push the docker image
.PHONY: push
push:
	docker push ${IMG}
