TOOL?=vault-plugin-auth-ibmcloud
TEST?=$$(go list ./... | grep -v /vendor/)
EXTERNAL_TOOLS=\
	github.com/mitchellh/gox@v1.0.1
BUILD_TAGS?=${TOOL}
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
TEST_ARGS?=./...
# bin generates the releaseable binaries for this plugin
bin: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

default: dev

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin, except for quickdev which
# is only put into /bin/
quickdev: generate
	@CGO_ENABLED=0 go build -i -tags='$(BUILD_TAGS)' -o bin/vault-plugin-auth-ibmcloud
dev: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

testcompile: fmtcheck generate
	@for pkg in $(TEST) ; do \
		go test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

test:
	@go test -short -parallel=40 ./...

test-acc:
	@go test -parallel=40 $(TESTARGS)
# generate runs `go generate` to build the dynamically generated
# source files.
generate:
	@go generate $(go list ./... | grep -v /vendor/)

# bootstrap the build by downloading additional tools
bootstrap:
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go install $$tool; \
	done

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt:
	gofmt -w $(GOFMT_FILES)

mocks:
	mockgen -destination ${CURDIR}/mocks_test.go -source iam_helper.go -package ibmcloudauth


.PHONY: bin default generate test bootstrap fmt fmtcheck
