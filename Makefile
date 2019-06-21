.PHONY: default
default: binaries

# binaries
.PHONY: binaries
binaries: bin/pkitool bin/pkid
bin/pkitool: $(shell find ./cmd/pkitool ./pkg -name "*.go")
	go build -v -o $@ $($@:bin/=cmd/) ./cmd/pkitool/*.go
bin/pkid: $(shell find ./cmd/pkid ./pkg -name "*.go")
	go build -v -o $@ $($@:bin/=cmd/) ./cmd/pkid/*.go

.PHONY: install
install: $$GOPATH/bin/pkitoolk $$GOPATH/bin/pkid
$$GOPATH/bin/%: bin/%
	cp -v $< $@
