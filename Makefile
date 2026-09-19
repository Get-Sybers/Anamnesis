# anamnesis — pure-Go memory forensics (no Volatility, no Python).
BINARY := anamnesis

.PHONY: build build-memprocfs test vet fmt clean

# Default build: the full CAR pipeline + CLI. The engine backend is stubbed (it
# errors clearly at open) so this builds and tests with no native library.
build:
	CGO_ENABLED=0 go build -o $(BINARY) ./cmd/anamnesis

# The real build: links the MemProcFS-backed engine. Needs the vmm shared library
# at runtime (--lib / ANAMNESIS_VMM_LIB). Still CGO_ENABLED=0 (purego).
build-memprocfs:
	CGO_ENABLED=0 go build -tags memprocfs -o $(BINARY) ./cmd/anamnesis

test:
	go test ./...

vet:
	go vet ./...
	go vet -tags memprocfs ./...

fmt:
	gofmt -l -w .

clean:
	rm -f $(BINARY)
