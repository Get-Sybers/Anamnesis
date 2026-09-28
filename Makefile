# anamnesis — pure-Go memory forensics (no Volatility, no Python).
# Root Makefile: the standard Go target set (go-standards.md §13). conform and
# upgrade are the two scripted mechanisms (§12); fmt writes, fmt-check gates.
BINARY := anamnesis

.PHONY: build build-memprocfs test vet fmt fmt-check tidy generate conform upgrade clean

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

## fmt: gofmt -w every file (writes)
fmt:
	gofmt -w .

## fmt-check: fail if any Go file needs gofmt (gates CI)
fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy:
	go mod tidy

generate:
	go generate ./...

## conform: the Go conformance gate (§12) — run by CI and locally
conform:
	@scripts/go-conform.sh

## upgrade: raise deps + toolchain to the highest allowed, then re-conform (§12)
upgrade:
	@scripts/go-upgrade.sh

clean:
	rm -f $(BINARY)
