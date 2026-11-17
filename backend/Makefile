SHELL := sh
.DEFAULT_GOAL := verify

.PHONY: verify
verify:
	@cgo=$$(go env CGO_ENABLED) || exit 1; \
	if [ "$$cgo" != "1" ]; then \
		echo "ERROR: go-sqlite3 requires CGO_ENABLED=1 (current: $$cgo) and a C compiler such as gcc. See docs/LOCAL_VERIFICATION.md at the repository root." >&2; \
		exit 1; \
	fi; \
	cc=$$(go env CC) || exit 1; \
	if ! $$cc --version >/dev/null 2>&1; then \
		echo "ERROR: C compiler '$$cc' is unavailable. Install gcc or clang and configure CC. See docs/LOCAL_VERIFICATION.md at the repository root." >&2; \
		exit 1; \
	fi
	go test ./...
