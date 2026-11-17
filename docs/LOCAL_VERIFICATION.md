# Local backend verification

The backend uses github.com/mattn/go-sqlite3, which requires cgo and a native C
compiler. CGO_ENABLED=0 produces a SQLite stub and cannot run database tests.
The verify target checks the effective Go settings before running go test ./....
It returns a nonzero exit code when a prerequisite is missing or tests fail.

## Requirements

- Go 1.22 or newer, available as go on PATH.
- GNU Make and a POSIX sh on PATH.
- A C compiler compatible with the Go target architecture (gcc or clang), on PATH.
- Effective CGO_ENABLED=1. CC selects the compiler (Go defaults to gcc on many hosts).
- Dependencies already cached, or network access to download the Go modules.

Run from the repository root:

```sh
cd backend
go env CGO_ENABLED CC GOOS GOARCH
CGO_ENABLED=1 CC=gcc make verify
```

On Debian/Ubuntu, install the build tools with sudo apt-get install build-essential.
On macOS, install the command-line developer tools with xcode-select --install,
then use CGO_ENABLED=1 CC=clang make verify.

## Windows (PowerShell)

Install GNU Make, Git for Windows (for sh), and a native MinGW-w64 gcc matching
Go's architecture. Add their executable directories to PATH in this terminal.
For windows/amd64, use an x86_64 compiler; a compiler targeting MSYS alone is
not a substitute for a native Windows toolchain.

```powershell
cd backend
$env:CGO_ENABLED = '1'
$env:CC = 'gcc'
go env CGO_ENABLED CC GOOS GOARCH
sh --version
make --version
gcc --version
make verify
```

These environment settings affect only the current terminal and its children.
The Makefile uses sh explicitly, including when make is started from PowerShell.

## Diagnose the environment guard

From backend, in a POSIX shell:

```sh
CGO_ENABLED=0 make verify
CGO_ENABLED=1 CC=sentinel-atlas-missing-cc make verify
```

The first command must fail with an explicit CGO_ENABLED=1 requirement; the
second must fail naming the unavailable C compiler. Neither should start tests.
After installing the compiler, use the normal verification command above.
Passing the prerequisite checks alone does not mean the tests pass; the target
then runs the actual backend suite and preserves its failure status.
