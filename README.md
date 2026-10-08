# terabox-go

A Go client for TeraBox, ported from
[seiya-npm/terabox-api](https://github.com/seiya-npm/terabox-api).
Requires Go 1.21 or later and uses only the standard library.

## Install

```sh
go get github.com/cfbeg/terabox-go
```

## Read account quota

Set `TERABOX_NDUS` to the session's `ndus` cookie, then use a context to bound
the operation:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	terabox "github.com/cfbeg/terabox-go"
)

func main() {
	ndus := os.Getenv("TERABOX_NDUS")
	if ndus == "" {
		log.Fatal("TERABOX_NDUS is required")
	}
	client := terabox.NewClient(ndus)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	quota, err := client.GetQuota(ctx)
	if err != nil {
		log.Fatal(err)
	}
	if quota.Errno != 0 {
		log.Fatalf("quota API error: %d", quota.Errno)
	}
	fmt.Printf("Used: %d bytes; available: %d bytes\n", quota.Used, quota.Available)
}
```

`NewClient("")` creates an unauthenticated client for the passport flows.
Save `CookieString()` and restore it with `WithCookies(savedCookies)` to retain
browser/challenge state across restarts. A successful `PassportLogin` or
`RegisterFinish` returns `NDUS`; pass it to `NewClient` for an authenticated client.

## Errors and HTTP behavior

- Single-request API methods return server result codes in `Errno`, `Code`,
  or `ErrorCode`. Check these fields even when the Go error is nil.
- Multi-request operations stop on failed prerequisites. `errors.As` can
  retrieve an `*terabox.APIError` and its original server `Code` from the
  returned error. Transport and decoding errors remain wrapped in `*terabox.Error`.
- Per-request timeouts and caller deadlines use whichever expires first.
  Closing a response body releases the internal timeout context.
- `WithHTTPClient` copies the supplied client's configuration. The package
  handles redirects and cookies itself, so the supplied `CheckRedirect` and
  `Jar` are not used or modified. Custom transports, proxies, and client timeouts
  are retained.
- Discovered endpoints must use HTTPS and belong to `terabox.com`. Additional
  exact origins can be trusted explicitly with `WithWebHost` or `WithUploadHost`;
  this also supports HTTP servers in local tests. Unrelated redirects and HTTPS
  downgrades are rejected before credentials are sent.
- Page refreshes validate their final response before committing cookies,
  tokens, account state, or regional host changes. Login pages may refresh only
  the passport token without erasing unrelated session tokens.

## Uploads and synchronization

The upload API exposes individual steps: `HashFile`, `PrecreateFile`,
`GetUploadHost`, `UploadChunks`, and `CreateFile`. Keep the returned hashes and
upload ID in `UploadData`, and initialize `Uploaded` to one flag per chunk.
Handle precreate result codes and `ReturnType` before proceeding with chunk upload.

`HashFile` stores `FileHashes.ChunkSize`. Preserve it when saving hashes or
resuming an upload so membership changes cannot alter part boundaries.
A zero `ChunkSize` retains the legacy behavior of deriving it from the current
account. `NoHashCheck` disables local hash calculation for unknown parts; a valid
server MD5 is still required. An `UploadData` value must not be shared between
concurrent upload calls.

Empty local files have no chunks: `UploadChunks` performs no transfer, and
precreate/create send `block_list=[]`. Remote empty-file acceptance has not
been verified against the service.

`FileDiff` serializes calls on the same client and commits its cursor only
after every page succeeds. A pagination or request failure resets the cursor
for a full sync on the next call. Cancellation while waiting for another
`FileDiff` call is checked after that call finishes.

`GetRecentUploads` keeps its page argument for source compatibility but ignores
it: pagination for `/rest/recent/listall` has not been verified.

## Development

```sh
go test ./...
go vet ./...
go test -race ./...
```

Tests use mock transports, local HTTP servers, and temporary files; they do not
require a live account. The race detector requires CGO and a C compiler.
CI checks Go 1.21 and the current stable Go release on Linux and Windows, and
runs the race detector on Linux.
