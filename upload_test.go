package terabox

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type uploadTestTransport func(*http.Request) (*http.Response, error)

func (f uploadTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func uploadTestResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func uploadTestMD5(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func uploadTestFile(t *testing.T, content []byte) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "upload.bin")
	if err := os.WriteFile(filePath, content, 0600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func uploadTestData(content []byte, chunkSize int64) *UploadData {
	chunks := []string{}
	for start := int64(0); start < int64(len(content)); start += chunkSize {
		chunks = append(chunks, uploadTestMD5(content[start:min(start+chunkSize, int64(len(content)))]))
	}
	return &UploadData{RemoteDir: "/", File: "upload.bin", Size: int64(len(content)), UploadID: "local-upload", Hash: &FileHashes{Chunks: chunks, ChunkSize: chunkSize}, Uploaded: make([]bool, len(chunks))}
}

func TestHashFileStoresBoundariesAndHashes(t *testing.T) {
	content := bytes.Repeat([]byte("abcdefg"), (4<<20)/7+50)
	c := NewClient("")
	hashes, err := c.HashFile(context.Background(), uploadTestFile(t, content), nil)
	if err != nil {
		t.Fatal(err)
	}
	if hashes.ChunkSize != 4<<20 || len(hashes.Chunks) != 2 {
		t.Fatalf("unexpected chunk metadata: size=%d chunks=%v", hashes.ChunkSize, hashes.Chunks)
	}
	if hashes.Chunks[0] != uploadTestMD5(content[:4<<20]) || hashes.Chunks[1] != uploadTestMD5(content[4<<20:]) {
		t.Fatalf("chunk hashes do not match file boundaries: %v", hashes.Chunks)
	}
	if hashes.File != uploadTestMD5(content) || hashes.Slice != uploadTestMD5(content[:256<<10]) || hashes.CRC32 != crc32.ChecksumIEEE(content) {
		t.Fatal("file, slice or CRC32 hash differs from independently hashed content")
	}
}

func TestUploadChunksPreservesSavedBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		resume bool
		legacy bool
	}{
		{name: "saved boundaries"},
		{name: "resumed boundaries", resume: true},
		{name: "legacy zero chunk size", legacy: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := []byte("abcdefgh")
			splitSize := int64(3)
			if test.legacy {
				splitSize = 4 << 20
			}
			data := uploadTestData(content, splitSize)
			if test.legacy {
				data.Hash.ChunkSize = 0
			}
			if test.resume {
				data.Uploaded[0] = true
			}
			var mu sync.Mutex
			received := make(map[int]string)
			rt := uploadTestTransport(func(req *http.Request) (*http.Response, error) {
				reader, err := req.MultipartReader()
				if err != nil {
					return nil, err
				}
				part, err := reader.NextPart()
				if err != nil {
					return nil, err
				}
				chunk, err := io.ReadAll(part)
				if err != nil {
					return nil, err
				}
				index, err := strconv.Atoi(req.URL.Query().Get("partseq"))
				if err != nil {
					return nil, err
				}
				mu.Lock()
				received[index] = string(chunk)
				mu.Unlock()
				return uploadTestResponse(req, http.StatusOK, fmt.Sprintf(`{"md5":%q}`, uploadTestMD5(chunk))), nil
			})
			c := NewClient("", WithHTTPClient(&http.Client{Transport: rt}))
			c.SetVIPDefaults()
			var lastProgress ProgressEvent
			err := c.UploadChunks(context.Background(), data, uploadTestFile(t, content), &UploadOptions{
				MaxTasks: 3, MaxTries: 1, Progress: func(event ProgressEvent) { lastProgress = event },
			})
			if err != nil {
				t.Fatal(err)
			}
			for index := range data.Hash.Chunks {
				if test.resume && index == 0 {
					if _, exists := received[index]; exists {
						t.Fatal("already uploaded part was sent again")
					}
					continue
				}
				start := int64(index) * splitSize
				want := string(content[start:min(start+splitSize, int64(len(content)))])
				if received[index] != want || !data.Uploaded[index] {
					t.Errorf("part %d: content=%q uploaded=%v; want %q", index, received[index], data.Uploaded[index], want)
				}
			}
			if lastProgress.Sent != int64(len(content)) || lastProgress.PartsDone != len(data.Hash.Chunks) {
				t.Fatalf("incomplete final progress: %+v", lastProgress)
			}
		})
	}
}

func TestUploadChunkRejectsMalformedSuccess(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"md5":""}`, `{"md5":"bad"}`, `{"error_code":1,"error_msg":"rejected"}`} {
		t.Run(body, func(t *testing.T) {
			rt := uploadTestTransport(func(req *http.Request) (*http.Response, error) {
				if _, err := io.Copy(io.Discard, req.Body); err != nil {
					return nil, err
				}
				return uploadTestResponse(req, http.StatusOK, body), nil
			})
			c := NewClient("", WithHTTPClient(&http.Client{Transport: rt}))
			data := uploadTestData([]byte("abc"), 3)
			result, err := c.UploadChunk(context.Background(), data, 0, strings.NewReader("abc"), 3)
			if err == nil || result != nil {
				t.Fatalf("malformed response was accepted: result=%+v err=%v", result, err)
			}
			data.Hash.Chunks[0] = "unknown"
			data.NoHashCheck = true
			if err := c.UploadChunks(context.Background(), data, uploadTestFile(t, []byte("abc")), &UploadOptions{MaxTries: 1}); err == nil {
				t.Fatal("malformed response was accepted when hash calculation was disabled")
			}
			if data.Uploaded[0] || data.Hash.Chunks[0] != "unknown" {
				t.Fatalf("failed part was marked complete: %+v", data)
			}
		})
	}
}

func TestUploadChunksValidatesBeforeTransfer(t *testing.T) {
	content := []byte("abc")
	filePath := uploadTestFile(t, content)
	for _, test := range []struct {
		name   string
		mutate func(*UploadData)
		path   string
	}{
		{name: "missing hashes", mutate: func(d *UploadData) { d.Hash = nil }},
		{name: "negative file size", mutate: func(d *UploadData) { d.Size = -1 }},
		{name: "negative chunk size", mutate: func(d *UploadData) { d.Hash.ChunkSize = -1 }},
		{name: "wrong chunk count", mutate: func(d *UploadData) { d.Hash.Chunks = append(d.Hash.Chunks, d.Hash.Chunks[0]) }},
		{name: "wrong completion count", mutate: func(d *UploadData) { d.Uploaded = nil }},
		{name: "missing upload ID", mutate: func(d *UploadData) { d.UploadID = "" }},
		{name: "missing file name", mutate: func(d *UploadData) { d.File = "" }},
		{name: "local size differs", mutate: func(d *UploadData) { d.Size = 2 }},
		{name: "missing local file", path: filepath.Join(t.TempDir(), "missing")},
		{name: "directory", path: t.TempDir()},
		{name: "empty metadata for nonempty file", mutate: func(d *UploadData) { d.Size = 0; d.Hash.Chunks = nil; d.Uploaded = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			rt := uploadTestTransport(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				return uploadTestResponse(req, http.StatusOK, `{"md5":"900150983cd24fb0d6963f7d28e17f72"}`), nil
			})
			c := NewClient("", WithHTTPClient(&http.Client{Transport: rt}))
			data := uploadTestData(content, 3)
			if test.mutate != nil {
				test.mutate(data)
			}
			path := filePath
			if test.path != "" {
				path = test.path
			}
			if err := c.UploadChunks(context.Background(), data, path, nil); err == nil {
				t.Fatal("invalid input was accepted")
			}
			if calls.Load() != 0 {
				t.Fatalf("invalid input caused %d transfers", calls.Load())
			}
		})
	}
}

func TestUploadMethodsRejectNilData(t *testing.T) {
	c := NewClient("")
	for name, call := range map[string]func() error{
		"precreate": func() error { _, err := c.PrecreateFile(context.Background(), nil); return err },
		"rapid":     func() error { _, err := c.RapidUpload(context.Background(), nil); return err },
		"chunk": func() error {
			_, err := c.UploadChunk(context.Background(), nil, 0, strings.NewReader("abc"), 3)
			return err
		},
		"chunks": func() error { return c.UploadChunks(context.Background(), nil, "", nil) },
		"create": func() error { _, err := c.CreateFile(context.Background(), nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("nil data was accepted")
			}
		})
	}
}

func TestUploadChunkValidatesBeforeTransfer(t *testing.T) {
	for _, test := range []struct {
		name   string
		index  int
		size   int64
		source io.Reader
		noID   bool
	}{
		{name: "negative sequence", index: -1, size: 3, source: strings.NewReader("abc")},
		{name: "nil source", size: 3},
		{name: "negative size", size: -1, source: strings.NewReader("abc")},
		{name: "zero size", source: strings.NewReader("")},
		{name: "content length overflow", size: math.MaxInt64, source: strings.NewReader("abc")},
		{name: "missing upload ID", size: 3, source: strings.NewReader("abc"), noID: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			rt := uploadTestTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				return uploadTestResponse(req, http.StatusOK, `{}`), nil
			})
			c := NewClient("", WithHTTPClient(&http.Client{Transport: rt}))
			data := uploadTestData([]byte("abc"), 3)
			if test.noID {
				data.UploadID = ""
			}
			if _, err := c.UploadChunk(context.Background(), data, test.index, test.source, test.size); err == nil || calls != 0 {
				t.Fatalf("invalid input: err=%v calls=%d", err, calls)
			}
		})
	}
}

func TestEmptyFileUploadUsesNoChunks(t *testing.T) {
	filePath := uploadTestFile(t, nil)
	var requests []string
	rt := uploadTestTransport(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.Path)
		if err := req.ParseForm(); err != nil {
			return nil, err
		}
		if req.Form.Get("block_list") != "[]" || req.Form.Get("size") != "0" {
			return nil, fmt.Errorf("unexpected empty-file form: %v", req.Form)
		}
		return uploadTestResponse(req, http.StatusOK, `{"errno":0,"uploadid":"empty-upload","fs_id":1}`), nil
	})
	c := NewClient("", WithHTTPClient(&http.Client{Transport: rt}))
	c.updateData(func(d *appData) { d.jsToken = "local-token" })
	hashes, err := c.HashFile(context.Background(), filePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := &UploadData{RemoteDir: "/", File: "empty.bin", Hash: hashes}
	precreate, err := c.PrecreateFile(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	data.UploadID = precreate.UploadID
	if err := c.UploadChunks(context.Background(), data, filePath, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateFile(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	if strings.Join(requests, ",") != "/api/precreate,/api/create" {
		t.Fatalf("empty file caused unexpected requests: %v", requests)
	}
}

func TestUploadChunksRetriesOnlyTransientHTTPFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			rt := uploadTestTransport(func(req *http.Request) (*http.Response, error) {
				if _, err := io.Copy(io.Discard, req.Body); err != nil {
					return nil, err
				}
				if calls.Add(1) == 1 || status != http.StatusServiceUnavailable {
					return uploadTestResponse(req, status, `{}`), nil
				}
				return uploadTestResponse(req, http.StatusOK, `{"md5":"900150983cd24fb0d6963f7d28e17f72"}`), nil
			})
			c := NewClient("", WithHTTPClient(&http.Client{Transport: rt}))
			data := uploadTestData([]byte("abc"), 3)
			err := c.UploadChunks(context.Background(), data, uploadTestFile(t, []byte("abc")), &UploadOptions{MaxTasks: 1, MaxTries: 2})
			if status == http.StatusServiceUnavailable {
				if err != nil || calls.Load() != 2 || !data.Uploaded[0] {
					t.Fatalf("transient failure was not retried: err=%v calls=%d", err, calls.Load())
				}
			} else {
				var statusErr *httpStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != status || calls.Load() != 1 || data.Uploaded[0] {
					t.Fatalf("permanent failure was retried or lost: err=%v calls=%d", err, calls.Load())
				}
			}
		})
	}
}

func TestCreateFileRejectsIncompleteChunks(t *testing.T) {
	c := NewClient("")
	data := uploadTestData([]byte("abc"), 3)
	data.Hash.Chunks[0] = "unknown"
	if _, err := c.CreateFile(context.Background(), data); err == nil {
		t.Fatal("file with incomplete chunk hashes was accepted")
	}
	data.Hash.Chunks = nil
	if _, err := c.CreateFile(context.Background(), data); err == nil {
		t.Fatal("file with missing chunk hashes was accepted")
	}
}

func TestHashFileRejectsSizeChange(t *testing.T) {
	filePath := uploadTestFile(t, []byte("abc"))
	c := NewClient("")
	_, err := c.HashFile(context.Background(), filePath, func(ProgressEvent) {
		if err := os.Truncate(filePath, 0); err != nil {
			t.Fatal(err)
		}
	})
	// Truncating after the file was read does not change the number of bytes
	// hashed, so check the open file again before returning its metadata.
	if err == nil {
		t.Fatal("hash metadata accepted a file whose size changed during hashing")
	}
}

func TestGetUploadHostValidatesDiscoveryBeforeSaving(t *testing.T) {
	for _, test := range []struct {
		name      string
		host      string
		errno     int
		initial   string
		wantHost  string
		wantError bool
	}{
		{name: "empty", wantError: true},
		{name: "invalid URL", host: "%invalid.terabox.com", wantError: true},
		{name: "unrelated domain", host: "upload.example.net", wantError: true},
		{name: "misleading suffix", host: "terabox.com.example.net", wantError: true},
		{name: "userinfo", host: "user@c-jp.terabox.com", wantError: true},
		{name: "path", host: "c-jp.terabox.com/path", wantError: true},
		{name: "query", host: "c-jp.terabox.com?query=1", wantError: true},
		{name: "empty query", host: "c-jp.terabox.com?", wantError: true},
		{name: "fragment", host: "c-jp.terabox.com#fragment", wantError: true},
		{name: "empty fragment", host: "c-jp.terabox.com#", wantError: true},
		{name: "port", host: "c-jp.terabox.com:443", wantError: true},
		{name: "empty port", host: "c-jp.terabox.com:", wantError: true},
		{name: "full URL", host: "https://c-jp.terabox.com", wantError: true},
		{name: "valid discovery", host: "c-jp.terabox.com", wantHost: "https://c-jp.terabox.com"},
		{name: "valid apex", host: "terabox.com", wantHost: "https://terabox.com"},
		{name: "explicit custom origin", host: "upload.example.net", initial: "https://upload.example.net", wantHost: "https://upload.example.net"},
		{name: "failed API discovery", errno: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			rt := uploadTestTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Query().Get("method") != "locateupload" {
					return nil, errors.New("unexpected discovery request")
				}
				body, err := json.Marshal(LocateUploadResponse{Errno: test.errno, Host: test.host})
				if err != nil {
					return nil, err
				}
				return uploadTestResponse(req, http.StatusOK, string(body)), nil
			})
			initial := test.initial
			if initial == "" {
				initial = "https://previous.terabox.com"
			}
			c := NewClient("", WithUploadHost(initial), WithHTTPClient(&http.Client{Transport: rt}))
			response, err := c.GetUploadHost(context.Background())
			if (err != nil) != test.wantError {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.wantError && (response == nil || response.Errno != test.errno) {
				t.Fatalf("API result lost: %+v", response)
			}
			wantHost := test.wantHost
			if wantHost == "" {
				wantHost = initial
			}
			_, gotHost, _ := c.snapshot()
			if gotHost != wantHost {
				t.Fatalf("upload host=%q; want %q", gotHost, wantHost)
			}
		})
	}
}
