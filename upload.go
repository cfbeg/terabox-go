package terabox

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// sliceMD5Size is the size of the leading file slice that gets its own MD5.
const sliceMD5Size = 256 << 10

// GetChunkSize calculates the upload chunk size for a file size.
// Non-VIP users always get 4 MiB; VIP users get the smallest size from
// [4, 8, 16, 32, 64, 128] MiB whose GiB multiple still covers the file.
func GetChunkSize(fileSize int64, isVIP bool) int64 {
	const MiB = int64(1) << 20
	const GiB = int64(1) << 30

	limitSizes := []int64{4, 8, 16, 32, 64, 128}

	if !isVIP {
		return limitSizes[0] * MiB
	}
	for _, limit := range limitSizes {
		if fileSize <= limit*GiB {
			return limit * MiB
		}
	}
	return limitSizes[len(limitSizes)-1] * MiB
}

// FileHashes holds the hashes of a local file used by the upload flow.
type FileHashes struct {
	CRC32  uint32
	Slice  string   // MD5 of the first 256 KiB
	File   string   // MD5 of the whole file
	ETag   string   // File, or md5(chunksJSON)-N for multi-chunk files
	Chunks []string // per-chunk MD5 in upload order
	// ChunkSize preserves the boundaries used to calculate Chunks. Zero
	// retains the legacy behavior of deriving them from the current account.
	ChunkSize int64
}

// ProgressEvent is delivered to a ProgressFunc during hashing/uploading.
type ProgressEvent struct {
	Phase      string // "hash" or "upload"
	Sent       int64  // bytes processed so far
	Total      int64  // total bytes
	PartsDone  int    // finished chunks (upload phase only)
	PartsTotal int    // total chunks (upload phase only)
}

// ProgressFunc receives upload flow progress notifications. It is called
// from the calling goroutine or client-internal goroutines and must not
// block for long.
type ProgressFunc func(ProgressEvent)

// makeRemoteFPath joins a remote directory and file name with exactly one
// slash, matching the JS makeRemoteFPath.
func makeRemoteFPath(sdir, sfile string) string {
	if !strings.HasSuffix(sdir, "/") {
		sdir += "/"
	}
	return sdir + sfile
}

// HashFile calculates the hashes for a local file in a single sequential
// pass, like the JS hashFile helper. It reports "hash" progress events
// after each processed read buffer.
func (c *Client) HashFile(ctx context.Context, filePath string, onProgress ProgressFunc) (*FileHashes, error) {
	const op = "hashFile"

	f, err := os.Open(filePath)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if !st.Mode().IsRegular() {
		return nil, wrapErr(op, errors.New("local path is not a regular file"))
	}
	size := st.Size()
	splitSize := GetChunkSize(size, c.Account().IsVIP)

	crcHash := crc32.NewIEEE()
	fileHash := md5.New()
	sliceHash := md5.New()
	chunkHash := md5.New()

	hashData := &FileHashes{ChunkSize: splitSize, Chunks: []string{}}
	var bytesRead, allBytesRead int64

	buf := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			return nil, wrapErr(op, err)
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			data := buf[:n]
			fileHash.Write(data)
			crcHash.Write(data)

			offset := 0
			for offset < len(data) {
				remaining := int64(len(data) - offset)
				chunkRemaining := splitSize - bytesRead
				readLimit := min(remaining, chunkRemaining)
				sliceAllowed := allBytesRead < sliceMD5Size
				if sliceAllowed {
					readLimit = min(readLimit, sliceMD5Size-allBytesRead)
				}

				chunk := data[offset : offset+int(readLimit)]
				chunkHash.Write(chunk)
				if sliceAllowed {
					sliceHash.Write(chunk)
				}

				offset += int(readLimit)
				allBytesRead += readLimit
				bytesRead += readLimit

				if bytesRead >= splitSize {
					hashData.Chunks = append(hashData.Chunks, hex.EncodeToString(chunkHash.Sum(nil)))
					chunkHash = md5.New()
					bytesRead = 0
				}
			}

			if onProgress != nil {
				onProgress(ProgressEvent{Phase: "hash", Sent: allBytesRead, Total: size})
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, wrapErr(op, rerr)
		}
	}

	finalStat, err := f.Stat()
	if err != nil {
		return nil, wrapErr(op, err)
	}
	if allBytesRead != size || finalStat.Size() != size {
		return nil, wrapErr(op, errors.New("local file size changed while hashing"))
	}
	if bytesRead > 0 {
		hashData.Chunks = append(hashData.Chunks, hex.EncodeToString(chunkHash.Sum(nil)))
	}

	hashData.CRC32 = crcHash.Sum32()
	hashData.Slice = hex.EncodeToString(sliceHash.Sum(nil))
	hashData.File = hex.EncodeToString(fileHash.Sum(nil))
	hashData.ETag = hashData.File

	if len(hashData.Chunks) > 1 {
		chunksJSON, _ := json.Marshal(hashData.Chunks)
		etagSum := md5.Sum(chunksJSON)
		hashData.ETag = hex.EncodeToString(etagSum[:]) + "-" + strconv.Itoa(len(hashData.Chunks))
	}
	return hashData, nil
}

// UploadData carries one file through the precreate/chunks/create flow.
// UploadChunks updates Uploaded and Hash.Chunks; callers must not share
// this state with concurrent upload calls or access it until the call ends.
type UploadData struct {
	RemoteDir   string
	File        string
	Size        int64
	UploadID    string
	Hash        *FileHashes
	NoHashCheck bool   // skip computed chunk-MD5 verification
	Uploaded    []bool // per-chunk completion flags (resume support)
}

// PrecreateResponse is the /api/precreate result.
type PrecreateResponse struct {
	Errno      int         `json:"errno"`
	UploadID   string      `json:"uploadid"` // server sends "uploadid" (no underscore)
	ReturnType int         `json:"return_type"`
	BlockSize  int64       `json:"block_size"`
	RequestID  json.Number `json:"request_id"`
}

// RapidUploadResponse is the /api/rapidupload result. The server nests
// the file metadata under "info"; it is flattened here, preserving the
// flat public fields of the original definition.
type RapidUploadResponse struct {
	Errno     int         `json:"errno"`
	RequestID json.Number `json:"request_id"`
	FSID      int64       `json:"-"`
	Path      string      `json:"-"`
	MD5       string      `json:"-"`
	Size      int64       `json:"-"`
	CTime     int64       `json:"-"`
	MTime     int64       `json:"-"`
}

// UnmarshalJSON flattens the nested "info" object returned by the server.
func (r *RapidUploadResponse) UnmarshalJSON(b []byte) error {
	var wire struct {
		Errno     int         `json:"errno"`
		RequestID json.Number `json:"request_id"`
		Info      struct {
			MD5   string `json:"md5"`
			FSID  int64  `json:"fs_id"`
			Path  string `json:"path"`
			Size  int64  `json:"size"`
			CTime int64  `json:"ctime"`
			MTime int64  `json:"mtime"`
		} `json:"info"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	r.Errno, r.RequestID = wire.Errno, wire.RequestID
	r.FSID, r.Path, r.MD5 = wire.Info.FSID, wire.Info.Path, wire.Info.MD5
	r.Size, r.CTime, r.MTime = wire.Info.Size, wire.Info.CTime, wire.Info.MTime
	return nil
}

// LocateUploadResponse is the locateupload result.
type LocateUploadResponse struct {
	Errno int    `json:"errno"`
	Host  string `json:"host"`
}

// ChunkUploadResult is the superfile2 chunk upload result.
type ChunkUploadResult struct {
	MD5       string      `json:"md5"`
	ErrorCode int         `json:"error_code"`
	ErrorMsg  string      `json:"error_msg"`
	RequestID json.Number `json:"request_id"`
}

// CreateFileResponse is the /api/create (file) result.
type CreateFileResponse struct {
	Errno int    `json:"errno"`
	FSID  int64  `json:"fs_id"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	CTime int64  `json:"ctime"`
	MD5   string `json:"-"`   // decoded from EMD5
	EMD5  string `json:"md5"` // server-obfuscated MD5
	ETag  string `json:"-"`   // MD5 plus chunk-count suffix
}

// errHashRequired is returned by upload steps called without hash data.
var errHashRequired = errors.New("hash data required")

func validateUploadTarget(data *UploadData) error {
	if data == nil {
		return errors.New("upload data required")
	}
	if data.Size < 0 {
		return errors.New("file size must not be negative")
	}
	if data.File == "" {
		return errors.New("remote file name required")
	}
	return nil
}

func validateUploadHashes(data *UploadData) error {
	if err := validateUploadTarget(data); err != nil {
		return err
	}
	if data.Hash == nil {
		return errHashRequired
	}
	if data.Hash.ChunkSize < 0 {
		return errors.New("chunk size must not be negative")
	}
	return nil
}

func (c *Client) uploadChunkSize(data *UploadData) int64 {
	if data.Hash.ChunkSize > 0 {
		return data.Hash.ChunkSize
	}
	return GetChunkSize(data.Size, c.Account().IsVIP)
}

func uploadChunkCount(size, chunkSize int64) int64 {
	if size == 0 {
		return 0
	}
	return 1 + (size-1)/chunkSize
}

// PrecreateFile initiates an upload, reserving an upload ID. On errno
// 4000023 ("need verify") the app tokens are refreshed and the request is
// retried once.
func (c *Client) PrecreateFile(ctx context.Context, data *UploadData) (*PrecreateResponse, error) {
	const op = "precreateFile"
	if err := validateUploadHashes(data); err != nil {
		return nil, wrapErr(op, err)
	}

	var blockList string
	if data.Size == 0 {
		if len(data.Hash.Chunks) != 0 {
			return nil, wrapErr(op, errors.New("empty file must not have chunk hashes"))
		}
		blockList = "[]"
	} else if CheckMD5Slice(data.Hash.Chunks) {
		b, _ := json.Marshal(data.Hash.Chunks)
		blockList = string(b)
	} else {
		predefined := []string{"5910a591dd8fc18c32a8f3df4fdc1761"}
		if data.Size > 4*1024*1024 {
			predefined = append(predefined, "a5fc157d78e6ad1c7e114b056c92821e")
		}
		b, _ := json.Marshal(predefined)
		blockList = string(b)
	}

	form := newForm()
	form.Append("path", makeRemoteFPath(data.RemoteDir, data.File))
	form.Append("autoinit", "1")
	form.Append("size", strconv.FormatInt(data.Size, 10))
	form.Append("file_limit_switch_v34", "true")
	form.Append("block_list", blockList)
	form.Append("rtype", "2")
	if data.UploadID != "" {
		form.Append("uploadid", data.UploadID)
	}
	if CheckMD5Value(data.Hash.Slice) && CheckMD5Value(data.Hash.File) {
		form.Append("content-md5", data.Hash.File)
		form.Append("slice-md5", data.Hash.Slice)
	}
	// CRC32 is a uint32, always within the server's accepted range.
	form.Append("content-crc32", strconv.FormatUint(uint64(data.Hash.CRC32), 10))

	for attempt := 0; ; attempt++ {
		if err := c.ensureJSToken(ctx); err != nil {
			return nil, wrapErr(op, err)
		}
		query := c.appQuery()
		query.Set("jsToken", c.dataSnapshot().jsToken)

		var resp PrecreateResponse
		err := c.doJSON(ctx, op, &requestOpts{
			method: http.MethodPost,
			path:   "/api/precreate",
			query:  query,
			form:   form,
		}, &resp)
		if err != nil {
			return nil, err
		}
		if resp.Errno != errnoPrecreateVerify || attempt >= 1 {
			return &resp, nil
		}
		if _, err := c.UpdateAppData(ctx, ""); err != nil {
			return nil, wrapErr(op, err)
		}
	}
}

// RapidUpload attempts an instant upload using file hashes, skipping the
// data transfer entirely when the server already has the file.
func (c *Client) RapidUpload(ctx context.Context, data *UploadData) (*RapidUploadResponse, error) {
	const op = "rapidUpload"
	if err := validateUploadHashes(data); err != nil {
		return nil, wrapErr(op, err)
	}
	if data.Size < sliceMD5Size {
		return nil, wrapErr(op, errors.New("File size too small!"))
	}
	if !CheckMD5Value(data.Hash.Slice) || !CheckMD5Value(data.Hash.File) {
		return nil, wrapErr(op, errors.New("Bad MD5 Slice Hash or MD5 File Hash"))
	}

	form := newForm()
	form.Append("path", makeRemoteFPath(data.RemoteDir, data.File))
	form.Append("content-length", strconv.FormatInt(data.Size, 10))
	form.Append("content-md5", data.Hash.File)
	form.Append("slice-md5", data.Hash.Slice)
	form.Append("content-crc32", strconv.FormatUint(uint64(data.Hash.CRC32), 10))
	rtype := "2"
	if CheckMD5Slice(data.Hash.Chunks) {
		b, _ := json.Marshal(data.Hash.Chunks)
		form.Append("block_list", string(b))
	} else {
		// unsafe rapid upload without chunk hashes
		rtype = "3"
	}
	form.Append("rtype", rtype)
	form.Append("mode", "1")

	var resp RapidUploadResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/rapidupload",
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetUploadHost discovers the upload endpoint and stores it as the
// client's upload host on success.
func (c *Client) GetUploadHost(ctx context.Context) (*LocateUploadResponse, error) {
	const op = "getUploadHost"

	var resp LocateUploadResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodGet,
		path:   "/rest/2.0/pcs/file",
		query:  url.Values{"method": {"locateupload"}},
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Errno == 0 {
		uhost := "https://" + resp.Host
		u, err := url.Parse(uhost)
		if err != nil {
			return nil, wrapErr(op, err)
		}
		if u.User != nil || u.Host == "" || u.Host != resp.Host || u.Host != u.Hostname() ||
			u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return nil, wrapErr(op, errors.New("upload host must be a hostname without URL components"))
		}
		if err := c.validateEndpoint(u); err != nil {
			return nil, wrapErr(op, err)
		}
		c.mu.Lock()
		c.uhost = uhost
		c.mu.Unlock()
	}
	return &resp, nil
}

// UploadChunk uploads a single file part via multipart POST. src is
// streamed (never buffered in memory) and must provide exactly size bytes.
func (c *Client) UploadChunk(ctx context.Context, data *UploadData, partSeq int, src io.Reader, size int64) (*ChunkUploadResult, error) {
	const op = "uploadChunk"
	if err := validateUploadTarget(data); err != nil {
		return nil, wrapErr(op, err)
	}
	if strings.TrimSpace(data.UploadID) == "" {
		return nil, wrapErr(op, errors.New("upload ID required"))
	}
	if partSeq < 0 {
		return nil, wrapErr(op, errors.New("part sequence must not be negative"))
	}
	if src == nil {
		return nil, wrapErr(op, errors.New("chunk source required"))
	}
	if size <= 0 {
		return nil, wrapErr(op, errors.New("chunk size must be positive"))
	}

	var rb [16]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return nil, wrapErr(op, err)
	}
	boundary := hex.EncodeToString(rb[:])

	bodyHead := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"file\"; filename=\"blob\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n"
	bodyTail := "\r\n--" + boundary + "--\r\n"
	if size > math.MaxInt64-int64(len(bodyHead)+len(bodyTail)) {
		return nil, wrapErr(op, errors.New("chunk size exceeds maximum content length"))
	}

	_, uploadHost, cookieHeader := c.snapshot()

	query := c.appQuery()
	query.Set("method", "upload")
	query.Set("path", makeRemoteFPath(data.RemoteDir, data.File))
	query.Set("uploadid", data.UploadID)
	query.Set("partseq", strconv.Itoa(partSeq))

	body := io.MultiReader(strings.NewReader(bodyHead), src, strings.NewReader(bodyTail))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		uploadHost+"/rest/2.0/pcs/superfile2?"+query.Encode(), body)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.ContentLength = int64(len(bodyHead)) + size + int64(len(bodyTail))
	req, err = c.signAndroidRequest(req)
	if err != nil {
		return nil, wrapErr(op, err)
	}

	resp, err := c.doHTTP(req, c.uploadTimeout)
	if err != nil {
		return nil, wrapErr(op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, wrapErr(op, &httpStatusError{StatusCode: resp.StatusCode})
	}

	var res ChunkUploadResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, wrapErr(op, err)
	}
	if res.ErrorCode != 0 {
		return nil, wrapErr(op, fmt.Errorf("Upload failed! Error Code #%d (%s)", res.ErrorCode, res.ErrorMsg))
	}
	if !CheckMD5Value(res.MD5) {
		return nil, wrapErr(op, errors.New("upload response is missing a valid chunk MD5"))
	}
	return &res, nil
}

// UploadOptions configures UploadChunks.
type UploadOptions struct {
	MaxTasks int          // concurrent chunk uploads (default 10)
	MaxTries int          // attempts per chunk (default 5)
	Progress ProgressFunc // receives "upload" progress events
}

// UploadChunks uploads every not-yet-uploaded chunk of a file with a
// worker pool, MD5 verification and retries. It cancels the remaining
// parts on the first part that exhausts its retries. Hash.ChunkSize fixes
// the chunk boundaries; zero uses the current account for legacy callers.
// Empty files have no parts, so this step makes no HTTP requests. Creation
// of the remote entry remains the responsibility of CreateFile.
func (c *Client) UploadChunks(ctx context.Context, data *UploadData, filePath string, opts *UploadOptions) error {
	const op = "uploadChunks"

	if err := validateUploadHashes(data); err != nil {
		return wrapErr(op, err)
	}
	totalChunks := len(data.Hash.Chunks)
	splitSize := c.uploadChunkSize(data)
	if expected := uploadChunkCount(data.Size, splitSize); int64(totalChunks) != expected {
		return wrapErr(op, fmt.Errorf("chunk count %d does not match file size %d and chunk size %d (want %d)", totalChunks, data.Size, splitSize, expected))
	}
	if len(data.Uploaded) != totalChunks {
		return wrapErr(op, fmt.Errorf("uploaded length %d does not match chunk count %d", len(data.Uploaded), totalChunks))
	}
	if data.Size > 0 && strings.TrimSpace(data.UploadID) == "" {
		return wrapErr(op, errors.New("upload ID required"))
	}
	if err := ctx.Err(); err != nil {
		return wrapErr(op, err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		return wrapErr(op, err)
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return wrapErr(op, err)
	}
	if !st.Mode().IsRegular() {
		return wrapErr(op, errors.New("local path is not a regular file"))
	}
	if st.Size() != data.Size {
		return wrapErr(op, fmt.Errorf("local file size %d does not match upload size %d", st.Size(), data.Size))
	}

	maxTasks, maxTries := 10, 5
	var progress ProgressFunc
	if opts != nil {
		if opts.MaxTasks > 0 {
			maxTasks = opts.MaxTasks
		}
		if opts.MaxTries > 0 {
			maxTries = opts.MaxTries
		}
		progress = opts.Progress
	}
	maxTasks = max(maxTasks, 1)
	maxTries = max(maxTries, 1)

	pending := make([]int, 0, totalChunks)
	var sentTotal, partsDone int64
	for i := 0; i < totalChunks; i++ {
		if data.Uploaded[i] {
			sentTotal += min(splitSize, data.Size-int64(i)*splitSize)
			partsDone++
		} else {
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 {
		if progress != nil {
			progress(ProgressEvent{Phase: "upload", Sent: sentTotal, Total: data.Size, PartsDone: int(partsDone), PartsTotal: totalChunks})
		}
		return nil
	}
	maxTasks = min(maxTasks, len(pending))

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stopTicker := make(chan struct{})
	var tickerWg sync.WaitGroup
	if progress != nil {
		tickerWg.Add(1)
		go func() {
			defer tickerWg.Done()
			t := time.NewTicker(250 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-stopTicker:
					return
				case <-t.C:
					progress(ProgressEvent{
						Phase:      "upload",
						Sent:       atomic.LoadInt64(&sentTotal),
						Total:      data.Size,
						PartsDone:  int(atomic.LoadInt64(&partsDone)),
						PartsTotal: totalChunks,
					})
				}
			}
		}()
	}

	var firstErr error
	var errMu sync.Mutex
	recordErr := func(err error) {
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		errMu.Unlock()
	}

	task := func(i int) error {
		offset := int64(i) * splitSize
		length := min(splitSize, data.Size-offset)
		known := data.Hash.Chunks[i]
		needCalc := !CheckMD5Value(known) && !data.NoHashCheck

		var lastErr error
		for try := 0; try < maxTries; try++ {
			if err := childCtx.Err(); err != nil {
				return fmt.Errorf("Upload failed! [PART #%d]: %w", i+1, err)
			}
			if try > 0 {
				if err := backoffSleep(childCtx, try-1); err != nil {
					return fmt.Errorf("Upload failed! [PART #%d]: %w", i+1, err)
				}
			}

			var src io.Reader = io.NewSectionReader(file, offset, length)
			var hasher hash.Hash
			if needCalc {
				hasher = md5.New()
				src = io.TeeReader(src, hasher)
			}

			res, err := c.UploadChunk(childCtx, data, i, src, length)
			if err == nil {
				switch {
				case CheckMD5Value(known) && res.MD5 != known:
					lastErr = fmt.Errorf("MD5 hash mismatch for file (part: %d of %d)\n\t[Actual MD5:%s / Got MD5:%s]",
						i+1, totalChunks, known, res.MD5)
				case needCalc && hex.EncodeToString(hasher.Sum(nil)) != res.MD5:
					lastErr = fmt.Errorf("MD5 hash mismatch for file (part: %d of %d)\n\t[Actual MD5:%s / Got MD5:%s]",
						i+1, totalChunks, hex.EncodeToString(hasher.Sum(nil)), res.MD5)
				default:
					if CheckMD5Value(res.MD5) && data.Hash.Chunks[i] != res.MD5 {
						data.Hash.Chunks[i] = res.MD5
					}
					data.Uploaded[i] = true
					atomic.AddInt64(&sentTotal, length)
					atomic.AddInt64(&partsDone, 1)
					return nil
				}
			} else {
				lastErr = err
				var statusErr *httpStatusError
				if errors.As(err, &statusErr) && statusErr.StatusCode >= 400 && statusErr.StatusCode < 500 &&
					statusErr.StatusCode != http.StatusRequestTimeout && statusErr.StatusCode != http.StatusTooManyRequests {
					return fmt.Errorf("Upload failed! [PART #%d]: %w", i+1, err)
				}
			}

			args := []any{"part", i + 1, "error", lastErr}
			if try+1 != maxTries {
				args = append(args, "retry", try+1)
			}
			c.warn("Upload failed for part", args...)
		}
		return fmt.Errorf("Upload failed! [PART #%d]: %w", i+1, lastErr)
	}

	var nextIdx int64
	var wg sync.WaitGroup
	for w := 0; w < maxTasks; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if childCtx.Err() != nil {
					return
				}
				n := atomic.AddInt64(&nextIdx, 1) - 1
				if n >= int64(len(pending)) {
					return
				}
				if err := task(pending[n]); err != nil {
					recordErr(err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if progress != nil {
		close(stopTicker)
		tickerWg.Wait()
		progress(ProgressEvent{
			Phase:      "upload",
			Sent:       atomic.LoadInt64(&sentTotal),
			Total:      data.Size,
			PartsDone:  int(atomic.LoadInt64(&partsDone)),
			PartsTotal: totalChunks,
		})
	}

	if firstErr != nil {
		return wrapErr(op, firstErr)
	}
	if err := ctx.Err(); err != nil {
		return wrapErr(op, err)
	}
	return nil
}

// CreateFile creates the final remote file entry after all chunks were
// uploaded. On success EMD5 is decoded into MD5 and ETag is derived.
func (c *Client) CreateFile(ctx context.Context, data *UploadData) (*CreateFileResponse, error) {
	const op = "createFile"
	if err := validateUploadHashes(data); err != nil {
		return nil, wrapErr(op, err)
	}
	if strings.TrimSpace(data.UploadID) == "" {
		return nil, wrapErr(op, errors.New("upload ID required"))
	}
	if expected := uploadChunkCount(data.Size, c.uploadChunkSize(data)); int64(len(data.Hash.Chunks)) != expected {
		return nil, wrapErr(op, fmt.Errorf("chunk count %d does not match expected count %d", len(data.Hash.Chunks), expected))
	}
	if data.Size > 0 && !CheckMD5Slice(data.Hash.Chunks) {
		return nil, wrapErr(op, errors.New("valid chunk hashes required to create file"))
	}

	chunks := data.Hash.Chunks
	if chunks == nil {
		chunks = []string{}
	}
	blockJSON, _ := json.Marshal(chunks)

	form := newForm()
	form.Append("path", makeRemoteFPath(data.RemoteDir, data.File))
	form.Append("size", strconv.FormatInt(data.Size, 10))
	form.Append("isdir", "0")
	if CheckMD5Value(data.Hash.Slice) && CheckMD5Value(data.Hash.File) {
		form.Append("content-md5", data.Hash.File)
		form.Append("slice-md5", data.Hash.Slice)
	}
	form.Append("content-crc32", strconv.FormatUint(uint64(data.Hash.CRC32), 10))
	form.Append("block_list", string(blockJSON))
	form.Append("uploadid", data.UploadID)
	form.Append("rtype", "2")

	var resp CreateFileResponse
	err := c.doJSON(ctx, op, &requestOpts{
		method: http.MethodPost,
		path:   "/api/create",
		form:   form,
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.EMD5 != "" {
		resp.MD5 = DecodeMD5(resp.EMD5)
		resp.ETag = resp.MD5
		if len(data.Hash.Chunks) > 1 {
			resp.ETag += "-" + strconv.Itoa(len(data.Hash.Chunks))
		}
	}
	return &resp, nil
}
