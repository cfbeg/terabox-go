# Observing a real browser share click

`ParseAndroidShareClickObservation` imports one actually observed `POST /api/srn/ck` request. It performs no network request, token generation, JavaScript evaluation or installation simulation. Browser `clienttype=5` and native WebView `clienttype=1` keep their separate common query and final form contracts.

```go
var observation terabox.AndroidShareClickObservation
if err := json.Unmarshal(privateObservationJSON, &observation); err != nil {
    return err
}
click, err := terabox.ParseAndroidShareClickObservation(installationDeviceID, observation)
```

The observation includes `method`, exact `url`, request `headers`, exact form `body` and UTC `observed_at`. The parser requires the observed browser User-Agent, Content-Type and Referer, checks the page/request origin, rejects duplicate query/form fields and case-duplicate headers, and preserves optional absent versus empty agency/op_source values. Native body version/devuid/cuid must match the query and installation. Endpoint form language remains independent from interceptor query language.

The returned object describes request inputs. The browser has already attempted that request. The adapter does not mark it successful and does not call `ReportAndroidShareClick`; callers must retain the request's attempted state and actual response separately before any recovery decision. A captured request alone establishes neither an installed Play referrer nor server attribution acceptance or acquisition credit.

## Capture tool

The optional script requires Node.js **22 or newer**, with built-in `fetch` and `WebSocket`. It has no npm dependencies. Start and configure the browser/WebView outside the script, then select its explicit existing CDP target ID.

```text
node tools/capture_share_browser.mjs --help
node tools/capture_share_browser.mjs --endpoint http://127.0.0.1:9222 --target-id EXISTING_TARGET_ID --output private-observation.json --timeout 60
```

`--endpoint` accepts an existing HTTP(S) CDP discovery origin or an exact page WS(S) endpoint. `--target-id` is mandatory: the script never picks a page automatically. Discovery uses `/json/list` and attaches only to that existing page/WebView target. For a direct websocket endpoint its `/devtools/page/TARGET_ID` must match the explicit ID.

The script subscribes to `Network.requestWillBeSent` and `Network.requestWillBeSentExtraInfo`. Extra request headers supply the actual wire Cookie/UA/Referer; it does not infer Cookie from a browser cookie inventory. If the event omits postData, `Network.getRequestPostData` reads the already observed request body. Redirect chains with ambiguous event pairing are rejected. No Chrome launch, navigation, UI click, click HTTP request or token generation is performed. Perform the actual share-page click yourself after the script reports that it is observing.

The deadline includes discovery, attachment and observation; `--timeout` defaults to 60 seconds and cannot exceed 120 seconds. The output is opened with exclusive creation and mode `0600`, so an existing file is never overwritten. It contains private URLs, form values, cookies and headers. Success/error output prints no request values or output-file path. A failed capture can leave the newly reserved file empty; choose a new filename for the next attempt. Store the capture with private session evidence. The script only observes the request; it does not infer its server result.

Offline checks use Go observation fixtures and an in-process fake CDP websocket:

```text
go test ./...
node --check tools/capture_share_browser.mjs
node --test tools/capture_share_browser_test.mjs
```

The fake CDP tests cover both request/extra-header event orders, missing-body retrieval, header validation, timeout, ambiguous redirect pairing and exclusive output-file creation. They start no browser and make no external request.
