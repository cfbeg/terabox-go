package terabox

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
)

// fetchAndroidHyAsset loads only a referenced bootstrap dependency. Account
// cookies stay on the Hy origin and are never forwarded to the CDN.
func (c *Client) fetchAndroidHyAsset(ctx context.Context, target *url.URL) (string, error) {
	profile := c.AndroidAppProfile()
	page, _ := url.Parse(profile.PageURL)
	for hops := 0; hops < 6; hops++ {
		if !validHyRuntimeAssetURL(target) {
			return "", errors.New("Android Hy bootstrap asset origin is unsupported")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return "", errors.New("Android Hy bootstrap asset URL is invalid")
		}
		req.Header.Set("User-Agent", profile.UserAgent)
		req.Header.Set("Referer", profile.PageURL)
		if urlOrigin(target) == urlOrigin(page) {
			req.Header.Set("Cookie", c.CookieString())
		}
		// The runtime's narrower origin validation includes the asset CDN.
		requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
		req = req.WithContext(requestCtx)
		response, err := c.httpClient.Do(req)
		if err != nil {
			cancel()
			return "", errors.New("Android Hy bootstrap asset request failed")
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			next, locationErr := response.Location()
			response.Body.Close()
			cancel()
			if locationErr != nil {
				return "", errors.New("Android Hy bootstrap asset redirect is invalid")
			}
			target = next
			continue
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			cancel()
			return "", errors.New("Android Hy bootstrap asset response was rejected")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, hyRuntimeMaxScript+1))
		response.Body.Close()
		cancel()
		if readErr != nil || len(body) > hyRuntimeMaxScript {
			return "", errors.New("Android Hy bootstrap asset is incomplete or too large")
		}
		return string(body), nil
	}
	return "", errors.New("too many Android Hy bootstrap asset redirects")
}
