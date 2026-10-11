package terabox

import "net/url"

// advanceAndroidRegistrationPage follows the APK's router.push calls after a
// successful SendCode/Verify. Vue drops the previous page's unrelated query
// fields; native identity remains in the profile and JS bridge.
func (c *Client) advanceAndroidRegistrationPage(verification bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	page, err := url.Parse(c.androidApp.profile.PageURL)
	if err != nil {
		return
	}
	previous := page.Query()
	query := url.Values{}
	if verification {
		// HyEmailVerfify is the APK's actual route spelling.
		page.Path = "/wap/hylogin/emailVerfify"
		if previous.Has("from") {
			query["from"] = previous["from"]
		}
	} else {
		page.Path = "/wap/hylogin/emailRegister"
		query.Set("type", "2")
		query.Set("showDoublePwd", "1")
		if previous.Has("redirectUrl") {
			query["redirectUrl"] = previous["redirectUrl"]
		}
	}
	page.RawPath = ""
	page.RawQuery = query.Encode()
	if !verification {
		page.RawQuery = "type=2&showDoublePwd=1"
		if previous.Has("redirectUrl") {
			page.RawQuery += "&redirectUrl=" + url.QueryEscape(previous.Get("redirectUrl"))
		}
	}
	c.androidApp.profile.PageURL = page.String()
	c.androidApp.profile.Channel = c.androidApp.profile.UserAgent
}
