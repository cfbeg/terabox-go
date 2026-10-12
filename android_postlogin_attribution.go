package terabox

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

// AndroidMaterialSources are the three actual query strings computed by
// aw.e.___ from an observed AfSpreadHelperKt.c() scene, including empty strings.
type AndroidMaterialSources struct {
	Ad       string `json:"ad_material_source"`
	Native   string `json:"na_material_source"`
	Facebook string `json:"fb_material_source"`
}

// AndroidPostLoginAttributionState belongs to the authenticated account.
// Invite and material reports are separate from Webmaster credit confirmation.
type AndroidPostLoginAttributionState struct {
	AccountUID      string                   `json:"account_uid"`
	InviteCode      *string                  `json:"invite_code,omitempty"`
	MaterialSources *AndroidMaterialSources  `json:"material_sources,omitempty"`
	InviteReport    AndroidAttributionReport `json:"invite_report"`
	MaterialReport  AndroidAttributionReport `json:"material_report"`
}

func androidObservedMediaCache(capture AndroidAttributionCapture, profile AndroidAppProfile) *AndroidNativeMediaCache {
	if capture.NativeMediaCache != nil {
		cache := *capture.NativeMediaCache
		if cache.Value != nil {
			value := *cache.Value
			cache.Value = &value
		}
		return &cache
	}
	// Native profile fields represent already observed effective wire values.
	// An absent observation remains uninitialized until native transport calls.
	if value, ok := profile.NativeParams["af_media_source"]; ok {
		return &AndroidNativeMediaCache{Initialized: true, Value: &value}
	}
	if value, ok := profile.LegacyNativeParams["af_media_source"]; ok {
		return &AndroidNativeMediaCache{Initialized: true, Value: &value}
	}
	return &AndroidNativeMediaCache{}
}

// initializeAndroidAttributionMediaCache is called before native common query
// construction. It reproduces RequestCommonParams.c()'s one-time MMKV getter;
// writing returned first-launch metadata later never changes this process cache.
func (c *Client) initializeAndroidAttributionMediaCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.androidAttribution
	if state == nil || state.NativeMediaCache == nil || c.androidApp == nil {
		return
	}
	cache := state.NativeMediaCache
	if !cache.Initialized {
		value := "Undefined"
		stored := state.Capture.StoredMediaSource
		if state.ReferrerReport.Succeeded && state.Capture.Install != nil {
			stored = state.AppInstallMediaSource
		}
		if stored != nil {
			value = *stored
		}
		cache.Initialized, cache.Value = true, &value
	}
	applyAttributionMedia(&c.androidApp.profile, *cache.Value)
}

func androidMaterialSources(scene *string) *AndroidMaterialSources {
	if scene == nil || strings.TrimSpace(*scene) == "" {
		return nil
	}
	mapped := map[string]string{
		"aiPicture": "aipicture", "aiPPT": "na_aippt", "teraAI": "teraai", "scanPage": "terascan",
		"aiSearch": "aisearch", "transcribe": "aitranscribe", "aiCoding": "ai_coding", "shortPlay": "shortplay",
	}[*scene]
	sources := &AndroidMaterialSources{Ad: mapped}
	if strings.HasPrefix(*scene, "fb_") {
		sources.Facebook = strings.TrimPrefix(*scene, "fb_")
	} else {
		sources.Native = mapped
		if mapped == "" {
			sources.Native = *scene
		}
	}
	if strings.TrimSpace(sources.Ad) == "" && strings.TrimSpace(sources.Native) == "" && strings.TrimSpace(sources.Facebook) == "" {
		return nil
	}
	return sources
}

func androidPostLoginInputs(state *AndroidAttributionState) (*string, *AndroidMaterialSources) {
	if state == nil || state.Capture.Install == nil {
		return nil, nil
	}
	var code *string
	if state.ReferrerReport.Succeeded && state.Referrer != nil && state.Referrer.Code != nil && *state.Referrer.Code != "" {
		value := *state.Referrer.Code
		code = &value
	}
	var material *AndroidMaterialSources
	if state.Capture.Install.IsFirstLaunch {
		material = androidMaterialSources(state.Capture.MaterialSourceScene)
	}
	return code, material
}

func validateAndroidPostLoginAttribution(state *AndroidAttributionState, profile AndroidAppProfile) error {
	post := state.PostLogin
	if post == nil {
		return nil
	}
	code, material := androidPostLoginInputs(state)
	if post.AccountUID == "" || post.AccountUID != profile.UID ||
		!reflect.DeepEqual(post.InviteCode, code) || !reflect.DeepEqual(post.MaterialSources, material) {
		return errors.New("saved post-login attribution must match own account and observed installation inputs")
	}
	if (post.InviteReport.Attempted && code == nil) || (post.MaterialReport.Attempted && material == nil) {
		return errors.New("saved post-login report has no genuine attribution input")
	}
	return nil
}

// ReportAndroidPostLoginAttribution sends the APK's conditional
// account reports. Invite code comes only from the confirmed referrer response;
// material labels come only from an observed first-launch native scene. Own UID/NDUS/SK are
// required for eligible requests. Confirmed or uncertain attempts are retained,
// so restoring a session never silently repeats them. No input means no HTTP.
func (c *Client) ReportAndroidPostLoginAttribution(ctx context.Context) error {
	const op = "reportAndroidPostLoginAttribution"
	if err := c.requireAndroidApp(); err != nil {
		return wrapErr(op, err)
	}
	c.attributionMu.Lock()
	defer c.attributionMu.Unlock()
	state := c.AndroidAttribution()
	code, material := androidPostLoginInputs(state)
	if code == nil && material == nil {
		return nil
	}
	c.mu.Lock()
	profile := c.androidApp.profile
	if profile.UID == "" || profile.EncodedSK == "" || c.cookies["ndus"] == "" {
		c.mu.Unlock()
		return wrapErr(op, errors.New("post-login attribution requires the account's own native UID, NDUS and SK"))
	}
	if c.androidAttribution.PostLogin == nil {
		c.androidAttribution.PostLogin = &AndroidPostLoginAttributionState{AccountUID: profile.UID, InviteCode: code, MaterialSources: material}
	}
	c.mu.Unlock()
	if err := validateAndroidPostLoginAttribution(c.AndroidAttribution(), profile); err != nil {
		return wrapErr(op, err)
	}
	var reportErrors []error
	for _, operation := range []string{"invite", "material"} {
		if operation == "invite" && code == nil || operation == "material" && material == nil {
			continue
		}
		begin, err := c.attributionBegin(operation)
		if err != nil {
			reportErrors = append(reportErrors, err)
			continue
		}
		if !begin {
			continue
		}
		options := &requestOpts{method: http.MethodGet, path: "/api/activity/invite/v1/reportinvite", query: url.Values{}}
		if operation == "invite" {
			options.query.Set("code", *code)
		} else {
			options.method, options.path = http.MethodPost, "/newmain/reporter/userattribute"
			options.query.Set("ad_material_source", material.Ad)
			options.query.Set("na_material_source", material.Native)
			options.query.Set("fb_material_source", material.Facebook)
		}
		if _, err := c.attributionRequest(ctx, operation, options, true); err != nil {
			reportErrors = append(reportErrors, err)
			continue
		}
		c.mu.Lock()
		c.attributionReportLocked(operation).Succeeded = true
		c.mu.Unlock()
	}
	return wrapErr(op, errors.Join(reportErrors...))
}
