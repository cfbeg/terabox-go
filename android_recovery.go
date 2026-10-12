package terabox

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Preserve only an actual native response token when the missing UID prevents
// confirmation. It can be checked by NDUS; a UK never fills in the absent UID.
func recoverableAndroidNDUS(response *PassportResponse) string {
	var data struct {
		NDUS string `json:"ndus"`
	}
	if json.Unmarshal(response.Data, &data) != nil || data.NDUS == "" || !utf8.ValidString(data.NDUS) || strings.ContainsAny(data.NDUS, ";\r\n\x00") {
		return ""
	}
	return data.NDUS
}
