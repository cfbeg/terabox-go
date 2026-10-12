package terabox

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	hyInlineScript      = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
	hyLiteralAssignment = regexp.MustCompile(`\b(window\s*\.\s*(jsToken|templateData|__INITIAL_STATE__)|var\s+(jsToken|templateData|__INITIAL_STATE__))\s*=`)
)

// androidHyBootstrap follows wa() and Dr() in the APK login bundle: initial
// state PCF precedes template PCF; jsToken comes only from the browser global.
// It consumes observed literals, never executes downloaded JavaScript.
func androidHyBootstrap(page string) (TemplateData, error) {
	var initial, template TemplateData
	var token string
	for _, script := range hyInlineScript.FindAllStringSubmatch(page, -1) {
		attributes := strings.ToLower(script[1])
		if strings.Contains(attributes, "application/json") || strings.Contains(attributes, "application/ld+json") {
			continue
		}
		source, mask := script[2], maskHyJavaScript(script[2])
		for _, match := range hyLiteralAssignment.FindAllStringSubmatchIndex(mask, -1) {
			if match[1] < len(mask) && mask[match[1]] == '=' {
				// Equality reads a global; it does not establish its value.
				continue
			}
			name := ""
			if match[4] >= 0 {
				name = mask[match[4]:match[5]]
			} else if match[6] >= 0 {
				name = mask[match[6]:match[7]]
			}
			windowAssignment := strings.HasPrefix(mask[match[2]:match[3]], "window")
			if windowAssignment && hyMemberPrecedes(mask, match[0]) {
				continue
			}
			depth := 0
			for _, ch := range mask[:match[0]] {
				if ch == '{' {
					depth++
				} else if ch == '}' {
					depth--
				}
			}
			if depth != 0 || (!windowAssignment && strings.Contains(attributes, "module")) {
				if name == "jsToken" && windowAssignment {
					return TemplateData{}, errors.New("Android Hy jsToken requires an observed top-level literal; dynamic script capture is unsupported")
				}
				continue
			}
			if !hyTopLevelAssignmentStatement(mask, match[0]) {
				return TemplateData{}, errors.New("Android Hy bootstrap requires unconditional observed global literals; dynamic script capture is unsupported")
			}
			start := skipHyWhitespaceComments(source, match[1])
			if name == "jsToken" {
				value, end, err := readHyStringLiteral(source, start)
				if err != nil || !hyLiteralEndsAssignment(source, end) {
					return TemplateData{}, errors.New("Android Hy jsToken requires an observed string literal; dynamic script capture is unsupported")
				}
				token = value
				continue
			}
			end := hyJSONObjectEnd(source, start)
			if end == start || !hyLiteralEndsAssignment(source, end) {
				return TemplateData{}, errors.New("Android Hy bootstrap requires observed literal JSON state")
			}
			var entry struct {
				PcfToken string `json:"pcftoken"`
			}
			if json.Unmarshal([]byte(source[start:end]), &entry) != nil {
				return TemplateData{}, errors.New("Android Hy bootstrap contains invalid literal JSON state")
			}
			if name == "__INITIAL_STATE__" {
				initial.PcfToken = entry.PcfToken
			} else {
				template.PcfToken = entry.PcfToken
			}
		}
	}
	pcf := initial.PcfToken
	if pcf == "" {
		pcf = template.PcfToken
	}
	if pcf == "" {
		return TemplateData{}, errors.New("Android Hy page did not provide pcftoken")
	}
	return TemplateData{PcfToken: pcf, JsToken: token}, nil
}

func skipHyWhitespaceComments(source string, start int) int {
	for start < len(source) {
		if strings.ContainsRune(" \t\r\n\f", rune(source[start])) {
			start++
			continue
		}
		if strings.HasPrefix(source[start:], "//") {
			if end := strings.IndexByte(source[start:], '\n'); end >= 0 {
				start += end + 1
				continue
			}
			return len(source)
		}
		if strings.HasPrefix(source[start:], "/*") {
			if end := strings.Index(source[start+2:], "*/"); end >= 0 {
				start += end + 4
				continue
			}
			return len(source)
		}
		break
	}
	return start
}

func hyLiteralEndsAssignment(source string, end int) bool {
	if end > len(source) {
		return false
	}
	position := skipHyWhitespaceComments(source, end)
	if position == len(source) || source[position] == ';' || source[position] == ',' {
		return true
	}
	if strings.ContainsAny(source[end:position], "\r\n") &&
		((source[position] >= 'A' && source[position] <= 'Z') || (source[position] >= 'a' && source[position] <= 'z') || source[position] == '_' || source[position] == '$') {
		remaining := source[position:]
		// These word operators can continue the literal expression across a
		// newline. A new identifier/declaration instead requires ASI.
		if !strings.HasPrefix(remaining, "in ") && !strings.HasPrefix(remaining, "instanceof ") {
			return true
		}
	}
	return false
}

func hyJSONObjectEnd(source string, start int) int {
	if start >= len(source) || source[start] != '{' {
		return start
	}
	depth, quoted, escaped := 0, false, false
	for i := start; i < len(source); i++ {
		ch := source[i]
		if quoted {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = false
			}
			continue
		}
		if ch == '"' {
			quoted = true
		} else if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return start
}

func readHyStringLiteral(source string, start int) (string, int, error) {
	if start >= len(source) || (source[start] != '\'' && source[start] != '"') {
		return "", start, errors.New("string literal required")
	}
	quote, position := source[start], start+1
	var result strings.Builder
	var pendingSurrogate rune
	appendRune := func(value rune) error {
		if value >= 0xD800 && value <= 0xDBFF {
			if pendingSurrogate != 0 {
				return errors.New("unpaired string surrogate")
			}
			pendingSurrogate = value
			return nil
		}
		if value >= 0xDC00 && value <= 0xDFFF {
			if pendingSurrogate == 0 {
				return errors.New("unpaired string surrogate")
			}
			result.WriteRune(utf16.DecodeRune(pendingSurrogate, value))
			pendingSurrogate = 0
			return nil
		}
		if pendingSurrogate != 0 || !utf8.ValidRune(value) {
			return errors.New("invalid string code point")
		}
		result.WriteRune(value)
		return nil
	}
	for position < len(source) {
		ch := source[position]
		position++
		if ch == quote {
			if pendingSurrogate != 0 {
				return "", position, errors.New("unpaired string surrogate")
			}
			return result.String(), position, nil
		}
		if ch == '\n' || ch == '\r' {
			return "", position, errors.New("unescaped literal newline")
		}
		if ch != '\\' {
			value, size := utf8.DecodeRuneInString(source[position-1:])
			if value == utf8.RuneError && size == 1 {
				return "", position, errors.New("invalid string UTF-8")
			}
			position += size - 1
			if err := appendRune(value); err != nil {
				return "", position, err
			}
			continue
		}
		if position >= len(source) {
			break
		}
		escaped := source[position]
		position++
		var value rune
		switch escaped {
		case '\n':
			continue
		case '\r':
			if position < len(source) && source[position] == '\n' {
				position++
			}
			continue
		case 'b':
			value = '\b'
		case 'f':
			value = '\f'
		case 'n':
			value = '\n'
		case 'r':
			value = '\r'
		case 't':
			value = '\t'
		case 'v':
			value = '\v'
		case '0':
			if position < len(source) && source[position] >= '0' && source[position] <= '9' {
				return "", position, errors.New("legacy octal escape unsupported")
			}
			value = 0
		case 'x', 'u':
			digits := 2
			braced := false
			if escaped == 'u' {
				digits = 4
			}
			if escaped == 'u' && position < len(source) && source[position] == '{' {
				braced = true
				position++
				end := strings.IndexByte(source[position:], '}')
				if end <= 0 || end > 6 {
					return "", position, errors.New("invalid unicode escape")
				}
				digits = end
			}
			if position+digits > len(source) {
				return "", position, errors.New("incomplete literal escape")
			}
			parsed, err := strconv.ParseUint(source[position:position+digits], 16, 32)
			if err != nil {
				return "", position, errors.New("invalid literal escape")
			}
			position += digits
			if braced {
				position++
			}
			value = rune(parsed)
		default:
			if escaped >= '1' && escaped <= '9' {
				return "", position, errors.New("legacy numeric escape unsupported")
			}
			value = rune(escaped)
		}
		if err := appendRune(value); err != nil {
			return "", position, err
		}
	}
	return "", position, errors.New("unterminated string literal")
}

// Mask strings/comments before finding assignments so text inside a string or
// comment cannot establish a browser global. Source offsets remain unchanged.
func maskHyJavaScript(source string) string {
	mask := []byte(source)
	for position := 0; position < len(source); {
		start, end := position, position
		if strings.HasPrefix(source[position:], "//") {
			end = len(source)
			if newline := strings.IndexByte(source[position:], '\n'); newline >= 0 {
				end = position + newline
			}
		} else if strings.HasPrefix(source[position:], "/*") {
			end = len(source)
			if closing := strings.Index(source[position+2:], "*/"); closing >= 0 {
				end = position + closing + 4
			}
		} else if ch := source[position]; ch == '\'' || ch == '"' || ch == '`' {
			end = position + 1
			for end < len(source) {
				if source[end] == '\\' {
					end += 2
					continue
				}
				if source[end] == ch {
					end++
					break
				}
				end++
			}
			if end > len(source) {
				end = len(source)
			}
		} else if source[position] == '/' && hyRegexLiteralStart(source, position) {
			end = position + 1
			inClass := false
			for end < len(source) {
				ch := source[end]
				if ch == '\\' {
					end += 2
					continue
				}
				if ch == '[' {
					inClass = true
				} else if ch == ']' {
					inClass = false
				}
				if ch == '/' && !inClass {
					end++
					break
				}
				if ch == '\r' || ch == '\n' {
					break
				}
				end++
			}
			if end > len(source) {
				end = len(source)
			}
		}
		if end == start {
			position++
			continue
		}
		for i := start; i < end; i++ {
			if mask[i] != '\r' && mask[i] != '\n' {
				mask[i] = ' '
			}
		}
		position = end
	}
	return string(mask)
}

func hyRegexLiteralStart(source string, position int) bool {
	for previous := position - 1; previous >= 0; previous-- {
		if strings.ContainsRune(" \t\r\n\f", rune(source[previous])) {
			continue
		}
		return strings.ContainsRune("=(:,[!&|?;{}", rune(source[previous]))
	}
	return true
}

func hyMemberPrecedes(mask string, position int) bool {
	for previous := position - 1; previous >= 0; previous-- {
		ch := mask[previous]
		if strings.ContainsRune(" \t\r\n\f", rune(ch)) {
			continue
		}
		return ch == '.' || ch == '$' || ch == '_' || (ch >= '0' && ch <= '9') ||
			(ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
	}
	return false
}

func hyTopLevelAssignmentStatement(mask string, position int) bool {
	for previous := position - 1; previous >= 0; previous-- {
		ch := mask[previous]
		if strings.ContainsRune(" \t\r\n\f", rune(ch)) {
			continue
		}
		return ch == ';' || ch == '}'
	}
	return true
}
