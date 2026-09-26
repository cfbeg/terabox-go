package terabox

import "strings"

// queryEscapeAll escapes a string for form data and query strings.
// Characters outside [A-Za-z0-9-_.~] are percent-encoded; space becomes
// '+'. This matches JavaScript's URLSearchParams output (which also
// leaves !'()* unescaped; percent-encoding them is equivalent after
// decoding).
func queryEscapeAll(s string) string {
	const hexChars = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ':
			b.WriteByte('+')
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexChars[c>>4])
			b.WriteByte(hexChars[c&0x0f])
		}
	}
	return b.String()
}

// formValues holds URL-encoded form pairs preserving insertion order,
// mirroring the JS FormUrlEncoded wrapper around URLSearchParams.
type formValues struct {
	keys   []string
	values []string
}

func newForm() *formValues { return &formValues{} }

func newFormFrom(pairs map[string]string) *formValues {
	f := newForm()
	for k, v := range pairs {
		f.Append(k, v)
	}
	return f
}

func (f *formValues) Append(key, value string) {
	f.keys = append(f.keys, key)
	f.values = append(f.values, value)
}

func (f *formValues) Set(key, value string) {
	f.Delete(key)
	f.Append(key, value)
}

func (f *formValues) Delete(key string) {
	keys := f.keys[:0]
	values := f.values[:0]
	for i, k := range f.keys {
		if k != key {
			keys = append(keys, k)
			values = append(values, f.values[i])
		}
	}
	f.keys = keys
	f.values = values
}

// String returns the encoded form body with spaces encoded as %20,
// matching the JS implementation (URLSearchParams output with every
// '+' replaced by '%20').
func (f *formValues) String() string {
	var b strings.Builder
	for i, k := range f.keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(queryEscapeAll(k))
		b.WriteByte('=')
		v := queryEscapeAll(f.values[i])
		v = strings.ReplaceAll(v, "+", "%20")
		b.WriteString(v)
	}
	return b.String()
}
