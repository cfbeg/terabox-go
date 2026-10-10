# Android native request signing

## Verified input

The implementation was reconstructed from `TeraBox_Android_web_v4.26.5.apk`,
not from the earlier report's example Python model.

| Artifact | SHA-256 |
| --- | --- |
| APK | `73340b723c45cca9bb44289b1ca3ea2e5e207f4af406a6970bb2ef1badf7f696` |
| `lib/arm64-v8a/libdubox-security.so` | `d376c9a8cbab80ba991bf354b089cce7962e3eb135211f8ed57bd75de6664d9c` |
| `lib/arm64-v8a/libnetdisk-security-rand.so` | `c4912d59811a46b0d9d52d2105dbe48a46ab7e92044a5a8f3cd7d72d875ffc13` |
| `lib/armeabi-v7a/libdubox-security.so` | `39ae24cea7f06b64cd56cde789e00a9bab69af2858cedbd2b0592dadc2fedeca` |

Analysis used ELF symbols, AArch64/Thumb disassembly, Ghidra decompilation,
DEX call sites, and execution of native instructions under Unicorn. Native
addresses below are ELF virtual addresses, before Ghidra's image-base offset.

## URLHandler: the Java-invoked path

`classes13.dex`, `com.dubox.drive.network.request._____` invokes
`URLHandler.handlerURL(Context, builtURL, nduss, uid)`.
The Kotlin parameter labels explicitly identify the last two strings as
`nduss` and `uid`. `classes11.dex`, `com.dubox.drive.account.f._()` populates
the network parameters from `Account.q()` and `Account.A()`, respectively.
These are separate runtime values; UID cannot be computed from NDUS.

`URLHandler.getDeviceID()` returns the application's device ID.
`URLHandler.getSK()` reads `net_param_sk` from the account's MMKV configuration
store (`xu.b.r()` → `xu._.i()` → `xu.______.a()` → `MMKV.getString`). Its default
is an empty string. No universal encrypted secret was found in the APK.

The native `handler_url` at `0x9c92c` does the following:

1. Returns the original URL if its existing `rand` parameter matches the
   native regex `[?|&]rand=(.*?)&` after appending a temporary `&` to the search
   input. Even an explicitly empty `rand=` is retained.
2. Extracts nonempty `time` and `version` with equivalent raw-URL regexes.
   It does not percent-decode these values. If either is missing or empty,
   the URL is returned unchanged.
3. Computes the digest below and appends `&rand=<digest>` to the original URL.

```text
secret = RC4(key = JNI_MUTF8(uid), data = StandardBase64Decode(net_param_sk))
secret = secret up to its first NUL byte

rand = SHA1hex(
    ASCII(SHA1hex(JNI_MUTF8(nduss)))
    || JNI_MUTF8(uid)
    || secret
    || raw_MUTF8_URL_capture(time)
    || JNI_MUTF8(deviceID)
    || raw_MUTF8_URL_capture(version)
    || ASCII("ae5821440fab5e1a61a025f014bd8972")
)
```

The fixed suffix is 31 characters. SHA-1 output is 40 lowercase hexadecimal
characters. `get_sha1` is at `0x90f1c`; `get_sk` is at `0x9c6ac`.
The ARM32 Thumb `get_sk` at `0x269ec` corroborates the Base64/RC4 operation.
`get_url_parameters` exists at `0x910f8`, but is not called by this handler.
The active path neither sorts all URL parameters nor adds a generic `sign`
field, contrary to the report's model.

The app's `time` source is epoch **milliseconds**. In `classes12.dex`,
`pu._____.__()` normally uses `System.currentTimeMillis()` and can use an
HTTP-Date-derived server offset plus elapsed realtime. The Go integration
uses local epoch milliseconds and preserves a supplied request time.

## SDK get_rand: separately verified calculation

`libnetdisk-security-rand.so` exports `get_rand` at `0x149540`. Its six string
arguments, in JNI declaration order, feed:

```text
SHA1hex(
    ASCII(SHA1hex(JNI_MUTF8(argument5)))
    || JNI_MUTF8(argument6)
    || RC4Decode(key=argument6, encryptedSK=argument4)
    || JNI_MUTF8(argument3)
    || JNI_MUTF8(argument1)
    || JNI_MUTF8(argument2)
    || ASCII(MD5hex(first APK signing certificate DER))
)
```

This is a deterministic digest, not a 16-character random nonce.
`get_signature_md5` at `0x148290` reads
`PackageInfo.signatures[0].toByteArray()`. The inspected APK has one certificate
of 923 bytes; its MD5 is `8d46bdb64111ea036427cb485633aedd` and its SHA-256 is
`b75fd2b70084d7e0813b8f74dd74b62ab79b2aa0ce1372331a1841bd88eed993`.
`sk_encode` at `0x149148` also decrypts Base64/RC4 despite its name, caching the
result by the key and encrypted value.

`classes4.dex` contains the `RandAlgorithm.getRand` native declaration and a
lazy wrapper, but no active invocation was found in the inspected DEX files.
`ComputeAndroidSDKRand` therefore exposes the verified calculation separately.
Its positional argument labels mirror the equivalent legacy components;
the HTTP client uses the Java-invoked URLHandler path.

## Go integration

```go
signer, err := terabox.NewAndroidSigner(terabox.AndroidSigningConfig{
	DeviceID: androidDeviceID,
	UID: androidAccountUID,
	EncodedSK: netParamSK,
	Channel: androidChannel,
	UserAgent: capturedAndroidUserAgent,
})
if err != nil {
	return err
}
client := terabox.NewClient(ndus, terabox.WithAndroidSigner(signer))
```

These variables are runtime values from the relevant app/account configuration.
The channel is the app's `android_<release>_<model>_bd-dubox_<build-channel>`
value. It is required for HTTP integration. A pure `SignURL` calculation does
not require a channel. Version defaults to the inspected APK's `4.26.5`;
the optional captured UA is used only on signed API calls.

JSON API methods and chunk uploads supply `devuid`, `cuid`, `clienttype=1`,
channel, version, and millisecond time before invoking `SignURL`; the Web `web`
flag is removed. The digest uses NDUS from the request's actual Cookie header,
so concurrent cookie refresh cannot make the digest disagree with that header.
A request explicitly omitting cookies is signed with an empty NDUS.

The APK interceptor's proven exclusion is an exact `passport` path segment.
Go also keeps HTML token-page refresh on its existing Web path as an
interoperability choice, not an APK-discovered URL allowlist. Existing Web
requests are unchanged unless a signer is enabled. This option adds the native
signature component; it does not replace all Web endpoints with native Android
endpoints or rewrite the existing Web passport registration protocol.

`SetAndroidSigner(newSigner)` updates the profile when UID or `net_param_sk`
changes. Passing nil disables it. Signers are immutable and safe to share.
`SignURL` preserves existing `rand` values like the native implementation.

Go inputs must be valid UTF-8. JNI Modified UTF-8 handling reproduces NUL as
`C0 80` and supplementary characters as separately encoded UTF-16 surrogates.
The native decoder truncates plaintext at NUL and has a 256-byte output buffer;
the Go decoder rejects ciphertext over 255 decoded bytes to keep that buffer
model terminated. Long RC4 keys use the first 256 bytes, matching the native
256-round key scheduler. Java unpaired-surrogate inputs are recorded by the
oracle but cannot be expressed by this valid-UTF-8 Go API.

## Reproducible verification

`testdata/android_signature_vectors.json` records the native/reference results,
input bytes, APK/library hashes, certificate fingerprint, and emulator stub
scope. The script executes native `get_rand`, certificate MD5, SHA-1, and RC4;
JNI access, C++ string/stream operations, libc memory operations, BIO Base64,
and hexadecimal formatting are modeled by explicit stubs.

SDK vectors execute the original SDK function. Legacy vectors execute that
same native digest path with the certificate suffix replaced by the legacy
constant; they verify the equivalent preimage calculation, not execution of
`handler_url` itself. Legacy URL parsing and Java wiring were checked through
disassembly/DEX and dedicated Go tests.

To regenerate without contacting the service, use an analysis Python environment
with `pyelftools`, `unicorn`, and `androguard`:

```sh
py -3 tools/verify_android_signature.py --apk path/to/TeraBox_Android_web_v4.26.5.apk --output native-vectors.json
```

The native library hash is pinned; unsupported libraries fail before emulation.
The script does not install packages or contact the network. Ordinary Go tests
use the checked-in vectors and require no APK, emulator, Python, or live account.
Live server acceptance and device-attestation behavior have not been tested.
