"""Verify Android request-signing vectors using code from a supplied APK.

Dependencies: Python 3, pyelftools, unicorn, and androguard. This program does
not install dependencies or access the network. Use --dependency-path to point
at an existing isolated package directory when needed.
The checked fixture was generated with pyelftools 0.33, unicorn 2.1.4, and
androguard 4.1.4. Regeneration is an explicit local check, not a CI download.

Example:
    py -3 tools/verify_android_signature.py --apk TeraBox.apk \
        --output testdata/android_signature_vectors.json

The supported ARM64 library is pinned by SHA-256. JNI calls, C++ string/stream
operations, BIO Base64 plumbing, memory allocation, and hex formatting are
stubbed, together with libc memory helpers and OpenSSL buffer cleansing.
get_rand, get_signature_md5, sk_encode, MD5, SHA-1, and RC4 execute the
APK's actual AArch64 instructions. JNI strings are represented as Modified
UTF-8, including NUL and surrogate pairs.
"""
import argparse
import base64
import hashlib
import io
import importlib.metadata
import json
import struct
import sys
import zipfile
from pathlib import Path

def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--dependency-path", action="append", default=[], type=Path)
    return parser.parse_args()

args = parse_args() if __name__ == "__main__" else None
if args is not None:
    for package_path in args.dependency_path:
        sys.path.insert(0, str(package_path.resolve()))
try:
    import unicorn as uc
    from unicorn.arm64_const import *
    from elftools.elf.elffile import ELFFile
except ModuleNotFoundError as exc:
    raise SystemExit("Missing analysis dependency: " + str(exc) +
                     ". Install pyelftools and unicorn into your analysis environment.")

LIBRARY_MEMBER = "lib/arm64-v8a/libnetdisk-security-rand.so"
LIBRARY_SHA256 = "c4912d59811a46b0d9d52d2105dbe48a46ab7e92044a5a8f3cd7d72d875ffc13"

def modified_utf8(value):
    encoded = bytearray()
    raw = value.encode("utf-16-be", "surrogatepass")
    for at in range(0, len(raw), 2):
        code = (raw[at] << 8) | raw[at + 1]
        if code == 0:
            encoded.extend(b"\xc0\x80")
        elif code <= 0x7f:
            encoded.append(code)
        elif code <= 0x7ff:
            encoded.extend((0xc0 | (code >> 6), 0x80 | (code & 0x3f)))
        else:
            encoded.extend((0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f)))
    return bytes(encoded)

REGS = [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7,UC_ARM64_REG_X8]

class RandOracle:
    def __init__(self, library, cert_der, certificate_md5_override=None):
        self.cpu = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
        self.library = library
        self.cert_md5 = (certificate_md5_override or hashlib.md5(cert_der).hexdigest()).encode()
        self.bio_read_count = 0
        self.cert_der = cert_der
        self.methods = {}
        self.heap = 0x50000000
        self.streams = {}
        self.bios = {}
        self.trace = []
        self.cpu.mem_map(0, 0x400000)
        self.cpu.mem_map(0x40000000, 0x10000)
        self.cpu.mem_map(0x41000000, 0x1000)
        self.cpu.mem_map(0x50000000, 0x1000000)
        self.cpu.mem_map(0x60000000, 0x10000)
        self.cpu.mem_map(0x70000000, 0x100000)
        self.cpu.reg_write(UC_ARM64_REG_TPIDR_EL0, 0x60000000)
        self.symbols = {}
        self.plt = {}
        with io.BytesIO(self.library) as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg.header.p_type == 'PT_LOAD':
                    self.cpu.mem_write(seg.header.p_vaddr, seg.data())
            dynsym = elf.get_section_by_name('.dynsym')
            self.symbols = {s.name: s.entry.st_value for s in dynsym.iter_symbols()}
            for relocation in elf.get_section_by_name('.rela.dyn').iter_relocations():
                e = relocation.entry
                value = e.r_addend
                if e.r_info_type in [257, 1025]:
                    value += dynsym.get_symbol(e.r_info_sym).entry.st_value
                if e.r_info_type in [257, 1025, 1027]:
                    self.cpu.mem_write(e.r_offset, struct.pack('<Q', value))
            pltbase = elf.get_section_by_name('.plt').header.sh_addr + 0x20
            self.plt = {pltbase + i*16: dynsym.get_symbol(r.entry.r_info_sym).name for i,r in enumerate(elf.get_section_by_name('.rela.plt').iter_relocations())}
        self.jni = 0x40000000
        self.table = 0x40001000
        self.cpu.mem_write(self.jni, struct.pack('<Q',self.table))
        self.callbacks = {0x40002000:'get_utf',0x40002010:'release_utf',0x40002020:'new_utf'}
        for offset, address in [(0x548,0x40002000),(0x550,0x40002010),(0x538,0x40002020)]:
            self.cpu.mem_write(self.table+offset, struct.pack('<Q',address))
        if cert_der is not None:
            self.cert_pointer=self.alloc(cert_der)
            for i,(offset,action) in enumerate([(0xf8,'class'),(0x108,'method'),(0xb8,'delete_ref'),(0x2f0,'field_id'),(0x2f8,'field'),(0x568,'array_element'),(0x5c0,'array_bytes'),(0x558,'array_length'),(0x600,'release_array')]):
                address=0x40002200+i*16
                self.callbacks[address]=action
                self.cpu.mem_write(self.table+offset,struct.pack('<Q',address))
            self.facet=self.alloc(struct.pack('<Q',0x40005000))
            self.cpu.mem_write(0x40005038,struct.pack('<Q',0x40002400))
            self.callbacks[0x40002400]='widen'
        self.cpu.hook_add(uc.UC_HOOK_CODE,self.hook)
        self.cpu.hook_add(uc.UC_HOOK_MEM_INVALID,self.invalid)

    def alloc(self, data_or_size):
        data = data_or_size if isinstance(data_or_size, bytes) else bytes(data_or_size)
        address = self.heap
        self.heap += ((len(data)+15)//16)*16 + 16
        self.cpu.mem_write(address, data)
        return address

    def cstr(self, address):
        result = bytearray()
        while True:
            b = bytes(self.cpu.mem_read(address+len(result),1))
            if b == b'\0': return bytes(result)
            result += b

    def string(self,address):
        obj = bytes(self.cpu.mem_read(address,24))
        if obj[0]&1:
            _,size,pointer = struct.unpack('<QQQ',obj)
            return bytes(self.cpu.mem_read(pointer,size))
        return obj[1:1+(obj[0]>>1)]

    def set_string(self,address,data):
        if len(data)<=22:
            obj=bytes([len(data)*2])+data+b'\0'
            self.cpu.mem_write(address,obj.ljust(24,b'\0'))
        else:
            pointer=self.alloc(data+b'\0')
            cap=(len(data)+16)&~15
            self.cpu.mem_write(address,struct.pack('<QQQ',cap|1,len(data),pointer))

    def ret(self,value=None):
        if value is not None: self.cpu.reg_write(UC_ARM64_REG_X0,value)
        self.cpu.reg_write(UC_ARM64_REG_PC,self.cpu.reg_read(UC_ARM64_REG_LR))

    def invalid(self,cpu,access,address,size,value,userdata):
        print('INVALID',access,hex(address),'pc',hex(cpu.reg_read(UC_ARM64_REG_PC)))
        return False

    def hook(self,cpu,address,size,userdata):
        args=[cpu.reg_read(r) for r in REGS]
        if address==0x41000000:
            cpu.emu_stop(); return
        if address in self.callbacks:
            action=self.callbacks[address]
            if action=='get_utf': self.ret(args[1])
            elif action=='release_utf': self.ret()
            elif action=='new_utf':
                self.output=self.cstr(args[1]); self.ret(self.alloc(self.output+b'\0'))
            elif action=='method':
                method=self.cstr(args[2]).decode(); handle=self.alloc(16); self.methods[handle]=method; self.ret(handle)
            elif action=='array_bytes': self.ret(self.cert_pointer)
            elif action=='array_length': self.ret(len(self.cert_der))
            elif action=='widen': self.ret(args[1])
            elif action in ['delete_ref','release_array']:self.ret()
            else:self.ret(self.alloc(16))
            return
        if address==0x149c34:
            self.streams.setdefault(args[0],bytearray()).extend(bytes(cpu.mem_read(args[1],args[2])))
            self.ret(args[0]); return
        if address==0x148d24:
            cpu.mem_write(args[0],f'{args[3]&255:02x}'.encode()+b'\0'); self.ret(2); return
        name=self.plt.get(address)
        if not name: return
        if name=='_ZN7netdisk17get_signature_md5EP7_JNIEnvP8_jobject':
            if self.cert_der is not None:cpu.reg_write(UC_ARM64_REG_PC,self.symbols[name]);return
            self.set_string(args[8],self.cert_md5); self.trace.append({'cert_md5':self.cert_md5.decode()}); self.ret(); return
        if name=='_ZN7_JNIEnv16CallObjectMethodEP8_jobjectP10_jmethodIDz':
            method=self.methods[args[2]]
            self.trace.append({'jni_method':method,'arg3':args[3]})
            if method=='getPackageName':self.ret(self.alloc(b'com.dubox.drive\0'))
            else:self.ret(self.alloc(16))
            return
        if name=='_ZNKSt6__ndk18ios_base6getlocEv':self.ret();return
        if name=='_ZNKSt6__ndk16locale9use_facetERNS0_2idE':self.ret(self.facet);return
        if name=='_ZNSt6__ndk16localeD1Ev':self.ret();return
        if name=='_ZNSt6__ndk113basic_ostreamIcNS_11char_traitsIcEEElsEi':
            self.streams.setdefault(args[0],bytearray()).extend(f'{args[1]&255:02x}'.encode());self.ret(args[0]);return
        if name=='_ZNKSt6__ndk115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv':
            data=bytes(self.streams.get(args[0]-8,b''))
            self.set_string(args[8],data); self.ret(); return
        if name=='_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_':
            self.set_string(args[0],self.string(args[1])); self.ret(args[0]); return
        if name=='strlen': self.ret(len(self.cstr(args[0]))); return
        if name in ['_Znwm','malloc']: self.ret(self.alloc(args[0])); return
        if name in ['memcpy','memmove']:
            cpu.mem_write(args[0],bytes(cpu.mem_read(args[1],args[2]))); self.ret(args[0]); return
        if name=='memset':
            cpu.mem_write(args[0],bytes([args[1]&255])*args[2]); self.ret(args[0]); return
        if name=='OPENSSL_cleanse':
            cpu.mem_write(args[0],bytes(args[1])); self.ret(); return
        if name=='strcmp':
            a,b=self.cstr(args[0]),self.cstr(args[1]); self.ret(0 if a==b else 1); return
        if name=='_ZNSt6__ndk115basic_streambufIcNS_11char_traitsIcEEEC2Ev':
            self.streams.pop(args[0]-8,None);self.ret();return
        if name in ['_ZdlPv','free','BIO_free_all','BIO_set_flags'] or ('St6__ndk1' in name and ('ios_base4init' in name or 'basic_streambuf' in name or 'D2Ev' in name)):
            self.ret(); return
        if name=='BIO_f_base64': self.ret(1); return
        if name=='BIO_new':
            self.ret(self.alloc(16)); return
        if name=='BIO_new_mem_buf':
            handle=self.alloc(16); self.bios[handle]=bytes(cpu.mem_read(args[0],args[1])); self.ret(handle); return
        if name=='BIO_push':
            self.bios[args[0]]=self.bios[args[1]]; self.ret(args[0]); return
        if name=='BIO_read':
            self.bio_read_count += 1
            decoded=base64.b64decode(self.bios[args[0]])[:args[2]]; cpu.mem_write(args[1],decoded); self.ret(len(decoded)); return
        if name in ['_ZN7netdisk8get_sha1ERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE','_ZN7netdisk9sk_encodeERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES8_','SHA1_Init','SHA1_Update','SHA1_Final','MD5','MD5_Init','MD5_Update','MD5_Final','RC4_set_key','RC4','md5_block_data_order']:
            if name.startswith('_ZN7netdisk8get_sha1'): self.trace.append({'sha1_input_hex':self.string(args[0]).hex()})
            if name.startswith('_ZN7netdisk9sk_encode'): self.trace.append({'rc4_key_hex':self.string(args[0]).hex(),'base64_cipher':self.string(args[1]).decode('ascii')})
            cpu.reg_write(UC_ARM64_REG_PC,self.symbols[name]); return
        raise RuntimeError(f'Unhandled PLT: {address:#x} {name}')

    def run(self,values):
        sp=0x700ff000
        self.output=None
        pointers=[self.alloc(modified_utf8(v)+b'\0') for v in values]
        for r,v in zip(REGS,[self.jni,0,0x40003000]+pointers[:5]): self.cpu.reg_write(r,v)
        self.cpu.mem_write(sp,struct.pack('<Q',pointers[5]))
        self.cpu.reg_write(UC_ARM64_REG_SP,sp)
        self.cpu.reg_write(UC_ARM64_REG_LR,0x41000000)
        try:
            self.cpu.emu_start(self.symbols['_ZN7netdisk8get_randEP7_JNIEnvP7_jclassP8_jobjectP8_jstringS7_S7_S7_S7_S7_'],0x41000000,count=5000000)
        except uc.UcError:
            pc=self.cpu.reg_read(UC_ARM64_REG_PC)
            print('ERROR PC',hex(pc),'TRACE',self.trace)
            print('ERROR OPCODES',bytes(self.cpu.mem_read(pc,32)).hex())
            raise
        if self.cpu.reg_read(UC_ARM64_REG_PC)!=0x41000000 or self.output is None:
            raise RuntimeError('Native get_rand did not finish within its instruction limit')
        return self.output.decode()

    def run_sk(self,key,cipher):
        key_obj=self.alloc(24);cipher_obj=self.alloc(24);output_obj=self.alloc(24)
        self.set_string(key_obj,modified_utf8(key));self.set_string(cipher_obj,cipher.encode('ascii'))
        self.cpu.reg_write(UC_ARM64_REG_X0,key_obj);self.cpu.reg_write(UC_ARM64_REG_X1,cipher_obj);self.cpu.reg_write(UC_ARM64_REG_X8,output_obj)
        self.cpu.reg_write(UC_ARM64_REG_SP,0x700ff000);self.cpu.reg_write(UC_ARM64_REG_LR,0x41000000)
        self.cpu.emu_start(self.symbols['_ZN7netdisk9sk_encodeERKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEES8_'],0x41000000,count=5000000)
        if self.cpu.reg_read(UC_ARM64_REG_PC)!=0x41000000:
            raise RuntimeError('Native sk_encode did not finish within its instruction limit')
        return self.string(output_obj)

def rc4(key, data):
    state=list(range(256));j=0
    for i in range(256):
        j=(j+state[i]+key[i%len(key)])%256;state[i],state[j]=state[j],state[i]
    result=bytearray();i=j=0
    for value in data:
        i=(i+1)%256;j=(j+state[i])%256;state[i],state[j]=state[j],state[i]
        result.append(value^state[(state[i]+state[j])%256])
    return bytes(result)


def reference_rand(fields):
    key = modified_utf8(fields["UID"])
    secret = rc4(key, base64.b64decode(fields["EncodedSK"])).split(b"\0", 1)[0]
    inner = hashlib.sha1(modified_utf8(fields["NDUS"])).hexdigest().encode("ascii")
    outer = inner + key + secret
    for name in ("Time", "DeviceID", "Version"):
        outer += modified_utf8(fields[name])
    outer += fields.get("LegacySuffix", fields["CertificateMD5"]).encode("ascii")
    return hashlib.sha1(outer).hexdigest(), outer

def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()

def main(arguments):
    try:
        from androguard.core.apk import APK
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing analysis dependency: " + str(exc) +
                         ". Install androguard into your analysis environment.")
    with zipfile.ZipFile(arguments.apk) as archive:
        library = archive.read(LIBRARY_MEMBER)
    library_hash = hashlib.sha256(library).hexdigest()
    if library_hash != LIBRARY_SHA256:
        raise SystemExit("Unsupported native library hash: " + library_hash)
    certificates = APK(str(arguments.apk), skip_analysis=True).get_certificates_der_v2()
    if len(certificates) != 1:
        raise SystemExit("Expected one APK v2 signing certificate.")
    certificate = certificates[0]
    certificate_md5 = hashlib.md5(certificate).hexdigest()
    names = ("DeviceID", "Version", "Time", "EncodedSK", "NDUS", "UID")
    base = {
        "DeviceID": "device-id-123", "Version": "4.26.5",
        "Time": "1700000000123", "NDUS": "ndus-ascii", "UID": "12345",
    }
    specs = [
        ("ascii", {}, b"secret-signing-key"),
        ("percent-characters", {"DeviceID": "device%2F+id", "NDUS": "token%2B+%3D&x=1"}, b"secret-signing-key"),
        ("unicode", {"DeviceID": "device-日本語", "NDUS": "セッション😀", "UID": "uid-日本"}, b"android-sk"),
        ("modified-utf8-nul", {"DeviceID": "device\0id", "NDUS": "ndus\0tail", "UID": "u\0id"}, b"android-sk"),
        ("supplementary", {"NDUS": "ndus-😀", "UID": "uid-😀"}, b"android-sk"),
        ("long-uid", {"UID": "uid-" + "x" * 300}, b"android-sk"),
        ("unpaired-surrogate", {"NDUS": "ndus-\ud83d"}, b"secret-signing-key"),
        ("decrypted-secret-nul", {}, b"abc\0tail"),
        ("decrypted-secret-leading-nul", {}, b"\0tail"),
        ("empty-ndus", {"NDUS": ""}, b"secret-signing-key"),
        ("cache-initial", {}, b"cache-secret-one"),
        ("cache-same-key-and-cipher", {"Time": "1700000000124"}, b"cache-secret-one"),
        ("cache-cipher-rotation", {"Time": "1700000000125"}, b"cache-secret-two"),
        ("cache-key-rotation", {"Time": "1700000000126", "UID": "54321"}, b"cache-secret-two"),
    ]
    vectors = []
    legacy_suffix = "ae5821440fab5e1a61a025f014bd8972"
    for algorithm in ("sdk", "legacy"):
        cert_input = certificate if algorithm == "sdk" else None
        suffix_override = None if algorithm == "sdk" else legacy_suffix
        shared_oracle = RandOracle(library, cert_input, suffix_override)
        for name, overrides, secret in specs:
            fields = {**base, **overrides}
            key = modified_utf8(fields["UID"])
            fields["EncodedSK"] = base64.b64encode(rc4(key, secret)).decode("ascii")
            fields["CertificateMD5"] = certificate_md5 if algorithm == "sdk" else ""
            if algorithm == "legacy":
                fields["LegacySuffix"] = legacy_suffix
            is_cached = name.startswith("cache-")
            oracle = shared_oracle if is_cached else RandOracle(library, cert_input, suffix_override)
            reads_before = oracle.bio_read_count
            native = oracle.run([fields[field] for field in names])
            expected, outer = reference_rand(fields)
            if native != expected:
                raise AssertionError("Native/reference mismatch: " + algorithm + ":" + name)
            cache_hit = is_cached and name == "cache-same-key-and-cipher"
            reads = oracle.bio_read_count - reads_before
            if reads != (0 if cache_hit else 1):
                raise AssertionError("Unexpected native cache behavior: " + algorithm + ":" + name)
            vectors.append({
                "Name": name, "Algorithm": algorithm, **fields,
                "ExpectedRand": native, "ExpectedRawSHA1InputHex": outer.hex(),
                "NativeBIOReadCount": reads,
                "NativeContext": "cache-sequence" if is_cached else "fresh",
            })
    sk_specs = [
        ("rc4-known-key", "Key", "u/MW6NlArwrT", b"Plaintext"),
        ("rc4-known-wiki", "Wiki", "ECG/BCA=", b"pedia"),
        ("rc4-known-secret", "Secret", "RaAfZF/DWzg1UlRLm/U=", b"Attack at dawn"),
        ("plaintext-nul", "key", "ag5X7VDuEiY=", b"abc"),
        ("plaintext-leading-nul", "key", "CxhVhEg=", b""),
        ("modified-utf8-key-nul", "u\0id", "dPvaEOTX1mgHwg==", b"android-sk"),
        ("unicode-key", "uid-日本", "8kMtZYPVESn0tQ==", b"android-sk"),
        ("supplementary-key", "uid-😀", "1WrpSqIrZ/IxRA==", b"android-sk"),
    ]
    sk_vectors = []
    for name, uid, encoded, expected in sk_specs:
        actual = RandOracle(library, certificate).run_sk(uid, encoded)
        if actual != expected:
            raise AssertionError("Native SK mismatch: " + name)
        sk_vectors.append({
            "Name": name, "UID": uid, "UIDModifiedUTF8Hex": modified_utf8(uid).hex(),
            "EncodedSK": encoded, "ExpectedSKHex": actual.hex(),
        })
    result = {
        "Provenance": {
            "APKName": arguments.apk.name, "APKSHA256": file_sha256(arguments.apk),
            "LibraryMember": LIBRARY_MEMBER, "LibrarySHA256": library_hash,
            "SigningCertificateDERBytes": len(certificate),
            "CertificateMD5": certificate_md5,
            "CertificateSHA256": hashlib.sha256(certificate).hexdigest(),
            "NativeFunctions": {"get_rand": "0x149540", "get_signature_md5": "0x148290", "get_sha1": "0x148bec", "sk_encode": "0x149148"},
            "Emulator": "Unicorn AArch64",
            "RuntimeDependencies": {name: importlib.metadata.version(name) for name in ("unicorn", "pyelftools", "androguard")},
            "NativeExecution": ["get_rand", "get_signature_md5", "sk_encode", "MD5", "SHA1", "RC4"],
            "Stubs": ["JNI package/signature lookup and Modified UTF-8 strings", "C++ allocation/string/stream plumbing", "BIO Base64 wrapper", "libc memory operations", "OpenSSL temporary-buffer cleansing", "lowercase hexadecimal formatting"],
            "EncodingNote": "Unpaired Java UTF-16 surrogates are retained by JNI Modified UTF-8. Go strings with malformed UTF-8 and Go JSON decoding do not preserve such surrogates identically; unpaired-surrogate is an oracle-only boundary case.",
            "HashPolicy": "Only the ARM64 native library hash is pinned. APK and certificate hashes describe the supplied input and are not required to match a fixed whole-APK snapshot.",
            "InputMeaning": {"DeviceID": "getRand argument 1", "Version": "argument 2", "Time": "argument 3", "EncodedSK": "argument 4", "NDUS": "argument 5", "UID": "argument 6"},
            "SDKCallerStatus": "Native positional ordering is verified. A live Java caller for the SDK getRand declaration was not found in this APK; field labels mirror equivalent legacy inputs.",
            "LegacySuffix": legacy_suffix,
            "LegacyNote": "Legacy vectors execute SDK get_rand with get_signature_md5 stubbed to the libdubox handler_url fixed suffix. They do not execute the legacy URL handler and do not verify its URL parsing or caller wiring.",
        },
        "Vectors": vectors,
        "SKVectors": sk_vectors,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print("Verified", len(vectors), "signing vectors (SDK and legacy-suffix substitution) and", len(sk_vectors), "native SK vectors.")
    print("Fixture written to", arguments.output)

if __name__ == "__main__":
    main(args)
