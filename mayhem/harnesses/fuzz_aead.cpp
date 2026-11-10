// Authenticated and plain symmetric modes: encrypt the input's plaintext under an input-derived
// key/IV, decrypt it back (must match), then decrypt the raw input bytes as an arbitrary
// ciphertext (must be rejected or decrypt without a memory error).
#include "cryptlib.h"
#include "filters.h"
#include "aes.h"
#include "camellia.h"
#include "aria.h"
#include "sm4.h"
#include "gcm.h"
#include "ccm.h"
#include "eax.h"
#include "chachapoly.h"
#include "chacha.h"
#include "salsa.h"
#include "modes.h"
#include "secblock.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

using namespace CryptoPP;

struct Reader {
    const uint8_t *p;
    size_t n;
    bool take(byte *dst, size_t len) {
        if (n < len) return false;
        std::memcpy(dst, p, len);
        p += len;
        n -= len;
        return true;
    }
};

template <class E, class D>
static int Aead(Reader r, size_t keylen, size_t ivlen) {
    byte key[64], iv[32];
    if (!r.take(key, keylen) || !r.take(iv, ivlen)) return -1;
    const std::string pt(reinterpret_cast<const char *>(r.p), r.n);
    std::string ct, back;
    E enc;
    enc.SetKeyWithIV(key, keylen, iv, ivlen);
    StringSource(pt, true, new AuthenticatedEncryptionFilter(enc, new StringSink(ct)));
    D dec;
    dec.SetKeyWithIV(key, keylen, iv, ivlen);
    StringSource(ct, true, new AuthenticatedDecryptionFilter(dec, new StringSink(back)));
    if (back != pt) abort();
    try {
        D dec2;
        dec2.SetKeyWithIV(key, keylen, iv, ivlen);
        std::string junk;
        StringSource(pt, true, new AuthenticatedDecryptionFilter(dec2, new StringSink(junk)));
    } catch (const CryptoPP::Exception &) {
    }
    return 0;
}

template <class E, class D>
static int Plain(Reader r, size_t keylen, size_t ivlen) {
    byte key[64], iv[32];
    if (!r.take(key, keylen) || !r.take(iv, ivlen)) return -1;
    const std::string pt(reinterpret_cast<const char *>(r.p), r.n);
    std::string ct, back;
    E enc;
    enc.SetKeyWithIV(key, keylen, iv, ivlen);
    StringSource(pt, true, new StreamTransformationFilter(enc, new StringSink(ct)));
    D dec;
    dec.SetKeyWithIV(key, keylen, iv, ivlen);
    StringSource(ct, true, new StreamTransformationFilter(dec, new StringSink(back)));
    if (back != pt) abort();
    try {
        D dec2;
        dec2.SetKeyWithIV(key, keylen, iv, ivlen);
        std::string junk;
        StringSource(pt, true, new StreamTransformationFilter(dec2, new StringSink(junk)));
    } catch (const CryptoPP::Exception &) {
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    Reader r = {data + 1, size - 1};
    try {
        switch (data[0] % 16) {
        case 0: return Aead<GCM<AES>::Encryption, GCM<AES>::Decryption>(r, 16, 12);
        case 1: return Aead<GCM<AES>::Encryption, GCM<AES>::Decryption>(r, 32, 16);
        case 2: return Aead<EAX<AES>::Encryption, EAX<AES>::Decryption>(r, 16, 16);
        case 3: return Aead<GCM<ARIA>::Encryption, GCM<ARIA>::Decryption>(r, 16, 12);
        case 4: return Aead<ChaCha20Poly1305::Encryption, ChaCha20Poly1305::Decryption>(r, 32, 12);
        case 5: return Aead<XChaCha20Poly1305::Encryption, XChaCha20Poly1305::Decryption>(r, 32, 24);
        case 6: return Aead<GCM<Camellia>::Encryption, GCM<Camellia>::Decryption>(r, 16, 12);
        case 7: return Aead<EAX<ARIA>::Encryption, EAX<ARIA>::Decryption>(r, 16, 16);
        case 8: return Plain<CBC_Mode<AES>::Encryption, CBC_Mode<AES>::Decryption>(r, 16, 16);
        case 9: return Plain<CTR_Mode<AES>::Encryption, CTR_Mode<AES>::Decryption>(r, 32, 16);
        case 10: return Plain<CFB_Mode<AES>::Encryption, CFB_Mode<AES>::Decryption>(r, 24, 16);
        case 11: return Plain<OFB_Mode<SM4>::Encryption, OFB_Mode<SM4>::Decryption>(r, 16, 16);
        case 12: return Plain<ChaCha::Encryption, ChaCha::Decryption>(r, 32, 12);
        case 13: return Plain<Salsa20::Encryption, Salsa20::Decryption>(r, 32, 8);
        case 14: return Plain<XSalsa20::Encryption, XSalsa20::Decryption>(r, 32, 24);
        default: return Plain<CBC_CTS_Mode<AES>::Encryption, CBC_CTS_Mode<AES>::Decryption>(r, 16, 16);
        }
    } catch (const CryptoPP::Exception &) {
        return -1;
    }
}
