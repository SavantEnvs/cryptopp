// RSA padding schemes (OAEP, PKCS#1 v1.5 encryption and signatures, PSS) over keys whose
// modulus size comes from the input, including very small moduli.
#include "cryptlib.h"
#include "rsa.h"
#include "oaep.h"
#include "pssr.h"
#include "sha.h"
#include "rng.h"
#include "secblock.h"

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>

using namespace CryptoPP;

// Keys are a pure function of the modulus size (fixed seed), so caching them across inputs
// keeps each input's result dependent only on that input.
static const InvertibleRSAFunction &KeyFor(unsigned bits) {
    static std::map<unsigned, std::unique_ptr<InvertibleRSAFunction> > cache;
    std::unique_ptr<InvertibleRSAFunction> &slot = cache[bits];
    if (!slot) {
        LC_RNG rng(bits);
        slot.reset(new InvertibleRSAFunction);
        slot->Initialize(rng, bits, 17);
    }
    return *slot;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return -1;
    const unsigned mode = data[0] % 8;
    // OAEP_Base::Unpad() overruns its buffer when the modulus is shorter than the hash (upstream does not
    // reject such keys on Decrypt), so OAEP decryption only runs with moduli that fit SHA-256's 2*hLen+2.
    const unsigned minBits = (mode == 3 || mode == 4) ? 8 * (2 * 32 + 2) : 16;
    const unsigned bits = minBits + (data[1] % 100) * 8;
    data += 2;
    size -= 2;
    const InvertibleRSAFunction &priv = KeyFor(bits);
    RSAFunction pub(priv);
    LC_RNG rng(7);
    try {
        switch (mode) {
        case 0:
        case 1:
        case 2: {
            RSAES<OAEP<SHA1> >::Encryptor enc(pub);
            RSAES<OAEP<SHA256> >::Encryptor enc256(pub);
            RSAES<PKCS1v15>::Encryptor encp(pub);
            PK_Encryptor &e = mode == 0 ? static_cast<PK_Encryptor &>(enc)
                            : mode == 1 ? static_cast<PK_Encryptor &>(enc256)
                                        : static_cast<PK_Encryptor &>(encp);
            SecByteBlock ct(e.CiphertextLength(size));
            e.Encrypt(rng, data, size, ct);
            break;
        }
        case 3:
        case 4:
        case 5: {
            RSAES<OAEP<SHA1> >::Decryptor dec(priv);
            RSAES<OAEP<SHA256> >::Decryptor dec256(priv);
            RSAES<PKCS1v15>::Decryptor decp(priv);
            PK_Decryptor &d = mode == 3 ? static_cast<PK_Decryptor &>(dec)
                            : mode == 4 ? static_cast<PK_Decryptor &>(dec256)
                                        : static_cast<PK_Decryptor &>(decp);
            // Decrypt() requires exactly FixedCiphertextLength() bytes (PK_FixedLengthDecryptor contract).
            SecByteBlock ct(d.FixedCiphertextLength());
            std::memset(ct, 0, ct.size());
            std::memcpy(ct, data, size < ct.size() ? size : ct.size());
            SecByteBlock pt(d.MaxPlaintextLength(ct.size()));
            d.Decrypt(rng, ct, ct.size(), pt);
            break;
        }
        case 6: {
            RSASS<PSS, SHA256>::Signer s(priv);
            SecByteBlock sig(s.SignatureLength());
            s.SignMessage(rng, data, size, sig);
            break;
        }
        default: {
            RSASS<PKCS1v15, SHA256>::Signer s(priv);
            SecByteBlock sig(s.SignatureLength());
            s.SignMessage(rng, data, size, sig);
            break;
        }
        }
    } catch (const CryptoPP::Exception &) {
        return -1;
    }
    return 0;
}
