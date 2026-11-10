// Signature verification with fixed public keys: the signature bytes and the message both
// come from the input. Covers the discrete-log verifiers (DSA, ECDSA, ECNR), Ed25519 and RSA.
#include "cryptlib.h"
#include "rsa.h"
#include "pssr.h"
#include "dsa.h"
#include "eccrypto.h"
#include "ecp.h"
#include "oids.h"
#include "xed25519.h"
#include "sha.h"
#include "rng.h"

#include <cstdint>
#include <memory>

using namespace CryptoPP;

static std::unique_ptr<PK_Verifier> g_verifiers[7];

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    LC_RNG rng(2024);
    {
        ECDSA<ECP, SHA256>::PrivateKey k;
        k.Initialize(rng, ASN1::secp256r1());
        ECDSA<ECP, SHA256>::PublicKey pk;
        k.MakePublicKey(pk);
        g_verifiers[0].reset(new ECDSA<ECP, SHA256>::Verifier(pk));
    }
    {
        ECNR<ECP, SHA256>::PrivateKey k;
        k.Initialize(rng, ASN1::secp256r1());
        ECNR<ECP, SHA256>::PublicKey pk;
        k.MakePublicKey(pk);
        g_verifiers[1].reset(new ECNR<ECP, SHA256>::Verifier(pk));
    }
    {
        byte seed[32];
        rng.GenerateBlock(seed, sizeof(seed));
        ed25519::Signer signer(seed);
        g_verifiers[2].reset(new ed25519::Verifier(signer));
    }
    {
        RSA::PrivateKey k;
        k.GenerateRandomWithKeySize(rng, 1024);
        RSA::PublicKey pk(k);
        g_verifiers[3].reset(new RSASS<PKCS1v15, SHA256>::Verifier(pk));
        g_verifiers[4].reset(new RSASS<PSS, SHA256>::Verifier(pk));
    }
    {
        DSA::PrivateKey k;
        k.GenerateRandomWithKeySize(rng, 1024);
        DSA::PublicKey pk;
        k.MakePublicKey(pk);
        g_verifiers[5].reset(new DSA::Verifier(pk));
    }
    {
        ECDSA<ECP, SHA1>::PrivateKey k;
        k.Initialize(rng, ASN1::secp192r1());
        ECDSA<ECP, SHA1>::PublicKey pk;
        k.MakePublicKey(pk);
        g_verifiers[6].reset(new ECDSA<ECP, SHA1>::Verifier(pk));
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    PK_Verifier &v = *g_verifiers[data[0] % 7];
    const size_t siglen = data[1];
    data += 2;
    size -= 2;
    if (siglen > size) return -1;
    try {
        (void)v.VerifyMessage(data + siglen, size - siglen, data, siglen);
    } catch (const CryptoPP::Exception &) {
        return -1;
    }
    return 0;
}
