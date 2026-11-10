// Elliptic-curve decoding and agreement with attacker-chosen peer data: point decoding on
// several curves, ECDH/X25519 agreement, and ECIES decryption of an arbitrary ciphertext.
#include "cryptlib.h"
#include "eccrypto.h"
#include "ecp.h"
#include "oids.h"
#include "xed25519.h"
#include "rng.h"
#include "sha.h"
#include "secblock.h"

#include <cstdint>
#include <cstring>
#include <memory>

using namespace CryptoPP;

struct CurveState {
    DL_GroupParameters_EC<ECP> params;
    SecByteBlock priv;
};
static std::unique_ptr<CurveState> g_curves[4];
static const OID g_oids[4] = {ASN1::secp256r1(), ASN1::secp256k1(), ASN1::secp384r1(), ASN1::brainpoolP256r1()};
static std::unique_ptr<ECIES<ECP>::Decryptor> g_ecies;
static byte g_xpriv[32];

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    LC_RNG rng(99);
    for (int i = 0; i < 4; i++) {
        g_curves[i].reset(new CurveState);
        g_curves[i]->params.Initialize(g_oids[i]);
        ECDH<ECP>::Domain dh(g_curves[i]->params);
        g_curves[i]->priv.New(dh.PrivateKeyLength());
        SecByteBlock pub(dh.PublicKeyLength());
        dh.GenerateKeyPair(rng, g_curves[i]->priv, pub);
    }
    g_ecies.reset(new ECIES<ECP>::Decryptor(rng, ASN1::secp256r1()));
    rng.GenerateBlock(g_xpriv, sizeof(g_xpriv));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    const unsigned mode = data[0] % 10;
    data++;
    size--;
    LC_RNG rng(5);
    try {
        if (mode < 4) {
            CurveState &c = *g_curves[mode];
            ECDH<ECP>::Domain dh(c.params);
            SecByteBlock shared(dh.AgreedValueLength());
            // Agree() reads exactly PublicKeyLength() bytes of the peer key (API contract).
            SecByteBlock peer(dh.PublicKeyLength());
            std::memset(peer, 0, peer.size());
            std::memcpy(peer, data, size < peer.size() ? size : peer.size());
            (void)dh.Agree(shared, c.priv, peer, true);
            (void)dh.Agree(shared, c.priv, peer, false);
        } else if (mode < 8) {
            CurveState &c = *g_curves[mode - 4];
            ECP::Point P;
            if (!c.params.GetCurve().DecodePoint(P, data, size)) return -1;
            (void)c.params.GetCurve().Multiply(Integer(3), P);
            (void)c.params.GetCurve().VerifyPoint(P);
            (void)c.params.GetCurve().Add(P, c.params.GetSubgroupGenerator());
        } else if (mode == 8) {
            x25519 x(g_xpriv);
            byte pub[32] = {0}, shared[32];
            std::memcpy(pub, data, size < 32 ? size : 32);
            (void)x.Agree(shared, g_xpriv, pub, true);
            (void)x.Agree(shared, g_xpriv, pub, false);
        } else {
            SecByteBlock pt(g_ecies->MaxPlaintextLength(size));
            (void)g_ecies->Decrypt(rng, data, size, pt);
        }
    } catch (const CryptoPP::Exception &) {
        return -1;
    }
    return 0;
}
