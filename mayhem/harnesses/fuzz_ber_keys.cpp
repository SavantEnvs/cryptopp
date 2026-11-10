// BER/DER decoding of public keys, private keys and group parameters of every
// asymmetric family in the library.
#include "cryptlib.h"
#include "queue.h"
#include "rsa.h"
#include "dsa.h"
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
#include "dh.h"
#include "elgamal.h"
#include "xed25519.h"
#include "sha.h"
#include "rng.h"
#include "oids.h"
#include "asn.h"

#include <cstdint>

using namespace CryptoPP;

template <class K>
static void LoadKey(ByteQueue &q) {
    K key;
    key.Load(q);
    LC_RNG rng(1);
    (void)key.Validate(rng, 0);
}

template <class P>
static void LoadParams(ByteQueue &q) {
    P params;
    params.BERDecode(q);
    LC_RNG rng(1);
    (void)params.Validate(rng, 0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    const unsigned mode = data[0] % 17;
    data++;
    size--;
    ByteQueue q;
    q.Put(data, size);
    q.MessageEnd();
    try {
        switch (mode) {
        case 0: LoadKey<RSA::PublicKey>(q); break;
        case 1: LoadKey<RSA::PrivateKey>(q); break;
        case 2: LoadKey<DSA::PublicKey>(q); break;
        case 3: LoadKey<DSA::PrivateKey>(q); break;
        case 4: LoadKey<ECDSA<ECP, SHA256>::PublicKey>(q); break;
        case 5: LoadKey<ECDSA<ECP, SHA256>::PrivateKey>(q); break;
        case 6: LoadKey<ECDSA<EC2N, SHA256>::PublicKey>(q); break;
        case 7: LoadKey<ECDSA<EC2N, SHA256>::PrivateKey>(q); break;
        case 8: LoadKey<ed25519PublicKey>(q); break;
        case 9: LoadKey<ed25519PrivateKey>(q); break;
        case 10: LoadKey<ElGamalKeys::PublicKey>(q); break;
        case 11: LoadKey<ElGamalKeys::PrivateKey>(q); break;
        case 12: LoadParams<DL_GroupParameters_EC<ECP> >(q); break;
        case 13: LoadParams<DL_GroupParameters_EC<EC2N> >(q); break;
        case 14: LoadParams<DL_GroupParameters_GFP>(q); break;
        case 15: LoadParams<DL_GroupParameters_DSA>(q); break;
        default: {
            x25519 k;
            k.Load(q);
            break;
        }
        }
    } catch (const CryptoPP::Exception &) {
        return -1;
    }
    return 0;
}
