// Hashes and MACs: the digest computed by feeding the input in input-chosen pieces must
// equal the one-shot digest.
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptlib.h"
#include "sha.h"
#include "sha3.h"
#include "keccak.h"
#include "blake2.h"
#include "whrlpool.h"
#include "ripemd.h"
#include "md5.h"
#include "sm3.h"
#include "tiger.h"
#include "lsh.h"
#include "hmac.h"
#include "cmac.h"
#include "aes.h"
#include "siphash.h"
#include "secblock.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

using namespace CryptoPP;

static void Check(HashTransformation &h, const uint8_t *data, size_t size) {
    SecByteBlock one(h.DigestSize()), two(h.DigestSize());
    h.Update(data, size);
    h.Final(one);
    size_t off = 0, i = 0;
    while (off < size) {
        size_t n = 1 + (data[i % size] % 97);
        if (n > size - off) n = size - off;
        h.Update(data + off, n);
        off += n;
        i++;
    }
    h.Final(two);
    if (std::memcmp(one, two, one.size()) != 0) abort();
}

template <class H>
static void Hash(const uint8_t *data, size_t size) {
    H h;
    Check(h, data, size);
}

template <class M>
static void Mac(const uint8_t *data, size_t size, size_t keylen) {
    M m;
    byte key[64] = {0};
    std::memcpy(key, data, keylen < size ? keylen : size);
    m.SetKey(key, keylen);
    Check(m, data, size);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    const unsigned mode = data[0] % 23;
    data++;
    size--;
    switch (mode) {
    case 0: Hash<SHA1>(data, size); break;
    case 1: Hash<SHA224>(data, size); break;
    case 2: Hash<SHA256>(data, size); break;
    case 3: Hash<SHA384>(data, size); break;
    case 4: Hash<SHA512>(data, size); break;
    case 5: Hash<SHA3_256>(data, size); break;
    case 6: Hash<SHA3_512>(data, size); break;
    case 7: Hash<Keccak_256>(data, size); break;
    case 8: Hash<BLAKE2b>(data, size); break;
    case 9: Hash<BLAKE2s>(data, size); break;
    case 10: Hash<Whirlpool>(data, size); break;
    case 11: Hash<RIPEMD160>(data, size); break;
    case 12: Hash<Weak::MD5>(data, size); break;
    case 13: Hash<SM3>(data, size); break;
    case 14: Hash<Tiger>(data, size); break;
    case 15: Hash<LSH256>(data, size); break;
    case 16: Hash<LSH512>(data, size); break;
    case 17: Mac<HMAC<SHA256> >(data, size, 32); break;
    case 18: Mac<HMAC<SHA512> >(data, size, 64); break;
    case 19: Mac<CMAC<AES> >(data, size, 16); break;
    case 20: Mac<BLAKE2b>(data, size, 32); break;
    case 21: Mac<SipHash<2, 4, false> >(data, size, 16); break;
    case 22: Mac<SipHash<4, 8, true> >(data, size, 16); break;
    default: Hash<SHA256>(data, size); break;
    }
    return 0;
}
