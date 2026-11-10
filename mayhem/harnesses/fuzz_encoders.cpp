// Radix decoders (Base64, Base64URL, Base32, Base32Hex, Hex) on arbitrary text, plus an
// encode->decode round trip that must reproduce the input exactly.
#include "cryptlib.h"
#include "filters.h"
#include "base64.h"
#include "base32.h"
#include "hex.h"

#include <cstdint>
#include <cstdlib>
#include <string>

using namespace CryptoPP;

template <class Enc, class Dec>
static void RoundTrip(const uint8_t *data, size_t size) {
    std::string enc, dec;
    StringSource(data, size, true, new Enc(new StringSink(enc)));
    StringSource(enc, true, new Dec(new StringSink(dec)));
    if (dec.size() != size || (size && memcmp(dec.data(), data, size) != 0)) abort();
}

template <class Dec>
static void Decode(const uint8_t *data, size_t size) {
    std::string out;
    StringSource(data, size, true, new Dec(new StringSink(out)));
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    const unsigned mode = data[0] % 10;
    data++;
    size--;
    try {
        switch (mode) {
        case 0: Decode<Base64Decoder>(data, size); break;
        case 1: Decode<Base64URLDecoder>(data, size); break;
        case 2: Decode<Base32Decoder>(data, size); break;
        case 3: Decode<Base32HexDecoder>(data, size); break;
        case 4: Decode<HexDecoder>(data, size); break;
        case 5: RoundTrip<Base64Encoder, Base64Decoder>(data, size); break;
        case 6: RoundTrip<Base64URLEncoder, Base64URLDecoder>(data, size); break;
        case 7: RoundTrip<Base32Encoder, Base32Decoder>(data, size); break;
        case 8: RoundTrip<Base32HexEncoder, Base32HexDecoder>(data, size); break;
        default: RoundTrip<HexEncoder, HexDecoder>(data, size); break;
        }
    } catch (const CryptoPP::Exception &) {
    }
    return 0;
}
