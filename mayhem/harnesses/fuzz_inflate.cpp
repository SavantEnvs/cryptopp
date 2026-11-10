// DEFLATE family: raw Inflator, zlib, gzip decoders on arbitrary bytes, plus a
// Deflator->Inflator round trip that must reproduce the input exactly.
#include "cryptlib.h"
#include "filters.h"
#include "zinflate.h"
#include "zdeflate.h"
#include "zlib.h"
#include "gzip.h"

#include <cstdint>
#include <cstdlib>
#include <string>

using namespace CryptoPP;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    const unsigned mode = data[0] % 5;
    data++;
    size--;
    std::string out;
    try {
        switch (mode) {
        case 0:
            StringSource(data, size, true, new Inflator(new StringSink(out)));
            break;
        case 1:
            StringSource(data, size, true, new ZlibDecompressor(new StringSink(out)));
            break;
        case 2:
            StringSource(data, size, true, new Gunzip(new StringSink(out)));
            break;
        case 3:
            StringSource(data, size, true, new Inflator(new StringSink(out), true));
            break;
        default: {
            if (size < 1) return -1;
            const int level = data[0] % 10;
            data++;
            size--;
            std::string packed;
            StringSource(data, size, true, new Deflator(new StringSink(packed), level));
            StringSource(packed, true, new Inflator(new StringSink(out)));
            if (out.size() != size || (size && memcmp(out.data(), data, size) != 0)) abort();
            break;
        }
        }
    } catch (const CryptoPP::Exception &) {
    }
    return 0;
}
