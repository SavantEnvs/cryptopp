// Multi-precision Integer: decoding/parsing plus arithmetic identities that must hold for
// any operands (division, modular inverse, squaring, shifts, GCD).
#include "cryptlib.h"
#include "integer.h"
#include "nbtheory.h"
#include "queue.h"
#include "asn.h"

#include <cstdint>
#include <cstdlib>
#include <string>

using namespace CryptoPP;

static void Require(bool ok) {
    if (!ok) abort();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return -1;
    const unsigned mode = data[0] % 5;
    data++;
    size--;
    try {
        if (mode == 0) {
            const std::string text(reinterpret_cast<const char *>(data), size);
            Integer v(text.c_str());
            std::string dec;
            (void)v.BitCount();
            (void)IsPrime(v);
        } else if (mode == 1) {
            ByteQueue q;
            q.Put(data, size);
            q.MessageEnd();
            Integer v;
            v.BERDecode(q);
            Integer w(data, size, Integer::SIGNED);
            Require(w + (-w) == Integer::Zero());
        } else {
            const size_t la = 1 + data[0] % 48, lb = 1 + data[1] % 48;
            data += 2;
            size -= 2;
            if (size < la + lb) return -1;
            Integer a(data, la), b(data + la, lb);
            const size_t mlen = size - la - lb;
            Integer m(data + la + lb, mlen > 48 ? 48 : mlen);
            Require(a + b - b == a);
            Require(a * b == b * a);
            Require(a.Squared() == a * a);
            if (!b.IsZero()) {
                Integer q, r;
                Integer::Divide(r, q, a, b);
                Require(q * b + r == a);
                Require(r < b);
                Require(a * b / b == a);
            }
            Require(GCD(a, b) == GCD(b, a));
            if (mode == 3 && m > Integer::One()) {
                Integer inv = a.InverseMod(m);
                if (!inv.IsZero()) Require((a * inv) % m == Integer::One());
                Require(a_exp_b_mod_c(a, Integer::Two(), m) == (a * a) % m);
            }
            if (mode == 4) {
                const unsigned sh = data[0] % 200;
                Require(((a << sh) >> sh) == a);
                Require((a << sh) == a * Integer::Power2(sh));
            }
        }
    } catch (const CryptoPP::Exception &) {
        return -1;
    }
    return 0;
}
