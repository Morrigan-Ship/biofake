/*++
keys.c

Key store helpers and the deterministic synthetic fingerprint image generator.

Every key is a 32-byte seed. The image is generated once per key with
pure floating point math (user-mode process) from the seed, so the same key
always produces byte-identical captures. Identical captures mean the engine
adapter's SHA-256 of the image is stable, which makes enrollment and
verification behave like a real, perfectly repeatable finger.
--*/

#include "biofake.h"
#include <math.h>

BOOLEAN
BioFakeNameEqualI(
    _In_opt_ PCWSTR a,
    _In_opt_ PCWSTR b
    )
{
    WCHAR ca, cb;

    if (a == NULL || b == NULL) {
        return FALSE;
    }

    for (;;) {
        ca = *a;
        cb = *b;

        if (ca >= L'A' && ca <= L'Z') {
            ca = (WCHAR)(ca - L'A' + L'a');
        }
        if (cb >= L'A' && cb <= L'Z') {
            cb = (WCHAR)(cb - L'A' + L'a');
        }

        if (ca != cb) {
            return FALSE;
        }
        if (ca == L'\0') {
            return TRUE;
        }

        a++;
        b++;
    }
}

LONG
BioFakeFindKey(
    _In_ DRIVER_CONTEXT* Ctx,
    _In_opt_ PCWSTR Name
    )
{
    ULONG i;

    if (Name == NULL || Name[0] == L'\0') {
        return Ctx->ActiveIndex;
    }

    for (i = 0; i < Ctx->KeyCount; i++) {
        if (BioFakeNameEqualI(Ctx->Keys[i].Name, Name)) {
            return (LONG)i;
        }
    }

    return -1;
}

static
ULONGLONG
BioFakeNextRandom(
    _Inout_ ULONGLONG* state
    )
{
    ULONGLONG s = *state;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    *state = s;
    return s;
}

static
double
BioFakeSeedRange(
    _Inout_ ULONGLONG* state,
    double lo,
    double hi
    )
{
    double f = (double)(BioFakeNextRandom(state) >> 11) / 9007199254740992.0; // [0, 1)
    return lo + f * (hi - lo);
}

VOID
BioFakeEnsureImage(
    _Inout_ BIOFAKE_KEY* Key
    )
{
    ULONGLONG state = 0xcbf29ce484222325ULL;
    double cx, cy, f1, f2, f3, p1, p2, p3, ringSpacing;
    double dx, dy, r, wob, v;
    long band;
    BYTE val;
    int x, y;
    ULONG i;

    if (Key->ImageBuilt) {
        return;
    }

    // FNV-1a style mix of the 32 seed bytes into a 64-bit xorshift state.
    for (i = 0; i < BIOFAKE_SEED_SIZE; i++) {
        state ^= (ULONGLONG)Key->Seed[i];
        state *= 0x100000001b3ULL;
    }
    if (state == 0) {
        state = 0x9e3779b97f4a7c15ULL;
    }

    cx          = BioFakeSeedRange(&state, 40.0, 90.0);
    cy          = BioFakeSeedRange(&state, 40.0, 90.0);
    f1          = BioFakeSeedRange(&state, 0.030, 0.050);
    f2          = BioFakeSeedRange(&state, 0.026, 0.046);
    f3          = BioFakeSeedRange(&state, 0.040, 0.080);
    p1          = BioFakeSeedRange(&state, 0.0, 6.2831853);
    p2          = BioFakeSeedRange(&state, 0.0, 6.2831853);
    p3          = BioFakeSeedRange(&state, 0.0, 6.2831853);
    ringSpacing = BioFakeSeedRange(&state, 2.4, 3.4);

    for (y = 0; y < BIOFAKE_IMAGE_H; y++) {
        for (x = 0; x < BIOFAKE_IMAGE_W; x++) {
            dx = (double)x - cx;
            dy = (double)y - cy;
            r = sqrt(dx * dx + dy * dy);

            // Wobble the concentric rings with three seeded sine fields so
            // the result resembles fingerprint ridges rather than a target.
            wob = sin(dx * f1 + p1) + sin(dy * f2 + p2) + sin(r * f3 + p3);
            v = r / ringSpacing + wob * 0.8;

            band = (long)floor(v);
            val = (BYTE)((band & 1) ? 195 : 45);

            // Small deterministic noise so the image does not look flat.
            val = (BYTE)(val + (int)((BioFakeNextRandom(&state) >> 33) & 7) - 3);

            if (val < 10) {
                val = 10;
            } else if (val > 245) {
                val = 245;
            }

            Key->Image[y * BIOFAKE_IMAGE_W + x] = val;
        }
    }

    Key->ImageBuilt = TRUE;
}
