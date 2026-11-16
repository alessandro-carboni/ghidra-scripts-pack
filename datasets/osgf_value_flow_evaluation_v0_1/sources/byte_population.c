/* Validation family; valid n-byte array, 0 <= n <= 1024, unsigned is 32 bits.
 * Positive routines count all set bits. v&(v-1) clears exactly one set bit
 * for nonzero unsigned v, so the second loop counts the same bits.
 * Foil ignores bit 7. Witness [128]: subject=1, foil=0.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned) == 4) ? 1 : -1];
API unsigned subject(const unsigned char *p, unsigned n) {
    unsigned r = 0, i, b;
    for (i = 0; i < n; ++i)
        for (b = 0; b < 8; ++b) r += (p[i] >> b) & 1u;
    return r;
}
API unsigned subject_equivalent(const unsigned char *p, unsigned n) {
    unsigned r = 0, i, v;
    for (i = 0; i < n; ++i) {
        v = p[i];
        while (v) { v &= v - 1u; ++r; }
    }
    return r;
}
API unsigned foil(const unsigned char *p, unsigned n) {
    unsigned r = 0, i, b;
    for (i = 0; i < n; ++i)
        for (b = 0; b < 7; ++b) r += (p[i] >> b) & 1u;
    return r;
}
int main(void) { return 0; }
