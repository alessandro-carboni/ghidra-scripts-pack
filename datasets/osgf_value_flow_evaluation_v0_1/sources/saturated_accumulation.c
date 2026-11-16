/* Heldout family; valid n-byte array, 0 <= n <= 1024, unsigned is 32 bits.
 * Both positive routines implement min(sum(bytes),255). Invariant r<=255:
 * min(r+x,255) == r+min(x,255-r). Intermediate sums are <=510.
 * Foil saturates at 254. Witness [255]: subject=255, foil=254.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned) == 4) ? 1 : -1];
API unsigned subject(const unsigned char *p, unsigned n) {
    unsigned r = 0, i, t;
    for (i = 0; i < n; ++i) { t = r + p[i]; r = t > 255u ? 255u : t; }
    return r;
}
API unsigned subject_equivalent(const unsigned char *p, unsigned n) {
    unsigned r = 0, i, room, x;
    for (i = 0; i < n; ++i) {
        room = 255u - r; x = p[i]; r += x > room ? room : x;
    }
    return r;
}
API unsigned foil(const unsigned char *p, unsigned n) {
    unsigned r = 0, i, t;
    for (i = 0; i < n; ++i) { t = r + p[i]; r = t > 254u ? 254u : t; }
    return r;
}
int main(void) { return 0; }
