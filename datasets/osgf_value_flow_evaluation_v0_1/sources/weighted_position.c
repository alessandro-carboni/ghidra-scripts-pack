/* Discovery family; valid n-byte array, 0 <= n <= 1024, unsigned is 32 bits.
 * Both positive functions sum (i+1)*p[i]. Reversing iteration preserves the
 * unsigned sum (also bounded below 2^32 here). Foil changes each weight to i+2.
 * Negative witness [1]: subject=1, foil=2. No target execution required.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned) == 4) ? 1 : -1];
API unsigned subject(const unsigned char *p, unsigned n) {
    unsigned r = 0, i;
    for (i = 0; i < n; ++i) r += (i + 1u) * p[i];
    return r;
}
API unsigned subject_equivalent(const unsigned char *p, unsigned n) {
    unsigned r = 0;
    while (n) { r += n * p[n - 1]; --n; }
    return r;
}
API unsigned foil(const unsigned char *p, unsigned n) {
    unsigned r = 0, i;
    for (i = 0; i < n; ++i) r += (i + 2u) * p[i];
    return r;
}
int main(void) { return 0; }
