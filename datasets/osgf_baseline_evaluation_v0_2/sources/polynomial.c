/* Fresh discovery component. Unsigned 32-bit arithmetic, valid n-byte input.
 * r*33 == (r<<5)+r modulo 2^32, proving subject/equivalent equality.
 * Foil replaces XOR by addition; input [1] is a counterexample.
 */
#define API __declspec(dllexport) __declspec(noinline)
API unsigned subject(const unsigned char *p, unsigned n) {
    unsigned r=5381, i;
    for(i=0;i<n;i++) r=((r<<5)+r)^p[i];
    return r;
}
API unsigned subject_equivalent(const unsigned char *p, unsigned n) {
    unsigned r=5381, i;
    for(i=0;i<n;i++) r=(r*33u)^p[i];
    return r;
}
API unsigned foil(const unsigned char *p, unsigned n) {
    unsigned r=5381, i;
    for(i=0;i<n;i++) r=((r<<5)+r)+p[i];
    return r;
}
int main(void) { return 0; }
