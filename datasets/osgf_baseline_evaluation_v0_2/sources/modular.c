/* Fresh held-out component. For 0<=a,b<65521 and byte x, addition cannot
 * overflow 32 bits. b+(a+x mod m) mod m == (b+a+x) mod m. This proves the
 * equivalent reordered recurrence. Foil uses modulus 65519.
 */
#define API __declspec(dllexport) __declspec(noinline)
API unsigned subject(const unsigned char *p, unsigned n) {
    unsigned a=1, b=0, i;
    for(i=0;i<n;i++) { a=(a+p[i])%65521u; b=(b+a)%65521u; }
    return (b<<16)|a;
}
API unsigned subject_equivalent(const unsigned char *p, unsigned n) {
    unsigned a=1, b=0, i;
    for(i=0;i<n;i++) { b=(b+a+p[i])%65521u; a=(a+p[i])%65521u; }
    return (b<<16)|a;
}
API unsigned foil(const unsigned char *p, unsigned n) {
    unsigned a=1, b=0, i;
    for(i=0;i<n;i++) { a=(a+p[i])%65519u; b=(b+a)%65519u; }
    return (b<<16)|a;
}
int main(void) { return 0; }
