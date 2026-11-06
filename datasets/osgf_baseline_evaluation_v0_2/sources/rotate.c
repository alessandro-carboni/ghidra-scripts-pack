/* Fresh validation component. The shifted bit ranges are disjoint, so OR and
 * addition are equivalent modulo 2^32. Foil rotates by 8 rather than 7;
 * input [1,0] distinguishes the two behaviors.
 */
#define API __declspec(dllexport) __declspec(noinline)
API unsigned subject(const unsigned char *p, unsigned n) {
    unsigned r=0, i;
    for(i=0;i<n;i++) r=((r<<7)|(r>>25))^p[i];
    return r;
}
API unsigned subject_equivalent(const unsigned char *p, unsigned n) {
    unsigned r=0, i;
    for(i=0;i<n;i++) r=((r<<7)+(r>>25))^p[i];
    return r;
}
API unsigned foil(const unsigned char *p, unsigned n) {
    unsigned r=0, i;
    for(i=0;i<n;i++) r=((r<<8)|(r>>24))^p[i];
    return r;
}
int main(void) { return 0; }
