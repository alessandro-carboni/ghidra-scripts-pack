/* Static extraction probes, never executed by the extraction harness.
 * sum_array and sum_pointer agree for every valid n-byte input, modulo 2^32.
 * count_matches/count_33 differ on [32]; signed/unsigned comparison differ
 * for (0xffffffff, 0). copy_bytes requires nonoverlapping valid n-byte regions.
 */
#define API __declspec(dllexport) __declspec(noinline)
API unsigned sum_array(const unsigned char *p, unsigned n) {
    unsigned r=0, i; for(i=0;i<n;i++) r+=p[i]; return r;
}
API unsigned sum_pointer(const unsigned char *p, unsigned n) {
    unsigned r=0; while(n--) r+=*p++; return r;
}
API unsigned count_matches(const unsigned char *p, unsigned n) {
    unsigned r=0, i; for(i=0;i<n;i++) if(p[i]==32) r++; return r;
}
API unsigned count_33(const unsigned char *p, unsigned n) {
    unsigned r=0, i; for(i=0;i<n;i++) if(p[i]==33) r++; return r;
}
API unsigned xor_buffer(const unsigned char *p, unsigned n) {
    unsigned r=0, i; for(i=0;i<n;i++) r^=p[i]; return r;
}
API void copy_bytes(unsigned char *q, const unsigned char *p, unsigned n) {
    unsigned i; for(i=0;i<n;i++) q[i]=p[i];
}
API int signed_less(int a, int b) { return a<b; }
API int unsigned_less(unsigned a, unsigned b) { return a<b; }
int main(void) { return 0; }
