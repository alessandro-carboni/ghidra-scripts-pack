#include <windows.h>
#include <stdint.h>
#if defined(_MSC_VER)
#define KEEP __declspec(noinline)
#else
#define KEEP __attribute__((noinline,used))
#endif
#define OBSERVE() do { void *a=VirtualAlloc(0,64,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); if(a) VirtualFree(a,0,MEM_RELEASE); } while(0)
KEEP unsigned compute(const unsigned char *p, unsigned n) { unsigned r=0; for(unsigned i=0;i<n;i++){r += p[i]>31 ? 31 : p[i];} return r; }
KEEP unsigned compute_equivalent(const unsigned char *p,unsigned n) { unsigned r=0; unsigned i=n; while(i){--i; unsigned x=p[i]; r += x - (x>31 ? x-31 : 0);} return r; }
KEEP unsigned subject(const unsigned char *p,unsigned n) { OBSERVE(); return compute(p,n); }
KEEP unsigned effect_helper(const unsigned char *p,unsigned n) { OBSERVE(); return compute_equivalent(p,n); }
KEEP unsigned subject_equivalent(const unsigned char *p,unsigned n) { return effect_helper(p,n); }
KEEP unsigned foil(const unsigned char *p,unsigned n) { OBSERVE(); return compute(p,n)^1u; }
KEEP unsigned no_seed(unsigned x) { return (x+1u)*3u; }
KEEP unsigned unresolved_probe(unsigned (*callback)(unsigned),unsigned x) { return callback(x); }
int main(void) { unsigned char data[16]={0}; volatile unsigned value=subject(data,16)+subject_equivalent(data,16)+foil(data,16)+unresolved_probe(no_seed,2); return (int)value; }
