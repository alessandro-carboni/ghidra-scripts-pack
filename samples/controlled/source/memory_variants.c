#include <stdio.h>
#include <string.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned harmless_helper(unsigned n) { return (n*17u)^91u; }
API unsigned copy_buffer(const unsigned char *p,unsigned n) { unsigned char dst[256]; unsigned i,r=0; memcpy(dst,p,n); for(i=0;i<n;i++) r+=dst[i]; return r; }
API unsigned copy_buffer__transparent_wrapper(const unsigned char *p,unsigned n) { return copy_buffer(p,n); }
API unsigned copy_buffer__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=copy_buffer; return target(p,n); }
API unsigned copy_buffer__function_splitting(const unsigned char *p,unsigned n) { unsigned middle=n/2; unsigned a=copy_buffer(p,middle); unsigned b=copy_buffer(p+middle,n-middle); return a+b; }
API unsigned copy_buffer__dead_branch(const unsigned char *p,unsigned n) { if(n>255) return 123; return copy_buffer(p,n); }
API unsigned copy_buffer__harmless_strand(const unsigned char *p,unsigned n) { (void)harmless_helper(n); return copy_buffer(p,n); }
API unsigned copy_buffer__linear_chain_inner(const unsigned char *p,unsigned n) { return copy_buffer(p,n); }
API unsigned copy_buffer__linear_chain(const unsigned char *p,unsigned n) { return copy_buffer__linear_chain_inner(p,n); }
API unsigned xor_buffer(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) r^=p[i]; return r; }
API unsigned xor_buffer__transparent_wrapper(const unsigned char *p,unsigned n) { return xor_buffer(p,n); }
API unsigned xor_buffer__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=xor_buffer; return target(p,n); }
API unsigned xor_buffer__function_splitting(const unsigned char *p,unsigned n) { unsigned middle=n/2; unsigned a=xor_buffer(p,middle); unsigned b=xor_buffer(p+middle,n-middle); return a^b; }
API unsigned xor_buffer__dead_branch(const unsigned char *p,unsigned n) { if(n>255) return 123; return xor_buffer(p,n); }
API unsigned xor_buffer__harmless_strand(const unsigned char *p,unsigned n) { (void)harmless_helper(n); return xor_buffer(p,n); }
API unsigned xor_buffer__linear_chain_inner(const unsigned char *p,unsigned n) { return xor_buffer(p,n); }
API unsigned xor_buffer__linear_chain(const unsigned char *p,unsigned n) { return xor_buffer__linear_chain_inner(p,n); }
int main(void) { unsigned n,s,j; unsigned char p[256]; for(n=0;n<=255;n++) for(s=0;s<4;s++) { for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+s*31+n)%127); p[n]=0;
printf("copy_buffer__transparent_wrapper %u %u\n",n*4+s,copy_buffer__transparent_wrapper(p,n));
printf("copy_buffer__thunk %u %u\n",n*4+s,copy_buffer__thunk(p,n));
printf("copy_buffer__function_splitting %u %u\n",n*4+s,copy_buffer__function_splitting(p,n));
printf("copy_buffer__dead_branch %u %u\n",n*4+s,copy_buffer__dead_branch(p,n));
printf("copy_buffer__harmless_strand %u %u\n",n*4+s,copy_buffer__harmless_strand(p,n));
printf("copy_buffer__linear_chain %u %u\n",n*4+s,copy_buffer__linear_chain(p,n));
printf("xor_buffer__transparent_wrapper %u %u\n",n*4+s,xor_buffer__transparent_wrapper(p,n));
printf("xor_buffer__thunk %u %u\n",n*4+s,xor_buffer__thunk(p,n));
printf("xor_buffer__function_splitting %u %u\n",n*4+s,xor_buffer__function_splitting(p,n));
printf("xor_buffer__dead_branch %u %u\n",n*4+s,xor_buffer__dead_branch(p,n));
printf("xor_buffer__harmless_strand %u %u\n",n*4+s,xor_buffer__harmless_strand(p,n));
printf("xor_buffer__linear_chain %u %u\n",n*4+s,xor_buffer__linear_chain(p,n));
} return 0; }
