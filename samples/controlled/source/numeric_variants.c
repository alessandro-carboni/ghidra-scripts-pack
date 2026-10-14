#include <stdio.h>
#include <string.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned harmless_helper(unsigned n) { return (n*17u)^91u; }
API unsigned sum_array(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) r+=p[i]; return r; }
API unsigned sum_array__transparent_wrapper(const unsigned char *p,unsigned n) { return sum_array(p,n); }
API unsigned sum_array__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=sum_array; return target(p,n); }
API unsigned sum_array__function_splitting(const unsigned char *p,unsigned n) { unsigned middle=n/2; unsigned a=sum_array(p,middle); unsigned b=sum_array(p+middle,n-middle); return a+b; }
API unsigned sum_array__dead_branch(const unsigned char *p,unsigned n) { if(n>255) return 123; return sum_array(p,n); }
API unsigned sum_array__harmless_strand(const unsigned char *p,unsigned n) { (void)harmless_helper(n); return sum_array(p,n); }
API unsigned sum_array__linear_chain_inner(const unsigned char *p,unsigned n) { return sum_array(p,n); }
API unsigned sum_array__linear_chain(const unsigned char *p,unsigned n) { return sum_array__linear_chain_inner(p,n); }
API unsigned find_max(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>r) r=p[i]; return r; }
API unsigned find_max__transparent_wrapper(const unsigned char *p,unsigned n) { return find_max(p,n); }
API unsigned find_max__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=find_max; return target(p,n); }
API unsigned find_max__function_splitting(const unsigned char *p,unsigned n) { unsigned middle=n/2; unsigned a=find_max(p,middle); unsigned b=find_max(p+middle,n-middle); return a>b?a:b; }
API unsigned find_max__dead_branch(const unsigned char *p,unsigned n) { if(n>255) return 123; return find_max(p,n); }
API unsigned find_max__harmless_strand(const unsigned char *p,unsigned n) { (void)harmless_helper(n); return find_max(p,n); }
API unsigned find_max__linear_chain_inner(const unsigned char *p,unsigned n) { return find_max(p,n); }
API unsigned find_max__linear_chain(const unsigned char *p,unsigned n) { return find_max__linear_chain_inner(p,n); }
int main(void) { unsigned n,s,j; unsigned char p[256]; for(n=0;n<=255;n++) for(s=0;s<4;s++) { for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+s*31+n)%127); p[n]=0;
printf("sum_array__transparent_wrapper %u %u\n",n*4+s,sum_array__transparent_wrapper(p,n));
printf("sum_array__thunk %u %u\n",n*4+s,sum_array__thunk(p,n));
printf("sum_array__function_splitting %u %u\n",n*4+s,sum_array__function_splitting(p,n));
printf("sum_array__dead_branch %u %u\n",n*4+s,sum_array__dead_branch(p,n));
printf("sum_array__harmless_strand %u %u\n",n*4+s,sum_array__harmless_strand(p,n));
printf("sum_array__linear_chain %u %u\n",n*4+s,sum_array__linear_chain(p,n));
printf("find_max__transparent_wrapper %u %u\n",n*4+s,find_max__transparent_wrapper(p,n));
printf("find_max__thunk %u %u\n",n*4+s,find_max__thunk(p,n));
printf("find_max__function_splitting %u %u\n",n*4+s,find_max__function_splitting(p,n));
printf("find_max__dead_branch %u %u\n",n*4+s,find_max__dead_branch(p,n));
printf("find_max__harmless_strand %u %u\n",n*4+s,find_max__harmless_strand(p,n));
printf("find_max__linear_chain %u %u\n",n*4+s,find_max__linear_chain(p,n));
} return 0; }
