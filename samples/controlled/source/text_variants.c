#include <stdio.h>
#include <string.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned harmless_helper(unsigned n) { return (n*17u)^91u; }
API unsigned count_digits(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>=48 && p[i]<=57) r++; return r; }
API unsigned count_digits__transparent_wrapper(const unsigned char *p,unsigned n) { return count_digits(p,n); }
API unsigned count_digits__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=count_digits; return target(p,n); }
API unsigned count_digits__function_splitting(const unsigned char *p,unsigned n) { unsigned middle=n/2; unsigned a=count_digits(p,middle); unsigned b=count_digits(p+middle,n-middle); return a+b; }
API unsigned count_digits__dead_branch(const unsigned char *p,unsigned n) { if(n>255) return 123; return count_digits(p,n); }
API unsigned count_digits__harmless_strand(const unsigned char *p,unsigned n) { (void)harmless_helper(n); return count_digits(p,n); }
API unsigned count_digits__linear_chain_inner(const unsigned char *p,unsigned n) { return count_digits(p,n); }
API unsigned count_digits__linear_chain(const unsigned char *p,unsigned n) { return count_digits__linear_chain_inner(p,n); }
API unsigned count_letters(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>=65 && p[i]<=90) r++; return r; }
API unsigned count_letters__transparent_wrapper(const unsigned char *p,unsigned n) { return count_letters(p,n); }
API unsigned count_letters__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=count_letters; return target(p,n); }
API unsigned count_letters__function_splitting(const unsigned char *p,unsigned n) { unsigned middle=n/2; unsigned a=count_letters(p,middle); unsigned b=count_letters(p+middle,n-middle); return a+b; }
API unsigned count_letters__dead_branch(const unsigned char *p,unsigned n) { if(n>255) return 123; return count_letters(p,n); }
API unsigned count_letters__harmless_strand(const unsigned char *p,unsigned n) { (void)harmless_helper(n); return count_letters(p,n); }
API unsigned count_letters__linear_chain_inner(const unsigned char *p,unsigned n) { return count_letters(p,n); }
API unsigned count_letters__linear_chain(const unsigned char *p,unsigned n) { return count_letters__linear_chain_inner(p,n); }
int main(void) { unsigned n,s,j; unsigned char p[256]; for(n=0;n<=255;n++) for(s=0;s<4;s++) { for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+s*31+n)%127); p[n]=0;
printf("count_digits__transparent_wrapper %u %u\n",n*4+s,count_digits__transparent_wrapper(p,n));
printf("count_digits__thunk %u %u\n",n*4+s,count_digits__thunk(p,n));
printf("count_digits__function_splitting %u %u\n",n*4+s,count_digits__function_splitting(p,n));
printf("count_digits__dead_branch %u %u\n",n*4+s,count_digits__dead_branch(p,n));
printf("count_digits__harmless_strand %u %u\n",n*4+s,count_digits__harmless_strand(p,n));
printf("count_digits__linear_chain %u %u\n",n*4+s,count_digits__linear_chain(p,n));
printf("count_letters__transparent_wrapper %u %u\n",n*4+s,count_letters__transparent_wrapper(p,n));
printf("count_letters__thunk %u %u\n",n*4+s,count_letters__thunk(p,n));
printf("count_letters__function_splitting %u %u\n",n*4+s,count_letters__function_splitting(p,n));
printf("count_letters__dead_branch %u %u\n",n*4+s,count_letters__dead_branch(p,n));
printf("count_letters__harmless_strand %u %u\n",n*4+s,count_letters__harmless_strand(p,n));
printf("count_letters__linear_chain %u %u\n",n*4+s,count_letters__linear_chain(p,n));
} return 0; }
