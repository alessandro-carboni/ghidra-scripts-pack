#include <windows.h>
#include <stdio.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned length_helper(const unsigned char *p) { return (unsigned)lstrlenA((const char*)p); }
API unsigned api_length(const unsigned char *p,unsigned n) { (void)n; return (unsigned)lstrlenA((const char*)p); }
API unsigned api_length_wrapped(const unsigned char *p,unsigned n) { (void)n; return length_helper(p)+1u; }
API unsigned api_length_plus_one(const unsigned char *p,unsigned n) { (void)n; return (unsigned)lstrlenA((const char*)p)+1u; }
API unsigned api_compare(const unsigned char *p,unsigned n) { (void)n; return lstrcmpA((const char*)p,"AB")==0; }
API unsigned api_compare_inverted(const unsigned char *p,unsigned n) { (void)n; return lstrcmpA((const char*)p,"AB")!=0; }
int main(void) { unsigned i,j,n; unsigned char p[256]; for(i=0;i<16;i++) { n=i*7; for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[n]=0;
printf("api_length %u %u\n",i,api_length(p,n));
printf("api_length_wrapped %u %u\n",i,api_length_wrapped(p,n));
printf("api_length_plus_one %u %u\n",i,api_length_plus_one(p,n));
printf("api_compare %u %u\n",i,api_compare(p,n));
printf("api_compare_inverted %u %u\n",i,api_compare_inverted(p,n));
} return 0; }
