#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <stdio.h>
#include <string.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned copy_buffer(const unsigned char *p,unsigned n) { unsigned char dst[256]; unsigned i,r=0; memcpy(dst,p,n); for(i=0;i<n;i++) r+=dst[i]; return r; }
API unsigned xor_buffer(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) r^=p[i]; return r; }
API unsigned weighted_buffer(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) r+=(i+1)*p[i]; return r; }
int main(void) { unsigned i,j; unsigned char p[256]; for(i=0;i<16;i++) { for(j=0;j<i*7;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[i*7]=0;
printf("copy_buffer %u %u\n",i,copy_buffer(p,i*7));
printf("xor_buffer %u %u\n",i,xor_buffer(p,i*7));
printf("weighted_buffer %u %u\n",i,weighted_buffer(p,i*7));
} return 0; }
