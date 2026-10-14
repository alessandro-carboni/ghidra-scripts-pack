#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <stdio.h>
#include <string.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned sum_array(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) r+=p[i]; return r; }
API unsigned find_max(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>r) r=p[i]; return r; }
API unsigned count_matches(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) if(p[i]==32) r++; return r; }
int main(void) { unsigned i,j; unsigned char p[256]; for(i=0;i<16;i++) { for(j=0;j<i*7;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[i*7]=0;
printf("sum_array %u %u\n",i,sum_array(p,i*7));
printf("find_max %u %u\n",i,find_max(p,i*7));
printf("count_matches %u %u\n",i,count_matches(p,i*7));
} return 0; }
