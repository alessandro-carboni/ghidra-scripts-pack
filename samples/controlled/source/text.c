#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <stdio.h>
#include <string.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned count_digits(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>=48 && p[i]<=57) r++; return r; }
API unsigned count_letters(const unsigned char *p,unsigned n) { unsigned r=0,i; for(i=0;i<n;i++) if(p[i]>=65 && p[i]<=90) r++; return r; }
API unsigned search_string(const unsigned char *p,unsigned n) { unsigned i; for(i=0;i+1<n;i++) if(p[i]==65 && p[i+1]==66) return i+1; return 0; }
int main(void) { unsigned i,j; unsigned char p[256]; for(i=0;i<16;i++) { for(j=0;j<i*7;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[i*7]=0;
printf("count_digits %u %u\n",i,count_digits(p,i*7));
printf("count_letters %u %u\n",i,count_letters(p,i*7));
printf("search_string %u %u\n",i,search_string(p,i*7));
} return 0; }
