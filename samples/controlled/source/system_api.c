#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <stdio.h>
#include <string.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned read_file(const unsigned char *p,unsigned n) { DWORD a; (void)p; (void)n; a=GetFileAttributesA("C:\\Windows\\System32\\kernel32.dll"); return a!=INVALID_FILE_ATTRIBUTES; }
API unsigned create_socket(const unsigned char *p,unsigned n) { WSADATA w; SOCKET s; unsigned r; (void)p; (void)n; if(WSAStartup(MAKEWORD(2,2),&w)) return 0; s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); r=s!=INVALID_SOCKET; if(r) closesocket(s); WSACleanup(); return r; }
API unsigned read_registry_value(const unsigned char *p,unsigned n) { HKEY k; LONG e; (void)p; (void)n; e=RegOpenKeyExA(HKEY_CURRENT_USER,"Software",0,KEY_READ,&k); if(e==ERROR_SUCCESS) RegCloseKey(k); return e==ERROR_SUCCESS; }
int main(void) { unsigned i,j; unsigned char p[256]; for(i=0;i<16;i++) { for(j=0;j<i*7;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[i*7]=0;
printf("read_file %u %u\n",i,read_file(p,i*7));
printf("create_socket %u %u\n",i,create_socket(p,i*7));
printf("read_registry_value %u %u\n",i,read_registry_value(p,i*7));
} return 0; }
