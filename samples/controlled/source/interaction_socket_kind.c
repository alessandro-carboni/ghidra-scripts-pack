#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <stdio.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned socket_kind_helper(const unsigned char *p,unsigned n) { WSADATA w; SOCKET s; int kind=0,size=sizeof(kind); (void)p; (void)n; if(WSAStartup(MAKEWORD(2,2),&w)) return 0; s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); if(s!=INVALID_SOCKET) { if(getsockopt(s,SOL_SOCKET,SO_TYPE,(char*)&kind,&size)!=0) kind=0; closesocket(s); } WSACleanup(); return (unsigned)kind; }
API unsigned interaction_socket_kind__linear_chain_inner(const unsigned char *p,unsigned n);
API unsigned interaction_socket_kind(const unsigned char *p,unsigned n) { return socket_kind_helper(p,n)*(n+1u); }
API unsigned interaction_socket_kind_flipped(const unsigned char *p,unsigned n) { return (socket_kind_helper(p,n)*(n+1u))^1u; }
API unsigned interaction_socket_kind__transparent_wrapper(const unsigned char *p,unsigned n) { return interaction_socket_kind(p,n); }
API unsigned interaction_socket_kind__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=interaction_socket_kind; return target(p,n); }
API unsigned interaction_socket_kind__linear_chain(const unsigned char *p,unsigned n) { return interaction_socket_kind__linear_chain_inner(p,n); }
API unsigned interaction_socket_kind__linear_chain_inner(const unsigned char *p,unsigned n) { return interaction_socket_kind(p,n); }
int main(void) { unsigned i,j,n; unsigned char p[256]; for(i=0;i<16;i++) { n=i*7; for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[n]=0;
printf("interaction_socket_kind %u %u\n",i,interaction_socket_kind(p,n));
printf("interaction_socket_kind_flipped %u %u\n",i,interaction_socket_kind_flipped(p,n));
printf("interaction_socket_kind__transparent_wrapper %u %u\n",i,interaction_socket_kind__transparent_wrapper(p,n));
printf("interaction_socket_kind__thunk %u %u\n",i,interaction_socket_kind__thunk(p,n));
printf("interaction_socket_kind__linear_chain %u %u\n",i,interaction_socket_kind__linear_chain(p,n));
} return 0; }
