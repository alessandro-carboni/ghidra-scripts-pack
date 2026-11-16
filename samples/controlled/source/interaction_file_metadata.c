#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <stdio.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned file_metadata_helper(const unsigned char *p,unsigned n) { DWORD a; (void)p; (void)n; a=GetFileAttributesA("C:\\Windows\\System32\\kernel32.dll"); return a==INVALID_FILE_ATTRIBUTES?0u:(a&65535u); }
API unsigned interaction_file_metadata__linear_chain_inner(const unsigned char *p,unsigned n);
API unsigned interaction_file_metadata(const unsigned char *p,unsigned n) { return file_metadata_helper(p,n)+n; }
API unsigned interaction_file_metadata_flipped(const unsigned char *p,unsigned n) { return (file_metadata_helper(p,n)+n)^1u; }
API unsigned interaction_file_metadata__transparent_wrapper(const unsigned char *p,unsigned n) { return interaction_file_metadata(p,n); }
API unsigned interaction_file_metadata__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=interaction_file_metadata; return target(p,n); }
API unsigned interaction_file_metadata__linear_chain(const unsigned char *p,unsigned n) { return interaction_file_metadata__linear_chain_inner(p,n); }
API unsigned interaction_file_metadata__linear_chain_inner(const unsigned char *p,unsigned n) { return interaction_file_metadata(p,n); }
int main(void) { unsigned i,j,n; unsigned char p[256]; for(i=0;i<16;i++) { n=i*7; for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[n]=0;
printf("interaction_file_metadata %u %u\n",i,interaction_file_metadata(p,n));
printf("interaction_file_metadata_flipped %u %u\n",i,interaction_file_metadata_flipped(p,n));
printf("interaction_file_metadata__transparent_wrapper %u %u\n",i,interaction_file_metadata__transparent_wrapper(p,n));
printf("interaction_file_metadata__thunk %u %u\n",i,interaction_file_metadata__thunk(p,n));
printf("interaction_file_metadata__linear_chain %u %u\n",i,interaction_file_metadata__linear_chain(p,n));
} return 0; }
