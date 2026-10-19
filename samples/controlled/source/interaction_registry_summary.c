#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#include <stdio.h>
#define API __declspec(dllexport) __declspec(noinline)
API unsigned registry_summary_helper(const unsigned char *p,unsigned n) { HKEY key; DWORD subkeys=0; LONG status; (void)p; (void)n; if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft",0,KEY_READ,&key)!=ERROR_SUCCESS) return 0; status=RegQueryInfoKeyA(key,0,0,0,&subkeys,0,0,0,0,0,0,0); RegCloseKey(key); return status==ERROR_SUCCESS?subkeys:0u; }
API unsigned interaction_registry_summary__linear_chain_inner(const unsigned char *p,unsigned n);
API unsigned interaction_registry_summary(const unsigned char *p,unsigned n) { unsigned i,count=0; for(i=0;i<n;i++) if(p[i]>=65 && p[i]<=90) count++; return registry_summary_helper(p,n)^count; }
API unsigned interaction_registry_summary_flipped(const unsigned char *p,unsigned n) { unsigned i,count=0; for(i=0;i<n;i++) if(p[i]>=65 && p[i]<=90) count++; return (registry_summary_helper(p,n)^count)^1u; }
API unsigned interaction_registry_summary__transparent_wrapper(const unsigned char *p,unsigned n) { return interaction_registry_summary(p,n); }
API unsigned interaction_registry_summary__thunk(const unsigned char *p,unsigned n) { unsigned (*target)(const unsigned char *,unsigned)=interaction_registry_summary; return target(p,n); }
API unsigned interaction_registry_summary__linear_chain(const unsigned char *p,unsigned n) { return interaction_registry_summary__linear_chain_inner(p,n); }
API unsigned interaction_registry_summary__linear_chain_inner(const unsigned char *p,unsigned n) { return interaction_registry_summary(p,n); }
int main(void) { unsigned i,j,n; unsigned char p[256]; for(i=0;i<16;i++) { n=i*7; for(j=0;j<n;j++) p[j]=(unsigned char)((j*17+i*13)%127); p[n]=0;
printf("interaction_registry_summary %u %u\n",i,interaction_registry_summary(p,n));
printf("interaction_registry_summary_flipped %u %u\n",i,interaction_registry_summary_flipped(p,n));
printf("interaction_registry_summary__transparent_wrapper %u %u\n",i,interaction_registry_summary__transparent_wrapper(p,n));
printf("interaction_registry_summary__thunk %u %u\n",i,interaction_registry_summary__thunk(p,n));
printf("interaction_registry_summary__linear_chain %u %u\n",i,interaction_registry_summary__linear_chain(p,n));
} return 0; }
