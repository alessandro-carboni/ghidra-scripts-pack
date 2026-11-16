/* Domain: x,y,z are 32-bit unsigned; no pointers, no OS input.
 * Successive disjoint masks spread low16 bits into even positions; y occupies odd positions. Higher input bits are ignored.
 * Foil flips result bit0; differs for every valid input.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned)==4)?1:-1];
API unsigned subject(unsigned x,unsigned y,unsigned z) { unsigned r=0,i; for(i=0;i<16;i++){r|=((x>>i)&1u)<<(2*i); r|=((y>>i)&1u)<<(2*i+1);} return r; }
API unsigned subject_equivalent(unsigned x,unsigned y,unsigned z) { unsigned a=x&65535u,b=y&65535u; a=(a|(a<<8))&0x00ff00ffu; a=(a|(a<<4))&0x0f0f0f0fu; a=(a|(a<<2))&0x33333333u; a=(a|(a<<1))&0x55555555u; b=(b|(b<<8))&0x00ff00ffu; b=(b|(b<<4))&0x0f0f0f0fu; b=(b|(b<<2))&0x33333333u; b=(b|(b<<1))&0x55555555u; return a|(b<<1); }
API unsigned foil(unsigned x,unsigned y,unsigned z) { unsigned r=0,i; for(i=0;i<16;i++){r|=((x>>i)&1u)<<(2*i); r|=((y>>i)&1u)<<(2*i+1);} return r^1u; }
int main(void) { return 0; }
