/* Domain: x,y,z are 32-bit unsigned; no pointers, no OS input.
 * Each output bit is input bit i xor bit i+1; bit32 is zero.
 * Foil flips result bit0; differs for every valid input.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned)==4)?1:-1];
API unsigned subject(unsigned x,unsigned y,unsigned z) { return x^(x>>1); }
API unsigned subject_equivalent(unsigned x,unsigned y,unsigned z) { unsigned r=0,i; for(i=0;i<32;i++) r|=(((x>>i)^((x>>1)>>i))&1u)<<i; return r; }
API unsigned foil(unsigned x,unsigned y,unsigned z) { return (x^(x>>1))^1u; }
int main(void) { return 0; }
