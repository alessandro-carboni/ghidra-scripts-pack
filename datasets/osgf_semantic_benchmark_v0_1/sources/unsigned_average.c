/* Domain: x,y,z are 32-bit unsigned; no pointers, no OS input.
 * x+y=2*(x&y)+(x^y); quotient/remainder decomposition also yields floor((x+y)/2) without 32-bit overflow.
 * Foil flips result bit0; differs for every valid input.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned)==4)?1:-1];
API unsigned subject(unsigned x,unsigned y,unsigned z) { return (x&y)+((x^y)>>1); }
API unsigned subject_equivalent(unsigned x,unsigned y,unsigned z) { return (x>>1)+(y>>1)+((x&1u)&(y&1u)); }
API unsigned foil(unsigned x,unsigned y,unsigned z) { return ((x&y)+((x^y)>>1))^1u; }
int main(void) { return 0; }
