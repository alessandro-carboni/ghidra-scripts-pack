/* Domain: x,y,z are 32-bit unsigned; no pointers, no OS input.
 * Disjoint byte masks map byte i to position 3-i; iterative assembly gives same permutation.
 * Foil flips result bit0; differs for every valid input.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned)==4)?1:-1];
API unsigned subject(unsigned x,unsigned y,unsigned z) { return ((x&255u)<<24)|((x&65280u)<<8)|((x>>8)&65280u)|(x>>24); }
API unsigned subject_equivalent(unsigned x,unsigned y,unsigned z) { unsigned r=0,i; for(i=0;i<4;i++) r=(r<<8)|((x>>(8*i))&255u); return r; }
API unsigned foil(unsigned x,unsigned y,unsigned z) { return (((x&255u)<<24)|((x&65280u)<<8)|((x>>8)&65280u)|(x>>24))^1u; }
int main(void) { return 0; }
