/* Domain: x,y,z are 32-bit unsigned; no pointers, no OS input.
 * Ordering selects max-min, in [0,2^32-1].
 * Foil flips result bit0; differs for every valid input.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned)==4)?1:-1];
API unsigned subject(unsigned x,unsigned y,unsigned z) { return x >= y ? x-y : y-x; }
API unsigned subject_equivalent(unsigned x,unsigned y,unsigned z) { unsigned lo=x,hi=y; if(lo>hi){lo=y;hi=x;} return hi-lo; }
API unsigned foil(unsigned x,unsigned y,unsigned z) { return (x >= y ? x-y : y-x)^1u; }
int main(void) { return 0; }
