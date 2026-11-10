/* Domain: x,y,z are 32-bit unsigned; no pointers, no OS input.
 * Three compare-exchanges sort; nested inequalities select middle order statistic including ties.
 * Foil flips result bit0; differs for every valid input.
 */
#define API __declspec(dllexport) __declspec(noinline)
typedef char require_u32[(sizeof(unsigned)==4)?1:-1];
API unsigned subject(unsigned x,unsigned y,unsigned z) { unsigned a=x,b=y,c=z,t; if(a>b){t=a;a=b;b=t;} if(b>c){t=b;b=c;c=t;} if(a>b){t=a;a=b;b=t;} return b; }
API unsigned subject_equivalent(unsigned x,unsigned y,unsigned z) { return x>y ? (y>z?y:(x>z?z:x)) : (x>z?x:(y>z?z:y)); }
API unsigned foil(unsigned x,unsigned y,unsigned z) { unsigned a=x,b=y,c=z,t; if(a>b){t=a;a=b;b=t;} if(b>c){t=b;b=c;c=t;} if(a>b){t=a;a=b;b=t;} return b^1u; }
int main(void) { return 0; }
