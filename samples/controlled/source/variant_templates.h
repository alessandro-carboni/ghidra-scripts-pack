/* Prepared in step 8.0; instantiated and validated in step 8.3.
 * Pure routines only: no external side effects; identical arguments/results.
 */
#define TRANSPARENT_WRAPPER(name) \
API unsigned name##_wrapper(const unsigned char *p,unsigned n) { return name(p,n); }
#define THUNK(name) \
API unsigned name##_thunk(const unsigned char *p,unsigned n) { return name(p,n); }
#define LINEAR_CHAIN(name) \
API unsigned name##_chain_inner(const unsigned char *p,unsigned n) { return name(p,n); } \
API unsigned name##_chain(const unsigned char *p,unsigned n) { return name##_chain_inner(p,n); }
