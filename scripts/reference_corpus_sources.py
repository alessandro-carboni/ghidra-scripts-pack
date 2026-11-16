"""Prospective benign source contracts; never derived from similarity results."""

HEADER = """#include <winsock2.h>
#include <windows.h>
#define KEEP __attribute__((noinline,used))
"""
FOOTER = """
KEEP unsigned no_seed(unsigned x) { return x * 3u + 1u; }
int main(void) {
    volatile unsigned a=subject(), b=equivalent(), c=foil();
    return (int)(a+b+c+no_seed(2));
}
"""

FAMILIES = {
    "debugger_status": dict(
        split="discovery",
        contract="subject/equivalent return debugger-presence truth; foil returns its complement. Same stable OS debugger state across comparisons. No anti-analysis branch or evasion is implemented.",
        negative="Same API, same observation, opposite returned truth. Intended observable collision, not a claimed ability to infer return semantics.",
        source="""KEEP unsigned subject(void) { return IsDebuggerPresent() ? 1u : 0u; }
KEEP unsigned equivalent(void) { BOOL present=IsDebuggerPresent(); return present != FALSE; }
KEEP unsigned foil(void) { return IsDebuggerPresent() ? 0u : 1u; }
""",
    ),
    "resource_module": dict(
        split="validation",
        contract=("subject/equivalent load version.dll as a data file and test whether version resource 1 has nonzero size; foil targets kernel32.dll. Assumes stable OS library contents/availability. Labels refer to resource identity, not equality of success booleans."),
        negative="Same resource-access API sequence and graph shape, distinct file-name observation.",
        source="""KEEP unsigned subject(void) {
    HMODULE m=LoadLibraryExA("version.dll",0,LOAD_LIBRARY_AS_DATAFILE);
    unsigned result=0; if(m) { HRSRC r=FindResourceA(m,MAKEINTRESOURCEA(1),RT_VERSION); result=r && SizeofResource(m,r)>0; FreeLibrary(m); } return result;
}
KEEP unsigned equivalent(void) {
    HMODULE handle=LoadLibraryExA("version.dll",0,LOAD_LIBRARY_AS_DATAFILE);
    if(!handle) return 0; HRSRC entry=FindResourceA(handle,MAKEINTRESOURCEA(1),RT_VERSION); unsigned length=entry ? SizeofResource(handle,entry) : 0; FreeLibrary(handle); return length!=0;
}
KEEP unsigned foil(void) {
    HMODULE m=LoadLibraryExA("kernel32.dll",0,LOAD_LIBRARY_AS_DATAFILE);
    unsigned result=0; if(m) { HRSRC r=FindResourceA(m,MAKEINTRESOURCEA(1),RT_VERSION); result=r && SizeofResource(m,r)>0; FreeLibrary(m); } return result;
}
""",
    ),
    "socket_lifecycle": dict(
        split="heldout",
        contract="subject/equivalent create and close an IPv4 TCP socket; foil creates and closes an IPv4 UDP socket. No connect, send, receive or external endpoint. Assumes initialized Winsock and stable resource availability; source contracts specify requested socket kind, not success alone.",
        negative="Same socket/close API sequence, different protocol/type operands. Tests information absent from graph evidence rather than assuming constants are recovered.",
        source="""KEEP unsigned subject(void) {
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); if(s==INVALID_SOCKET) return 0; closesocket(s); return 1;
}
KEEP unsigned equivalent(void) {
    SOCKET handle=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); unsigned ok=(handle!=INVALID_SOCKET);
    if(ok) closesocket(handle); return ok;
}
KEEP unsigned foil(void) {
    SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); if(s==INVALID_SOCKET) return 0; closesocket(s); return 1;
}
""",
    ),
}


def source(name):
    footer = FOOTER
    if name == "socket_lifecycle":
        footer = footer.replace("int main(void) {", "int main(void) {\n    WSADATA data; if(WSAStartup(MAKEWORD(2,2),&data)!=0) return 1;")
        footer = footer.replace("    return (int)", "    WSACleanup();\n    return (int)")
    return HEADER + FAMILIES[name]["source"] + footer


def positive(query_region, reference_region):
    if query_region not in {"subject", "equivalent", "foil"} or reference_region not in {"subject", "equivalent", "foil"}:
        raise ValueError("unknown source-contract region")
    return (query_region == "foil") == (reference_region == "foil")
