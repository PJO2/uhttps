// ----------------------------------------------------
// Project: uhhtps
//  by PJO September 2025
// dump_addrs.c
// Retrieve all addresses from the local machine
// ----------------------------------------------------


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#else
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

typedef struct sockaddr_storage SOCKADDR_STORAGE;
#endif

#include "dump_addrs.h"

// -----------------------------------------
// Compare two sockaddr pointers for sorting
int sockaddr_cmp(const void *a, const void *b) 
{
const struct sockaddr *sa = (const struct sockaddr *)a;
const struct sockaddr *sb = (const struct sockaddr *)b;

    // First sort by family: AF_INET before AF_INET6
    if (sa->sa_family != sb->sa_family)
        return (int)sa->sa_family - (int)sb->sa_family;

    if (sa->sa_family == AF_INET) 
    {
        const struct sockaddr_in *ia = (const struct sockaddr_in *)sa;
        const struct sockaddr_in *ib = (const struct sockaddr_in *)sb;

        // Compare IPs (network order is fine for memcmp)
        int r = memcmp(&ia->sin_addr, &ib->sin_addr, sizeof(struct in_addr));
        if (r != 0) return r;

        // If same IP, compare ports
        return (int)ntohs(ia->sin_port) - (int)ntohs(ib->sin_port);

    } 
    else if (sa->sa_family == AF_INET6) 
    {
        const struct sockaddr_in6 *ia6 = (const struct sockaddr_in6 *)sa;
        const struct sockaddr_in6 *ib6 = (const struct sockaddr_in6 *)sb;

        int r = memcmp(&ia6->sin6_addr, &ib6->sin6_addr, sizeof(struct in6_addr));
        if (r != 0) return r;

        return (int)ntohs(ia6->sin6_port) - (int)ntohs(ib6->sin6_port);
    }
    return 0;
} // sockaddr_cmp


// -----------------------------------------
// sort then print out the addresses
void addrs2txt (char *buf, int bufsize, const struct S_Addrs *pT, int family, const char *sep)
{
int ark;
char host[NI_MAXHOST];
int len=0;
int seplen = sep==NULL ? 0 : strlen(sep);

    buf[--bufsize]=0; // strncpy do not add the 0 if overflow -> make bufize 1 char shorter
    // sort sa structure (can not use text compare since 192.168.1.1 will be before 3.1.1.1)
    qsort (pT->sas, pT->naddr, sizeof (pT->sas[0]), sockaddr_cmp);
    for (ark=0; ark<pT->naddr ; ark++)
    {
        // if family is given
        if (family!=AF_UNSPEC  && pT->sas[ark].ss_family!=family) continue;

        if (getnameinfo (& pT->sas[ark],
                          (socklen_t)((pT->sas[ark].ss_family == AF_INET) ? 
                                  sizeof(struct sockaddr_in) :
                                  sizeof(struct sockaddr_in6)),
                          host, sizeof(host),
                          NULL, 0,
                          NI_NUMERICHOST) == 0) 
        {
            hostlen = strlen(host);
            if (ark!=0) 
               if (seplen>0 && bufsize-len>sep)
               {  
                   memcpy(buf+len, sep, seplen+1);
                   len += seplen;
               }
            if (bufsize-len>hostlen)
            {
                   memcpy(buf+len, host, hostlen+1);
                   len += hostlen;
            }
        }
    }
} // print_text_addrs



// -----------------------------------
// wrapper to fill the sAddrs table (different APIs for Windows and Linux/MacOS)
// -----------------------------------

// push a sockaddr into the S_Addrs table
static void push_sockaddr(const struct sockaddr* sa, struct S_Addrs *pT) {
    if (!sa) return;
    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) return;
	// filter out loobacks and link-local addresses
    if (sa->sa_family == AF_INET) 
    {
        const struct in_addr* a = &((const struct sockaddr_in*)sa)->sin_addr;
        if ((ntohl(a->s_addr) >> 24) == 127) return;                // 127.0.0.0/8
        if ((ntohl(a->s_addr) & 0xFFFF0000U) == 0xA9FE0000U) return; // 169.254.0.0/16
      // queue the sa structure
        memcpy ( & pT->sas[pT->naddr++], sa, sizeof (struct sockaddr_in));
    }
    else if (sa->sa_family == AF_INET6) {
        const struct in6_addr* a6 = &((const struct sockaddr_in6*)sa)->sin6_addr;
        if (IN6_IS_ADDR_LOOPBACK(a6)) return ;        // ::1
        if (IN6_IS_ADDR_LINKLOCAL(a6)) return;       // fe80::/10
      // queue the sa structure
        memcpy ( & pT->sas[pT->naddr++], sa, sizeof (struct sockaddr_in6));
    }
} // push_sockaddr

// Use the system API to stack all sockaddr structures
struct S_Addrs *get_local_addresses_wrapper(struct S_Addrs *pT, int family) 
{
    pT->naddr = 0;
#ifdef _WIN32
ULONG dwSize=10240, dwResult;
ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
int ark;

	// Is buffer is too small the first returns the size of Adapter Addresses list
	IP_ADAPTER_ADDRESSES* pAdapterAddresses = NULL;
	for ( dwResult=ERROR_BUFFER_OVERFLOW, ark=0 ;  ark<2 && dwResult==ERROR_BUFFER_OVERFLOW ;   ark++) 
    {
        pAdapterAddresses = (PIP_ADAPTER_ADDRESSES) realloc(pAdapterAddresses, dwSize);
        if (pAdapterAddresses == NULL)  return NULL; 
        dwResult = GetAdaptersAddresses(family, flags, NULL, pAdapterAddresses, &dwSize);
    }
    if (dwResult!=NO_ERROR) return NULL; // should not happen

    // how many address do we have (maximise) ?
    int count=0;
    for (IP_ADAPTER_ADDRESSES* aa = pAdapterAddresses; aa!=NULL; aa = aa->Next) 
        for (IP_ADAPTER_UNICAST_ADDRESS* ua = aa->FirstUnicastAddress; ua!=NULL; ua = ua->Next) 
           count++;           
    // printf ("allocating %d slots of %lu bytes\n", count, sizeof(pT->sas[0]));
    pT->sas = calloc (sizeof(pT->sas[0]), count);
    if (pT->sas==NULL) return NULL;

    // filter out inactive interfaces
    for (IP_ADAPTER_ADDRESSES* aa = pAdapterAddresses; aa!=NULL; aa = aa->Next) 
    {
        if (aa->OperStatus != IfOperStatusUp) continue;
        for (IP_ADAPTER_UNICAST_ADDRESS* ua = aa->FirstUnicastAddress; ua!=NULL; ua = ua->Next) 
            push_sockaddr(ua->Address.lpSockaddr, pT);
    }
    // sockaddr have been duplicated ->  pAdapterAddresses can be freed
    free(pAdapterAddresses);

#else
    struct ifaddrs* ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }
    int count=0;
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) 
       count++;
    printf ("allocating %d slots\n", count);
    pT->sas = calloc (sizeof(struct sockaddr), count);
    if (pT->sas==NULL) return NULL;
    for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        // Interface up & adresse IPv4/IPv6
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (family==AF_UNSPEC || ifa->ifa_addr->sa_family==family)
            push_sockaddr(ifa->ifa_addr, pT);
    }
    freeifaddrs(ifaddr);
#endif

    return pT;
} // get_local_addresses_wrapper

#ifdef TEST_MAIN

int families[] = { AF_UNSPEC, AF_INET, AF_INET6 };

int main(void) {
    // Winsock init (idempotent pour le process)
    // little database to store all sockaddr
struct S_Addrs sAddr;
char buf [100];
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif    
    for (int ark=0 ; ark<3 ; ark++)
    {
       printf ("\nfamily is %d\n", families[ark]);
       get_local_addresses_wrapper(& sAddr, families[ark]);
       addrs2txt(buf, sizeof buf &sAddr, families[ark], ", ");
       free (sAddr.sas);
    }
#ifdef _WIN32
	WSACleanup();
#endif    
}
#endif


