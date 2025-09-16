// Project https
// header for addrs2txt.c

// An agnostic Linux/Windows IPv4/IPv6 address database
// in array format (will be qsorted)

#ifndef TRUE
#  define FALSE (0==1)
#  define TRUE (1==1)
typedef int BOOL;
#endif

struct S_Addrs
{
    int               naddr;
    SOCKADDR_STORAGE *sas;
};

// get a sorted array of local address
struct S_Addrs *get_local_addresses_wrapper(struct S_Addrs *pT, int family, BOOL bFilterLocal) ;
// display in plain text 
char *addrs2txt (char *buf, size_t bufsize, const struct S_Addrs *pT, int family, const char *sep);
