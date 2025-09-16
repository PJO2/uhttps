// Project https
// header for dump_addrs.c

// An agnostic Linux/Windows IPv4/IPv6 address database
// in array format (will be qsorted)
struct S_Addrs
{
    int               naddr;
    SOCKADDR_STORAGE *sas;
};

struct S_Addrs *get_local_addresses_wrapper(struct S_Addrs *pT, int family, BOOL bFilterLocal) ;
void print_text_addrs (struct S_Addrs *pT);
