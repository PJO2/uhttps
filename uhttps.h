// --------------------------------------------------------
// uweb : a minimal web server which compile under MacOS, Linux and Windows
// by Ph. Jounin November 2019
//
// License: GPLv2
// Module: 
//         uweb.h
// --------------------------------------------------------


#define UWEB_VERSION "1.8"

#ifndef FALSE
#  define FALSE (0==1)
#  define TRUE  (1==1)
#endif

typedef int BOOL;
// ---------------------------------------------------------
// default parameters
// ---------------------------------------------------------

#define  DEFAULT_BURST_PKTS      5
#define  DEFAULT_BUFLEN         (1448*DEFAULT_BURST_PKTS)    // buffer size for reading HTTP command and file content (2 pkts of 1500 bytes)
#define  DEFAULT_HTTP_PORT      "8080"    
#define  DEFAULT_TLS_PORT       "8443"    
#define  DEFAULT_MAXTHREADS     1024       // maximum simultaneous connections
#define  DEFAULT_HTMLFILE       "index.html" // if request is "GET / HTTP/1.1"
#define  DEFAULT_BINARY_TYPE    "application/octet-stream"
#define  DEFAULT_TEXT_TYPE      "text/plain"


#define  SELECT_TIMEOUT        5      // every 5 seconds, look for terminated threads
#define  LISTENING_QUEUE_SIZE  3      // do not need a large queue


// ---------------------------------------------------------
// sSettings is a global variable
// ---------------------------------------------------------
// uweb Settings
struct S_Settings
{
	// logging
        int   uVerbose;
        int   timestamp;
        // System
        int    max_threads;             // maximum simultaneous connections
        int    slow_down;               // msec to wait between two frames
        // Global Network configuration
        BOOL  bIPv4;
        BOOL  bIPv6;
        char  *szBoundTo;
        // http settings
        char  *szHTTPPort;
        // tls settings
        BOOL   bTLS;              /* 0/1: enable TLS */
        char   *tls_cert;         /* PEM cert (fullchain) */
        char   *tls_key;          /* PEM private key */
        char   *szTlsPort;        /* TLS listen port (default 8443) */
        BOOL   bRedirectHttp;   /* 0/1: 80/8080 -> https:// redirect */
        // HTML settings
        char  *szDirectory;
        const char  *szDefaultHtmlFile;
        const char  *szDefaultContentType;      // all files accepted with this content-type
};
extern struct S_Settings sSettings;


// ---------------------------------------------------------
// Arduino-like behavior
// ---------------------------------------------------------

int Setup(void);
void doLoop(void);
void Cleanup(void);

