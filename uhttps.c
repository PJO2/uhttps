// --------------------------------------------------------
// uhttps : a minimal web server which compile under 
//        MacOS, Linux and Windows
// by Ph. Jounin September 2025
// 
// License: GPLv2
// Sources : 
//              - nweb23.c from IBM and Nigel Griffiths
//              - mweb.cpp from Ph. Jounin
//              - uweb.c from Ph. Jounin
// ---------------------------------------------------------



#include <openssl/ssl.h>
#include <openssl/err.h>

// avoid warning "variable set but unused"
#define __DUMMY(x) ( (void) (x) )

#define INVALID_FILE_VALUE NULL



// Compatibility 
#include "compat.h"

#include "log.h"
#include "uhttps.h"
#include "html_extensions.h"
#include "addrs2txt.h"
#include "win-dyn-load-tls.h"

  // ---------------------------------------------------------
  // Protocol Error codes and text
  // ---------------------------------------------------------
// managed status code
enum     { HTTP_OK=200,
           HTTP_PARTIAL=206,
           HTTP_BADREQUEST=400,
           HTTP_SECURITYVIOLATION=403,
           HTTP_NOTFOUND=404,
           HTTP_METHODNOTALLOWED=405,
           HTTP_TYPENOTSUPPORTED=415,
           HTTP_SERVERERROR=500 };

// requests processed by uhttps
enum {    HTTP_GET = 1,   HTTP_HEAD,  };

// Reporting
struct S_ErrorCodes
{
        int         status_code;
        const char *txt_content;
        const char *html_content;
}
sErrorCodes[] =
{
    { HTTP_BADREQUEST,        "Bad Request",            "HTTP malformed request syntax.",  },
    { HTTP_NOTFOUND,          "Not Found",              "The requested URL was not found on this server.",  },
    { HTTP_SECURITYVIOLATION, "Forbidden",              "Directory traversal attack detected.",             },
    { HTTP_TYPENOTSUPPORTED,  "Unsupported Media Type", "The requested file type is not allowed on this static file webserver.<br>\
                                                         Options -ct or -cb will override this control.", },
    { HTTP_METHODNOTALLOWED,  "Method Not Allowed",     "The requested file operation is not allowed on this static file webserver.", },
    { HTTP_SERVERERROR,       "Internal Server Error",  "Internal Server Error, can not access to file anymore.", },
};
// HTML and HTTP message return on Error
const char szHTMLErrFmt[]  = "<html><head>\n<title>%d %s</title>\n</head><body>\n<h1>%s</h1>\n%s\n</body></html>\n";
const char szHTTPDataFmt[] = "HTTP/1.1 %d %s\nServer: uhttps-%s\nContent-Length: %" PRIu64 "\nConnection: close\nContent-Type: %s\n\n";


  // ---------------------------------------------------------
  // Operationnal states : settings, HTML types  and thread data
  // ---------------------------------------------------------

enum e_THREADSTATUS { THREAD_STATE_INIT, THREAD_STATE_RUNNING, THREAD_STATE_EXITING, THREAD_STATE_DOWN };
typedef enum e_THREADSTATUS    THREADSTATUS ;

// tls/tcp socket identifiers 
typedef struct S_tls_conn {
    SOCKET   skt;
    BOOL     bTLS;
    SSL     *ssl;  /* NULL for plain HTTP */
} conn_t;

static SSL_CTX *g_tls_ctx = NULL;

// The structure for each transfer
struct S_ThreadData
{
        int         request;    // GET or HEAD
        conn_t      conn;       // socket descripto and SSL info
        SOCKADDR_STORAGE sa;                    // keep track of the client
        char       *buf;                        // buffer for communication allocated in main thread
        unsigned    buflen;                     // sizeof this buffer
        char        url_filename[MAX_PATH];     // URL to be retrieved
        char        long_filename[MAX_PATH];    // canonical file name with path
        char       *file_name;                  // pointer inside long_filename
        char       *file_type;                  // pointer inside long_filename
        FILE       *hFile;                      // file handle
        DWORD64     qwFileCurrentPos;           // pos in file (also the number of bytes sent to the client)
        DWORD64     qwFileSize;                 // total size of the file
        time_t      tStartTrf;                  // when the transfer has started

        THREAD_ID   ThreadId;                  // thread data (posix) or Id (Windows)
        THREADSTATUS ThStatus;                  // thread status
        struct S_ThreadData *next;
};

// Thread database
struct S_ThreadData  *pThreadDataHead;			// array allocated in main
int nbThreads = 0;                      // # running threads


// status passed to logger funcion
enum { LOG_BEGIN, LOG_END, LOG_RESET };


/////////////////////////////////////////////////////////////////
// utilities functions :
//      - report error
/////////////////////////////////////////////////////////////////


// Function LastErrorText. Thread unsafe
// A wrapper for FormatMessage : retrieve the message text for a system-defined error
char *LastErrorText(void) {
    static char buf[512];
#ifdef _WIN32
    DWORD err = GetLastError();
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, err, MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),
                             buf, (DWORD)sizeof buf, NULL);
    if (!n) _snprintf(buf, sizeof buf, "Windows error %lu", (unsigned long)err);
    return buf;
#else
    strncpy(buf, strerror(errno), sizeof buf); buf[sizeof buf-1]=0;
    return buf;
#endif
} // LastErrorText



  /////////////////////////////////////////////////////////////////
  // utilities socket operations :
  //	 - check that socket is still opened by listen at it
  //	 - return MSS
  //     - bind its socket
  //     - init WSA socket
  //     - Check if IPv6 is enabled
  //     - read wrapper
  //     - send wrapper
  //     - close wrapper
  /////////////////////////////////////////////////////////////////

// a Windows wrapper to  call WSAStartup...
int InitSocket()
{
    WSADATA  wsa;
    int      iResult;
    iResult = WSAStartup(MAKEWORD(2, 0), &wsa);
    // iResult = 1;
    if (iResult != 0)
    {
        LOG (FATAL, "Error : WSAStartup failed\nError %d (%s)\n", GetLastError(), LastErrorText());
        exit(-1);    // no recovery
    }
    return iResult;
} // InitSocket

int IsTransferCancelledByPeer(SOCKET skt)
{
    struct timeval to = { 0, 0 };
    fd_set fdset;
    char   recv_buf[32]; // read a significant amount of data
                             // since the HTTP request is still in buffer
    int   iResult;
    // check if socket has been closed by client
    FD_ZERO(&fdset);
    FD_SET(skt, &fdset);
    iResult = select((int) skt+1, &fdset, NULL, NULL, &to)>0
        && recv(skt, recv_buf, sizeof recv_buf, MSG_PEEK) == 0;
    return iResult;
} // IsTransferCancelledByPeer


  // return the max segment size for this socket
int GetSocketMSS(SOCKET skt)
{
    int tcp_mss = 0;
    socklen_t opt_len = sizeof tcp_mss;
    int iResult;

    iResult = getsockopt(skt, IPPROTO_TCP, TCP_MAXSEG, (char*) & tcp_mss , & opt_len);
    if (iResult < 0)
    {
        LOG (WARN, "Failed to get TCP_MAXSEG for master socket.\nError %d (%s)\n", 
                     GetLastError(), LastErrorText());
        return 1200; // fallback
    }
    return tcp_mss;
} // GetSocketMSS


  // return TRUE IPv6 is enabled on the local system
BOOL IsIPv6Enabled(void)
{
    SOCKET s = INVALID_SOCKET;
    int Rc;
    // just try to open an IPv6 socket
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    Rc = GetLastError();  // should be WSAEAFNOSUUPORT 10047
    closesocket(s);
        __DUMMY(Rc);

    return s != INVALID_SOCKET;
} // IsIPv6Enabled

// dump addresses 
int dump_addrinfo(ADDRINFO *runp)
{
    char hostbuf[50], portbuf[10];
    int e;

        LOG (DEBUG, "family: %d, socktype: %d, protocol: %d, ", runp->ai_family, runp->ai_socktype, runp->ai_protocol);
        e = getnameinfo(
            runp->ai_addr, (socklen_t) runp->ai_addrlen,
            hostbuf, sizeof(hostbuf),
            portbuf, sizeof(portbuf),
            NI_NUMERICHOST | NI_NUMERICSERV
    );
    LOG (DEBUG, "host: %s, port: %s\n", hostbuf, portbuf);
       __DUMMY(e);
return 0;
}


// create a listening socket
// and bind it to the HTTP port
SOCKET BindServiceSocket(const char *port, const char *sz_bind_addr)
{
    SOCKET             sListenSocket = INVALID_SOCKET;
    int                Rc;
    ADDRINFO           Hints, *res, *cur;
    int                True = 1;

    memset(&Hints, 0, sizeof Hints);
    if (sSettings.bIPv4 && ! sSettings.bIPv6)     	Hints.ai_family = AF_INET;    // force IPv4
    else if (sSettings.bIPv6  && !sSettings.bIPv4)  Hints.ai_family = AF_INET6;   // force IPv6
    else                                            Hints.ai_family = AF_UNSPEC;    // use IPv4 or IPv6, whichever

    // resolve the address and port we want to bind the server
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
    Rc = getaddrinfo(sz_bind_addr, port, &Hints, &res);
    if (Rc != 0)
    {
        LOG (ERROR, "Error : specified address %s is not recognized\nError %d (%s)\n", 
              sz_bind_addr, GetLastError(), LastErrorText());
        return INVALID_SOCKET;
    }

    // if getaddr_info returns only one entry: take it (option -i, -4, -6 or ipv4 only host)
    // else search for  the ipv6 socket (then deactivate the option IPV6_V6ONLY)
    if (res->ai_next == NULL)   cur = res;
    else                        for (cur = res ; cur!=NULL  &&  cur->ai_family!=AF_INET6 ; cur = cur->ai_next);
    assert (cur!=NULL);

    if (sSettings.uVerbose)
        dump_addrinfo (cur);

    // now open socket based on either selection
    sListenSocket = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
    if (sListenSocket == INVALID_SOCKET)
    {
        LOG (ERROR, "Error : Can't create socket\nError %d (%s)\n", GetLastError(), LastErrorText());
        return INVALID_SOCKET;
    }

    // now allow both IPv6 and IPv4 by disabling IPV6_ONLY (necessary since Vista)
    // http://msdn.microsoft.com/en-us/library/windows/desktop/bb513665(v=vs.85).aspx
    // does not work under XP --> do not check return code
    if (res->ai_next != NULL)  // did we select the ipv6 entry ?
    {
        int Param = FALSE;
        Rc = setsockopt(sListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)& Param, sizeof Param);
    }

    // allow socket to be reopened quickly
    if (setsockopt(sListenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)& True, sizeof True) == INVALID_SOCKET )
        LOG (WARN, "Error : Can't not activate addr reuse mode, will continue anyway\n  Error %d (%s)\n", GetLastError(), LastErrorText());

    // bind the socket to the active interface
    Rc = bind(sListenSocket, cur->ai_addr, (int) cur->ai_addrlen);
    if (Rc == INVALID_SOCKET)
    {
        LOG (ERROR, "Error : Can't not bind socket\nError %d (%s)\n", GetLastError(), LastErrorText());
        closesocket(sListenSocket);
        return INVALID_SOCKET;
    }

    // create the listen queue
    Rc = listen(sListenSocket, LISTENING_QUEUE_SIZE);
    if (Rc == -1)
    {
        LOG (ERROR, "Error : on listen\nError %d (%s)\n", GetLastError(), LastErrorText());
        closesocket(sListenSocket);
        return INVALID_SOCKET;
    }

    freeaddrinfo(res);
    return   Rc == INVALID_SOCKET ? Rc : sListenSocket;
} // BindServiceSocket

// read, send and close wrappers
static ssize_t io_read(conn_t *c, void *buf, size_t n) {
    return c->ssl ? SSL_read(c->ssl, buf, n)
                  : recv(c->skt, buf, n, 0);
}
static ssize_t io_write(conn_t *c, const void *buf, size_t n) {
    return c->ssl ? SSL_write(c->ssl, buf, n)
                  : send(c->skt, buf, n, 0);
}
static void conn_close(conn_t *c) {
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
    if (c->skt >= 0) { closesocket(c->skt); c->skt = INVALID_SOCKET; }
}



  /////////////////////////////////////////////////////////////////
  // HTTP protocol management
  //      - decode incoming message
  //      - read file and send it through the Http channel
  // resources are freed by calling thread
  /////////////////////////////////////////////////////////////////

// util: send an pre formated error code
int HTTPSendError(conn_t *c, int HttpStatusCode)
{
        char    szContentBuf[512], szHTTPHeaders[256];
        int     ark;
        size_t  iResult;

        // search error code in sErrorCodes array
        for ( ark=0 ; sErrorCodes[ark].status_code != 0  && sErrorCodes[ark].status_code!=HttpStatusCode ; ark++ );
        assert (sErrorCodes[ark].status_code==HttpStatusCode);  // exit if error code not found (bug)

        StringCchPrintf (szContentBuf, sizeof szContentBuf, szHTMLErrFmt,
                    sErrorCodes[ark].status_code,
                    sErrorCodes[ark].txt_content,
                    sErrorCodes[ark].txt_content,
                    sErrorCodes[ark].html_content );
        // now we have the string, get its length and send headers and string
        StringCchPrintf (szHTTPHeaders, sizeof szHTTPHeaders, szHTTPDataFmt,
                    sErrorCodes[ark].status_code,
                    sErrorCodes[ark].txt_content,
                    UHTTPS_VERSION,
                    (DWORD64) strlen (szContentBuf),
                    "text/html" );
        iResult = io_write (c, szHTTPHeaders, (int) strlen (szHTTPHeaders));
        iResult = io_write (c, szContentBuf,  (int) strlen (szContentBuf));
        return (int) iResult;
} // HTTPSendError


  // a minimal reporting for the server side
int LogTransfer(const struct S_ThreadData *pData, int when, int http_status)
{
    char szAddr[INET6_ADDRSTRLEN], szServ[NI_MAXSERV];
    int Rc;

    if (sSettings.uVerbose==0)  return 0;

    strcpy (szAddr, "");
    strcpy (szServ, "");
    Rc = getnameinfo((LPSOCKADDR)& pData->sa, sizeof pData->sa,
            szAddr, sizeof szAddr,
            szServ, sizeof szServ,
            NI_NUMERICHOST | NI_NUMERICSERV);
    if (Rc!=0) 
    {
        errno = Rc;
        LOG (ERROR, "getnameinfo failed.\nError %d (%s)\n", Rc, LastErrorText());
                return -1;
    }
    // do not use ipv4 mapped address
    if (* (unsigned short *) szAddr == * (unsigned short *) "::")
        memmove (szAddr, & szAddr[sizeof "::ffff:" - 1], sizeof "255.255.255.255");

    switch (when)
    {
        case LOG_BEGIN:
                LOG (DEBUG, "uhttps answers with headers:\n--->>\n%s--->>\n", pData->buf);
                LOG (WARN, "From %s:%s, GET %s, MSS is %u, burst size %d\n", 
            szAddr, szServ, pData->file_name, GetSocketMSS(pData->conn.skt), pData->buflen);
        break;

            case LOG_END:
                LOG (WARN, "From %s:%s, GET %s: %" PRIu64 " bytes sent, status : %d, time spent %lus\n",
            szAddr, szServ, pData->file_name==NULL ? "unknown" : pData->file_name,
            pData->qwFileCurrentPos, http_status, 
            time(NULL) - pData->tStartTrf
        );
        break;
            case LOG_RESET:
        LOG (WARN, "GET %s: Reset by %s:%s, %" PRIu64 " bytes sent, status : %d, time spent %lus\n",
            pData->file_name==NULL ? "unknown" : pData->file_name,  
                        szAddr, szServ, 
            pData->qwFileCurrentPos, http_status,
            time(NULL) - pData->tStartTrf
        );
        break;
    }
return 0;
} // LogTransfer


  // translate file extension into HTTP content-type field
  // Get extension type 
const char *GetHtmlContentType(const char *os_extension)
{
    int ark;

    if (os_extension == NULL)  
        return  sSettings.szDefaultContentType;

    // search for extension (do case insentive matching even for unix)
    for (ark = 0; ark<sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]); ark++)
        if (strcasecmp (sHtmlTypes[ark].ext, os_extension) == 0) break;
    if (ark >= sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]))
    {
        if (sSettings.szDefaultContentType==NULL)
            LOG (WARN, "Unregistered file extension\n");
        return sSettings.szDefaultContentType;		// NULL if not overridden
    }
    return (char *) sHtmlTypes[ark].filetype;
} // GetHtmlContentType


  // extract the file name 
  //			1- do not crash if we receive misformatted packets
  // HTTP formatting is GET _space_ file name ? arguments _space_ HTTP/VERSION _end of line_
BOOL ExtractFileName(const char *szHttpRequest, size_t request_length, char *szFileName, int name_size)
{
    const char *pCur=NULL, *pEnd;
    int         len, url_length;

    // check that string is nul terminated (ok already done in caller)
    if (strnlen(szHttpRequest, request_length) == request_length)
        return FALSE;

    // check that request is long enough to find the file name
    if (request_length < sizeof "GET / HTTP/1.x\n" - 1) return FALSE;


    // search second word (first has already been decoded) and space has been checked
    for (pCur = szHttpRequest; *pCur != ' '; pCur++);  // skip first word
    for (; *pCur == ' '; pCur++);  // go to second word

    // file name is supposed to start with '/', anyway accepts if / is missing
    for (; *pCur == '/'; pCur++);  // skip  /

    // go to next work or '?' or end of line (missing HTTP version)
    pEnd = strpbrk(pCur, "\r\n ?");
    // add: check that pEnd is not NULL !
    if (pEnd == NULL || (*pEnd != ' ' && *pEnd != '?'))		// if anormal endings
    {
        return FALSE;
    }
    // now we ignore all the other stuff sent by client....
    // just copy the file name
    url_length = (int) (pEnd - pCur);
    if (url_length == 0)		// file name is /
        StringCchCopy(szFileName, name_size, sSettings.szDefaultHtmlFile);
    else
    {
        len = min(url_length, name_size - 1);
        memcpy(szFileName, pCur, len);
        szFileName[len] = 0;
    }
    return TRUE;
} // ExtractFileName

// Extract The host from the HTTP request (Needed to redirect)
BOOL ExtractHostName(const char *szHttpRequest, size_t request_length, char *szHostName, int host_size)
{
const char *pCur=NULL;
int         ark=0;
   host_size--; // leave a place for the ending 0
   // search for a new line :
   for ( pCur=szHttpRequest ; pCur!=NULL ; pCur=strchr (pCur, '\n') )
   {
       pCur++; // begining of next line
       if (     request_length - (pCur-szHttpRequest) > sizeof ("Host:1.1.1.1") 
             && strncasecmp (pCur, "Host:", sizeof ("Host:")-1)==0 )
        {
             pCur += sizeof ("Host:")-1;
             while (*pCur==' ') pCur++;
             // search for ':' or end of line 
             for (ark=0 ; 
                  ark<host_size && *pCur!=0 && *pCur!=':' && !isspace(*pCur); 
                  ark++, pCur++)
                  szHostName[ark]=*pCur;
        }
   }
   szHostName[ark]=0;
return ark!=0 ;
} // ExtractHostName


// Minimal HTTP->HTTPS redirect (no Host:, no query handling) 
int SendRedirect2Https (struct S_ThreadData *pData) 
{
char host[256];
char path[256];
char resp[200+256+256];

    LOG(DEBUG, "Incoming Request: %s\n", pData->buf);
    if (!ExtractHostName(pData->buf, pData->buflen, host, sizeof host))
    {
        LOG(WARN, "Can not retrieve Host parameter\n");
        return FALSE;
    }
    strcpy (path, "/");
    ExtractFileName (pData->buf, pData->buflen, path+1, (int)sizeof(path)-1 ); 
    LOG(DEBUG, "EXtract: host is %s, path is %s\n", host, path);
    /* Minimal RFC-compliant redirect */
    StringCchPrintf (resp, sizeof(resp),
                    "HTTP/1.1 308 Permanent Redirect\r\n"
                    "Location: https://%s:%s%s\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "Server: uhttps-%s\r\n"
                    "\r\n",
                    host, sSettings.szTlsPort,
                    path,
                    UHTTPS_VERSION);
    resp [sizeof(resp)-1]=0;
    LOG (DEBUG, "redirection message:\n%s", resp);
    io_write(&pData->conn, resp, strlen(resp));
return TRUE;
} // SendRedirect2Https


  // Read request and extract file name
  // if error, can return abruptely: resources freed in calling funtions
int DecodeHttpRequest(struct S_ThreadData *pData, size_t request_length)
{
    char     szCurDir[MAX_PATH];

    // double check buffer overflow
    if (request_length >= pData->buflen)
        exit(-2);
    pData->buf[request_length++] = 0;

    // dump complete request
    LOG (DEBUG, "client request:\n<<---\n%s<<---\n", pData->buf);

    // ensure request is a GET or HEAD
    CharUpperBuff(pData->buf, sizeof "GET " - 1);
    if (memcmp(pData->buf, "GET ", sizeof "GET " - 1) == 0)
        pData->request = HTTP_GET;
    else if (memcmp(pData->buf, "HEAD ", sizeof "HEAD " - 1) == 0)
        pData->request = HTTP_HEAD;
    else  // reject other requests !
    {
        LOG (WARN, "Only Simple GET and HEAD operations supported\n");
        return HTTP_METHODNOTALLOWED;
    }
    // extract file name
    if (!ExtractFileName(pData->buf, request_length, pData->url_filename, sizeof pData->url_filename))
    {
        LOG (WARN, "invalid HTTP formatting\n");
        return HTTP_BADREQUEST;
    }

        // dry-run : try to open it (sanaty checks not done)
    pData->hFile = fopen (pData->url_filename, "rb");
    if (pData->hFile==INVALID_FILE_VALUE)   
    {
        LOG (WARN, "file %s not found/access denied\n", pData->url_filename);
        return HTTP_NOTFOUND;
    }
    fclose (pData->hFile);
    pData->hFile=INVALID_FILE_VALUE;

    // get canonical name && locate the file name location
    // Valid since we are in the main thread
    if ( ! GetFullPathName(pData->url_filename, MAX_PATH, pData->long_filename, &pData->file_name) )
    {
        if (GetLastError()==ERROR_FILE_NOT_FOUND)   
                LOG (WARN, "File |%s| not found\n", pData->url_filename);
        else    LOG (WARN, "s: invalid File formatting\n", pData->url_filename);
        pData->file_name = NULL;
        return HTTP_BADREQUEST;
    }

    if (pData->file_name == NULL)
        pData->file_type = NULL;
    else
        pData->file_type = strrchr(pData->file_name, '.');	// search for '.'

                                    // sanity check : do not go backward in the directory structure
    GetFullPathName(".", MAX_PATH, szCurDir, NULL);
#ifdef UNSAFE__DEBUG
    LOG(TRACE, "file to be retreived is %s, path is %s, file is %s, cur dir is %s\n", pData->long_filename, pData->buf, pData->file_name, szCurDir);
#endif
    size_t rootlen = strlen(szCurDir);
    if (      memcmp(szCurDir, pData->long_filename, strlen(szCurDir)) != 0
         ||   (pData->long_filename[rootlen] != '\\' && pData->long_filename[rootlen] != '/' && pData->long_filename[rootlen] != '\0')) 
    {
        LOG (WARN, "directory traversal detected\n");
        return HTTP_SECURITYVIOLATION;
    }
    return HTTP_OK;
} // DecodeHttpRequest



// Thread base
THREAD_RET WINAPI HttpTransferThread(void * lpParam)
{
    size_t   bytes_rcvd;
    size_t   bytes_read, bytes_sent;
    const char     *pContentType;
    struct S_ThreadData *pData = (struct S_ThreadData *)  lpParam;
    int      iHttpStatus=HTTP_BADREQUEST;
    int      tcp_mss;

    pData->ThStatus = THREAD_STATE_RUNNING;   // thread is now running

        // read http request
    bytes_rcvd = io_read(& pData->conn, pData->buf, pData->buflen - 1);
    if (bytes_rcvd < 0)
    {
        LOG (ERROR, "Error in recv\nError %d (%s)\n", GetLastError(), LastErrorText());
        goto cleanup;
    }
    pData->buf[bytes_rcvd] = 0; // now buf is zero terminated !!

    // redirect to HTTPS ?
    if (!pData->conn.bTLS && sSettings.bTLS && sSettings.bRedirectHttp) 
    {
        LOG(DEBUG, "redirecteing\n");
        SendRedirect2Https(pData);
        goto cleanup;
    }
    // modify buffer size depending on MSS
    if ( (tcp_mss = GetSocketMSS(pData->conn.skt)) > 0 ) 
        {
            pData->buflen = DEFAULT_BURST_PKTS * tcp_mss;
            pData->buf = realloc (pData->buf, pData->buflen);
            if (pData->buf==NULL)
                { LOG (FATAL, "can not allocate memory\n"); 
                  exit(3); }
        }

    // request is valid and pData filled with requested file
    iHttpStatus = DecodeHttpRequest(pData, bytes_rcvd);
    if (iHttpStatus != HTTP_OK)
        goto cleanup;

    // check extension and get the HTTP content=type of the file
    pContentType = GetHtmlContentType(pData->file_type);
    if (pContentType == NULL) 
    {
        iHttpStatus = HTTP_TYPENOTSUPPORTED;
        goto cleanup;
    }

    // open file in binary mode (file length and bytes sent will match)
    pData->hFile = fopen (pData->long_filename, "rb");
    if (pData->hFile == INVALID_FILE_VALUE)
    {
        LOG (ERROR, "Error opening file %s\nError %d (%s)\n", 
                             pData->long_filename, GetLastError(), LastErrorText());
        iHttpStatus = HTTP_NOTFOUND;
        goto cleanup;
    }
    // Get  file size, by moving to the end of file
    fseek (pData->hFile, 0, SEEK_END);
    pData->qwFileSize = ftell (pData->hFile);
    fseek (pData->hFile, 0, SEEK_SET);


    // file accepted -> send HTTP 200 answer
    StringCchPrintf(pData->buf, pData->buflen,
        szHTTPDataFmt,
        HTTP_OK, "OK",
        UHTTPS_VERSION,
        pData->qwFileSize,
        pContentType);
    io_write (& pData->conn, pData->buf, (int) strlen(pData->buf));
    LogTransfer(pData, LOG_BEGIN, 0);

    if (pData->request == HTTP_GET)
    {
        iHttpStatus = HTTP_PARTIAL;
        do
        {
            bytes_read = fread(pData->buf, 1, pData->buflen, pData->hFile);
            bytes_sent = io_write(& pData->conn, pData->buf, (int) bytes_read);
            pData->qwFileCurrentPos += bytes_read;

            if (pData->buflen == bytes_read && IsTransferCancelledByPeer(pData->conn.skt))
            {
                LogTransfer(pData, LOG_RESET, HTTP_PARTIAL);
                break;
            }
            LOG(TRACE, "read %d bytes from %s\n", bytes_read, pData->long_filename);

            if (sSettings.slow_down) ssleep(sSettings.slow_down);
        } while (bytes_read > 0);

        if (bytes_read == 0 && !feof(pData->hFile))	//note: if transfer cancelled report OK anyway
        {
            LOG (ERROR, "Error in ReadFile\nError %d (%s)\n", GetLastError(), LastErrorText());
            iHttpStatus = HTTP_SERVERERROR;
            goto cleanup;
        }
    } // HTTP GET request
    // if we reach this point file was successfully sent
    iHttpStatus = HTTP_OK;

    __DUMMY(bytes_sent);

cleanup:
    if (pData->conn.skt != INVALID_SOCKET)
    {
        if (iHttpStatus >= HTTP_BADREQUEST)   
            HTTPSendError (& pData->conn, iHttpStatus);
        conn_close(& pData->conn);
        pData->conn.skt = INVALID_SOCKET;
    }
    if (pData->buf != NULL)
    {
        free(pData->buf);
        pData->buf = NULL;
    }
    if (pData->hFile != INVALID_FILE_VALUE)
    {
        fclose (pData->hFile);
        pData->hFile = INVALID_FILE_VALUE;
    }
    // return Error to client
    LogTransfer(pData, LOG_END, iHttpStatus);
    ssleep(1000);

    pData->ThStatus = THREAD_STATE_EXITING;
    return (THREAD_RET) 0;  // return NULL to please compiler

} // HttpTransferThread



  /////////////////////////////////////////////////////////////////
  // main thread
  //      - create the listening socket
  //      - loop on waiting for incoming connection
  //      - start a new thread for each connection
  //      - free thread resource  after termination
  //      - maintain threads data link list
  /////////////////////////////////////////////////////////////////



  // Do Some cleanup on terminated Threads (use pThreadDataHead as global)
int ManageTerminatedThreads (void)
{
    int ark=0;
    struct S_ThreadData *pCur, *pNext, *pPrev;

    // check if threads have ended and free resources
    for (pPrev=NULL, pCur=pThreadDataHead ;  pCur!=NULL ; pCur=pNext )
    {
        pNext = pCur->next;   // pCur may be freed

        if (pCur->ThStatus==THREAD_STATE_EXITING)
        {
            // wait until thread termination
            _waitthreadend (pCur->ThreadId);
            pCur->ThStatus = THREAD_STATE_DOWN;

            // free resources (if not done before)
            if (pCur->buf!=NULL)    free (pCur->buf), pCur->buf=NULL;
            if (pCur->hFile!=INVALID_FILE_VALUE)  
                                              fclose (pCur->hFile), pCur->hFile=INVALID_FILE_VALUE;
            CloseHandle (pCur->ThreadId);
            ark++;

            // detach pCur from list, then free memory
            if (pPrev==NULL)   pThreadDataHead = pCur->next;
            else               pPrev->next     = pCur->next;
            // free record 
            free (pCur);

            --nbThreads;
        }
        else
             pPrev=pCur ; // pPrev is the last valid entry
    }
    return ark;
} // ManageTerminatedThreads


THREAD_ID StartHttpThread (SOCKET ClientSocket, const SOCKADDR_STORAGE *sa, BOOL bTLS)
{
    struct S_ThreadData *pCur;

    // resources available ? 
    if (nbThreads >= sSettings.max_threads)
    {
        LOG (WARN, "request rejected: too many simultaneous transfers\n");
        return INVALID_THREAD_VALUE;
    }

    // create a new ThreadData structure and populate it
    pCur = (struct S_ThreadData *) calloc (1, sizeof *pCur);
    if (pCur == NULL)
    {
        LOG (FATAL, "can not allocate memory\n");
        exit(2);
    }

    // populate record
    pCur->ThStatus = THREAD_STATE_INIT ; // thread pregnancy
    pCur->sa = * sa;
    pCur->buflen = DEFAULT_BUFLEN;
    pCur->buf = (char *) malloc (pCur->buflen);
    pCur->qwFileCurrentPos = 0;
    time(& pCur->tStartTrf);
    pCur->hFile = INVALID_FILE_VALUE;
    pCur->conn.skt = ClientSocket;
    pCur->conn.bTLS = bTLS;
    if (pCur->conn.bTLS)
    {
        pCur->conn.ssl = SSL_new(g_tls_ctx);
        if (pCur->conn.ssl==NULL) 
        {  
            LOG(ERROR, "Can not init SSL connection");
            free (pCur->buf);
            free (pCur);
            closesocket(ClientSocket);
            return INVALID_THREAD_VALUE;
        }
        // lik socket and ssl context
        SSL_set_fd(pCur->conn.ssl, ClientSocket);
        if (SSL_accept(pCur->conn.ssl) <= 0) 
        {
            LOG(DEBUG, "TLS handshake failed\n");
            SSL_free(pCur->conn.ssl); pCur->conn.ssl = NULL;
            closesocket(ClientSocket);
            free(pCur->buf); free(pCur);                   
            return INVALID_THREAD_VALUE;
        }
        LOG(INFO, "TLS %s / %s\n",
            SSL_get_version(pCur->conn.ssl),
            SSL_CIPHER_get_name(SSL_get_current_cipher(pCur->conn.ssl)));
    }

    if (pCur->buf == NULL)
    {
        LOG (FATAL, "can not allocate memory\n");
        exit(2);
    }

    // Pass the socket id to a new thread and listen again
    pCur->ThreadId = _startnewthread (HttpTransferThread, (void *) pCur);
    if (pCur->ThreadId == INVALID_THREAD_VALUE)
    {
        LOG (ERROR, "can not allocate thread\n");
        free (pCur->buf);
        free (pCur);
    }
    else
    {
        // insert data at the head of the list
        pCur->next = pThreadDataHead;
        pThreadDataHead = pCur;
        // register thread !
        nbThreads++;
    }
    return pCur->ThreadId;
} // StartHttpThread



// -------------------
// main loop 
// -------------------

static SOCKET HTTPListenSocket = INVALID_SOCKET;
static SOCKET TLSListenSocket  = INVALID_SOCKET;

void doLoop (void)
{
    SOCKADDR_STORAGE sa;
    socklen_t        sa_len;
    SOCKET           ClientSocket;
    struct timeval   tv_select;
    int              Rc;
    THREAD_ID        NewThread;
    fd_set           readfs;
    int              skt_max;
        
    // pre compute the max of both sockets (cast to int to get -1)
    skt_max = (int) HTTPListenSocket > (int) TLSListenSocket ? (int) HTTPListenSocket : (int) TLSListenSocket;

    // block main thread on select (wake up every 5 seconds to free resources)
    do
    {
        // worry about terminated threads
        ManageTerminatedThreads ();

        // and listen incoming connections
            FD_ZERO (&readfs);
            if (HTTPListenSocket!=INVALID_SOCKET) FD_SET (HTTPListenSocket, &readfs);
            if (TLSListenSocket!=INVALID_SOCKET)  FD_SET (TLSListenSocket, &readfs);
            tv_select.tv_sec  = SELECT_TIMEOUT;   // may have been changed by select
            tv_select.tv_usec = 0; 
            Rc = select (   skt_max+1,
                        & readfs, NULL, NULL, 
                        & tv_select);
    }
    while (Rc==0);  // 0 is timeout

    if (Rc == INVALID_SOCKET) 
    {
        LOG (FATAL, "Error : Select failed\nError %d (%s)\n", GetLastError(), LastErrorText());
        closesocket(HTTPListenSocket);
        closesocket(TLSListenSocket);
        WSACleanup();
        exit(1);
    }
    // A new connection has occurred, 
    SOCKET ListenSocket = FD_ISSET(HTTPListenSocket, &readfs) ? HTTPListenSocket :
                            FD_ISSET(TLSListenSocket, &readfs) ? TLSListenSocket : INVALID_SOCKET;
    // Accept new client connection (accept will not block)
    sa_len = sizeof sa;
    memset(&sa, 0, sizeof sa);
    ClientSocket = accept(ListenSocket, (struct sockaddr *) & sa, &sa_len);
    if (ClientSocket == INVALID_SOCKET) 
    {
        LOG (FATAL, "Error : Accept failed\nError %d (%s)\n", GetLastError(), LastErrorText());
        closesocket(ListenSocket);
        WSACleanup();
        exit(1);
    }

    // start a new thread, check if a thread has terminated
    // and return listening for incoming connections
    NewThread = StartHttpThread (ClientSocket, & sa, ListenSocket==TLSListenSocket);

    // pause either to let thread start or to pause the main loop on error
    ssleep (NewThread== INVALID_THREAD_VALUE ? 1000 : 10);

} // doLoop


// -------------------
// Setup and Cleanup
// -------------------

int TLSInit (void)
{
     // Initialize TLS
    const SSL_METHOD *method = TLS_server_method();
    g_tls_ctx = SSL_CTX_new(method);
    if (!g_tls_ctx) { LOG(ERROR, "can not start SSL, error", GetLastError()); return -1; }

    /* Safe defaults */
    SSL_CTX_set_options(g_tls_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_min_proto_version(g_tls_ctx, TLS1_2_VERSION);

    // SSL_CTX_set_options(g_tls_ctx, SSL_OP_NO_COMPRESSION);

    /* Load cert/key */
    if (SSL_CTX_use_certificate_file(g_tls_ctx, sSettings.tls_cert, SSL_FILETYPE_PEM) != 1) {
        LOG(ERROR, "Failed to load cert: %s\n", sSettings.tls_cert);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(g_tls_ctx, sSettings.tls_key, SSL_FILETYPE_PEM) != 1) {
        LOG(ERROR, "Failed to load key: %s\n", sSettings.tls_key);
        return -1;
    }
    if (SSL_CTX_check_private_key(g_tls_ctx) != 1) {
        LOG(ERROR, "Cert/Key mismatch\n");
        return -1;
    }
    return 0;
} // TLSInit


BOOL Setup (void)
{
char sbuf[MAX_PATH];

    InitSocket();
    // keep current directory to retrieve DLL (Windows) and certificate+key
    if (sSettings.bTLS) 
    {
        // link with OpenSSL dynamically if needed (Windows only)
        if (tls_dyn_load() != 0) 
            return FALSE;
        // Init OpenSSL (1.1.1/3.x) 
        OPENSSL_init_ssl(0, NULL);
        if (TLSInit() == -1)
            return FALSE;
    }

    // Now change directory before opening sockets
    if (!SetCurrentDirectory (sSettings.szDirectory))
    {
            LOG (FATAL, "can not change directory to %s\nError %d (%s)\n",
                        sSettings.szDirectory,
                        GetLastError(), LastErrorText());
            return FALSE;
    }
    GetCurrentDirectory(sizeof sbuf, sbuf);

    // And open services 
    HTTPListenSocket = BindServiceSocket (sSettings.szHTTPPort, sSettings.szBoundTo);
    if (HTTPListenSocket == INVALID_SOCKET)
            return FALSE;
    if (sSettings.bTLS) 
    {
        TLSListenSocket  = BindServiceSocket (sSettings.szTlsPort, sSettings.szBoundTo);
        if (TLSListenSocket == INVALID_SOCKET)
            return FALSE;
    } // TLS

    // Print listening address
    if (sSettings.szBoundTo==NULL)
    { 
    struct S_Addrs sAddr;
    char buf[512];
        int fam = sSettings.bIPv4 && sSettings.bIPv6 ? AF_UNSPEC : sSettings.bIPv4 ? AF_INET : AF_INET6;
        get_local_addresses_wrapper(& sAddr, fam, TRUE);
        LOG(INFO, "Listening on all local interfaces plus external addresses:\n");
        LOG(INFO, "  IPv4: %s\n", addrs2txt(buf, sizeof buf, &sAddr, AF_INET, ", "));
        LOG(INFO, "  IPv6: %s\n", addrs2txt(buf, sizeof buf, &sAddr, AF_INET6, ", "));
        free (sAddr.sas);        
    }
    if (HTTPListenSocket != INVALID_SOCKET)
            LOG(WARN, "uhttps HTTP%s on :%s:%s, base directory: %s\n",
                       TLSListenSocket  != INVALID_SOCKET ? "/HTTPs" : "",
                       sSettings.szHTTPPort, 
                       TLSListenSocket  != INVALID_SOCKET ? sSettings.szTlsPort : "",
                       sbuf
                );
    return TRUE;
} // Setup 


void Cleanup (void)
{
       ManageTerminatedThreads (); // free terminated threads resources
       closesocket(HTTPListenSocket);
       if (g_tls_ctx) { SSL_CTX_free(g_tls_ctx); g_tls_ctx = NULL; }
       WSACleanup();
} // Cleanup

