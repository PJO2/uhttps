// ---------------------------------------------------------
// Windows portability tweaks
// ---------------------------------------------------------

#if defined (_MSC_VER) || defined (__POCC__)


#undef UNICODE

// #include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <strsafe.h>
#include <process.h>
#include <BaseTsd.h>

#include "win-dyn-load-tls.h"

#define snprintf _snprintf 
#define vsnprintf _vsnprintf 
#define strcasecmp _stricmp 
#define strncasecmp _strnicmp 
#define strnlen     strnlen_s

// print 64 bytes unsigned (for files > 4Gb)
#define _FILE_OFFSET_BITS 64
#define PRIu64   "I64u"

typedef SSIZE_T ssize_t;
typedef  int    socklen_t;

// ---      Common thread encapsulation
typedef HANDLE THREAD_ID;
typedef unsigned THREAD_RET;

#define INVALID_THREAD_VALUE (THREAD_ID) -0

THREAD_ID _startnewthread(THREAD_RET(WINAPI* lpStartAddress) (void*),
	void* lpParameter)
{
	return (THREAD_ID)_beginthreadex(NULL, 0, lpStartAddress, lpParameter, 0, NULL);
}
void _waitthreadend(THREAD_ID ThId) { WaitForSingleObject(ThId, INFINITE);   }
void _killthread(THREAD_ID ThId)    { TerminateThread(ThId, (DWORD) 0xCAFE); }


// millisecond sleep (native for Windows, not for unix)
void ssleep(int msec) { Sleep(msec); }

// socket portability
#ifndef SO_REUSEPORT
#  define SO_REUSEPORT 0
#endif

#endif


// ---------------------------------------------------------
// Unix portability tweaks
// ---------------------------------------------------------

#ifdef UNIX

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
// required by addrs2txt
#include <ifaddrs.h>
#include <net/if.h>

#include <signal.h>
#include <pthread.h>


#define WINAPI

typedef int            BOOL;
typedef uint64_t       DWORD64;

// ---      system library
static inline int GetLastError(void) { return errno; }
#define ERROR_FILE_NOT_FOUND ENOENT
static inline void ssleep(int msec) { sleep(msec / 1000); usleep((msec % 1000) * 1000); }
static inline int min(int a, int b) { return (a < b ? a : b); }


// ----     socket library and types
#define INVALID_SOCKET -1

typedef struct sockaddr_storage SOCKADDR_STORAGE;
typedef struct sockaddr* LPSOCKADDR;
typedef struct addrinfo ADDRINFO;
typedef int SOCKET;
typedef int WSADATA;
#define MAKEWORD(low,high) ( low + (high<<8) )

static inline int closesocket(int s) { return close(s); }
static inline int WSAStartup(int version, WSADATA* ws)
{
	// ignore SIGPIPE signal (socket closed), avoid to terminate main thread !!
	signal(SIGPIPE, SIG_IGN);
	return 0;
}   // 0 is success
static inline int WSACleanup() { return 0; }


// ----     strings
#define StringCchPrintf  snprintf
static inline int StringCchCopy(char* d, int n, const char* s) { strncpy(d, s, n); return 1; }
static inline int CharUpperBuff(char* s, int n) { int p = 0;  while (*s != 0 && n-- > 0) { if (islower(*s)) *s = toupper(*s), p++; }  return p; }


// ----     directories
#define MAX_PATH 512

static inline int GetFullPathName(const char* lpFileName, int nBufferLength, char* lpBuffer, char** p)
{
	if (realpath(lpFileName, lpBuffer) == NULL)
		return 0;
	if (p != NULL)
		*p = strrchr(lpBuffer, '/');
	return strlen(lpBuffer);
}

static inline int GetCurrentDirectory(int nBufferLength, char* lpBuffer)
{
	char* p;
	p = getcwd(lpBuffer, nBufferLength);
	return p == NULL ? 0 : strlen(lpBuffer);
}

static inline int SetCurrentDirectory(const char* lpPathName) { return chdir(lpPathName) == 0; }


// ----     threads
typedef pthread_t THREAD_ID;
typedef void* THREAD_RET;
#define INVALID_THREAD_VALUE ((THREAD_ID) (-1))

static inline THREAD_ID _startnewthread(THREAD_RET(WINAPI* lpStartAddress) (void*), void* lpParameter)
{
	int rc;
	THREAD_ID ThId;
	rc = pthread_create(&ThId, NULL, lpStartAddress, lpParameter);
	return rc == 0 ? ThId : INVALID_THREAD_VALUE;
}
static inline void _waitthreadend(THREAD_ID id) { pthread_join(id, NULL); }
// void _killthread (THREAD_ID ThId)  { pthread_kill (ThId, SIGINT); } 
static inline int GetExitCodeThread(THREAD_ID ThId, THREAD_RET* rez) { *rez = 0; return 0; }
static inline int CloseHandle(THREAD_ID ThId) { return 0; }

#endif

// ---------------------------------------------------------
// end of tweaks 
// ---------------------------------------------------------

