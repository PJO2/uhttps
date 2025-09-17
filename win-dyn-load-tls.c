
//
// dynamicall load OpenSSL functions at runtime on Windows
// much simpler on linux (-lssl -lcrypto !!)
//

// win-dyn-load-tls.c
#if defined (_WIN32) && defined (UHTTPS_OPENSSL_DYNAMIC) 

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "uhttps.h"
#include "log.h"

#include "win-dyn-load-tls.h"

#define SizeOfTab(x) ((sizeof(x) / sizeof(x[0])))

const char *DLL_DIR_ENVIRONMENT_VARIABLE="UHTTPS_OPENSSL_DIR";

// --- Pointeurs globaux ---
const SSL_METHOD* (*p_TLS_server_method)(void) = NULL;
SSL_CTX* (*p_SSL_CTX_new)(const SSL_METHOD*) = NULL;
void      (*p_SSL_CTX_free)(SSL_CTX*) = NULL;
SSL*      (*p_SSL_new)(SSL_CTX*) = NULL;
int       (*p_SSL_set_fd)(SSL*, int) = NULL;
int       (*p_SSL_accept)(SSL*) = NULL;
int       (*p_SSL_read)(SSL*, void*, int) = NULL;
int       (*p_SSL_write)(SSL*, const void*, int) = NULL;
int       (*p_SSL_shutdown)(SSL*) = NULL;
void      (*p_SSL_free)(SSL*) = NULL;

unsigned long (*p_ERR_get_error)(void) = NULL;
void          (*p_ERR_error_string_n)(unsigned long, char*, size_t) = NULL;

int  (*p_OPENSSL_init_ssl)(uint64_t, const void*) = NULL;
int  (*p_OPENSSL_init_crypto)(uint64_t, const void*) = NULL;

int  (*p_SSL_CTX_use_certificate_file)(SSL_CTX*, const char*, int) = NULL;
int  (*p_SSL_CTX_use_PrivateKey_file)(SSL_CTX*, const char*, int) = NULL;
int  (*p_SSL_CTX_check_private_key)(const SSL_CTX*) = NULL;
// int  (*p_SSL_CTX_set_min_proto_version)(SSL_CTX*, int) = NULL;

const SSL_CIPHER* (*p_SSL_get_current_cipher)(const SSL*) = NULL;
const char* (*p_SSL_CIPHER_get_name)(const SSL_CIPHER*) = NULL;
const char* (*p_SSL_get_version)(const SSL*) = NULL;
int               (*p_SSL_CTX_set_cipher_list)(SSL_CTX*, const char*) = NULL;
int               (*p_SSL_CTX_set_ciphersuites)(SSL_CTX*, const char*) = NULL;
unsigned long (*p_SSL_CTX_set_options)(SSL_CTX*, unsigned long) = NULL;
long (*p_SSL_CTX_ctrl)(SSL_CTX* ctx, int cmd, long larg, void* parg) = NULL;


static HMODULE hSSL = NULL, hCRYPTO = NULL;
static int g_loaded = 0;

static void log_loaded_module(const char* tag, HMODULE h) {
    char p[MAX_PATH * 2] = { 0 };
    if (h && GetModuleFileNameA(h, p, (DWORD)sizeof p))
        fprintf(stderr, "[uhttps] %s => %s\n", tag, p);
    else
        fprintf(stderr, "[uhttps] %s => (null)\n", tag);
}


static FARPROC need(HMODULE h, const char* dll, const char* name) {
    FARPROC p = h ? GetProcAddress(h, name) : NULL;
    if (!p) {
        LOG(ERROR,
            "Cannot find symbol '%s' in %s.\n"
            "Please check the OpenSSL version (v3 recommended)\n",
            name, dll);
    }
    return p;
}

static HMODULE load_single_dll(const char* dir, const char* name) {
    HMODULE h = NULL;
    char path[MAX_PATH * 2];
    if (dir && *dir) {
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s", dir, name);
        SetLastError(0);
        h = LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!h) LOG(DEBUG, "LoadLibraryExA('%s') failed (err=%lu)\n", path, GetLastError());
    } else {
        LOG(DEBUG, "Trying to load DLL %s (no directory provided)\n", name);
    }
    if (!h) {
        SetLastError(0);
        h = LoadLibraryExA(name, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!h) LOG(DEBUG, "LoadLibraryExA('%s') failed (err=%lu)\n", name, GetLastError());
    }
    LOG(INFO, "Loading DLL %s...%s\n", path, h==NULL ? "NOK": "OK");
    return h;
} // load_single_dll

static int load_openssl_dlls(void) {
    if (g_loaded) return 0;

    const char* dir, *env;
    // if environnement variable provided and default settings not overridden : take it
    env = getenv(DLL_DIR_ENVIRONMENT_VARIABLE);
    dir = env && strcmp (DEFAULT_SSL_DIR, sSettings.szOpenSSLDir)==0  ? env : sSettings.szOpenSSLDir;
    LOG(DEBUG, "searching for DLLs in directory %s\n", dir);
    // Try OpenSSL 3 first then 1.1.1
    const char* ssl_candidates[] =    { "libssl-3-x64.dll",    "libssl-1_1-x64.dll" }; 
    const char* crypto_candidates[] = { "libcrypto-3-x64.dll", "libcrypto-1_1-x64.dll" };

    for (int i = 0; i < SizeOfTab(crypto_candidates) && !hCRYPTO; ++i) {
        hCRYPTO = load_single_dll(dir, crypto_candidates[i]);
        LOG(DEBUG, "loading dll %s => %p (err=%lu)\n",
            crypto_candidates[i], (void*)hCRYPTO, GetLastError());
        // log_loaded_module("libcrypto", hCRYPTO);
    }
    // Then libssl
    for (int i = 0; i < SizeOfTab(ssl_candidates) && !hSSL; ++i) {
        hSSL = load_single_dll(dir, ssl_candidates[i]);
        LOG(DEBUG, "loading dll %s => %p (err=%lu)\n",
            ssl_candidates[i], (void*)hSSL, GetLastError());
        // log_loaded_module("libssl", hSSL);
    }

    if (!hSSL || !hCRYPTO) {
        LOG(ERROR, "uhttps - Missing DLL\n"
            "Unable to load the required OpenSSL DLLs.\n"
            "Required: %s / %s (or their 1.1.1 variants).\n"
            "Place them next to uhttps.exe, add their folder to PATH,\n"
            "or set the %s environment variable.\n"
            "or set the --tls-dir parameter.\n\n",
            ssl_candidates[0], crypto_candidates[0], DLL_DIR_ENVIRONMENT_VARIABLE);
        return -1;
    }
    return 0;
}

int tls_dyn_load(void) {
    if (g_loaded) return 0;
    LOG(WARN, "Dynamically loading OpenSSL DLLs\n");

    if (load_openssl_dlls() != 0) return -1;
    // symbol parsing
    p_TLS_server_method = (const SSL_METHOD * (*)(void)) need(hSSL, "libssl", "TLS_server_method");
    p_SSL_CTX_new =       (SSL_CTX * (*)(const SSL_METHOD*)) need(hSSL, "libssl", "SSL_CTX_new");
    p_SSL_CTX_free =      (void (*)(SSL_CTX*)) need(hSSL, "libssl", "SSL_CTX_free");
    p_SSL_new =           (SSL * (*)(SSL_CTX*)) need(hSSL, "libssl", "SSL_new");
    p_SSL_set_fd =        (int (*)(SSL*, int)) need(hSSL, "libssl", "SSL_set_fd");
    p_SSL_accept =        (int (*)(SSL*)) need(hSSL, "libssl", "SSL_accept");
    p_SSL_read =          (int (*)(SSL*, void*, int)) need(hSSL, "libssl", "SSL_read");
    p_SSL_write =         (int (*)(SSL*, const void*, int)) need(hSSL, "libssl", "SSL_write");
    p_SSL_shutdown =      (int (*)(SSL*)) need(hSSL, "libssl", "SSL_shutdown");
    p_SSL_free =          (void (*)(SSL*)) need(hSSL, "libssl", "SSL_free");

    p_ERR_get_error =                  (unsigned long (*)(void)) need(hCRYPTO, "libcrypto", "ERR_get_error");
    p_ERR_error_string_n =             (void (*)(unsigned long, char*, size_t)) need(hCRYPTO, "libcrypto", "ERR_error_string_n");
    p_OPENSSL_init_ssl =               (int (*)(uint64_t, const void*)) need(hSSL, "libssl", "OPENSSL_init_ssl");
    p_OPENSSL_init_crypto =            (int (*)(uint64_t, const void*)) need(hCRYPTO, "libcrypto", "OPENSSL_init_crypto");

    p_SSL_CTX_use_certificate_file =   (int (*)(SSL_CTX*, const char*, int)) need(hSSL, "libssl", "SSL_CTX_use_certificate_file");
    p_SSL_CTX_use_PrivateKey_file =    (int (*)(SSL_CTX*, const char*, int)) need(hSSL, "libssl", "SSL_CTX_use_PrivateKey_file");
    p_SSL_CTX_check_private_key =      (int (*)(const SSL_CTX*)) need(hSSL, "libssl", "SSL_CTX_check_private_key");
//    p_SSL_CTX_set_min_proto_version =  (int (*)(SSL_CTX*, int)) need(hSSL, "libssl", "SSL_CTX_set_min_proto_version");
    p_SSL_get_current_cipher =         (const SSL_CIPHER * (*)(const SSL*)) need(hSSL, "libssl", "SSL_get_current_cipher");
    p_SSL_CIPHER_get_name =            (const char* (*)(const SSL_CIPHER*))   need(hSSL, "libssl", "SSL_CIPHER_get_name");
    p_SSL_get_version =                (const char* (*)(const SSL*)) need(hSSL, "libssl", "SSL_get_version");
    p_SSL_CTX_set_cipher_list =        (int (*)(SSL_CTX*, const char*)) need(hSSL, "libssl", "SSL_CTX_set_cipher_list");
    p_SSL_CTX_set_ciphersuites =       (int (*)(SSL_CTX*, const char*))  need(hSSL, "libssl", "SSL_CTX_set_ciphersuites");
    p_SSL_CTX_set_options =            (unsigned long (*)(SSL_CTX*, unsigned long)) need(hSSL, "libssl", "SSL_CTX_set_options");
    p_SSL_CTX_ctrl =                   (long (*)(SSL_CTX*, int, long, void*)) need(hSSL, "libssl", "SSL_CTX_ctrl");
	// Is there some missing symbol ?
    if (!p_TLS_server_method || !p_SSL_CTX_new || !p_SSL_new || !p_SSL_accept)
        return -1;

    g_loaded = 1;
    return 0;
} // tls_dyn_load

void tls_dyn_unload(void) {
    if (hSSL) { FreeLibrary(hSSL);    hSSL = NULL; }
    if (hCRYPTO) { FreeLibrary(hCRYPTO); hCRYPTO = NULL; }
    g_loaded = 0;
}
#endif // defined (_WIN32) && defined (UHTTPS_OPENSSL_DYNAMIC) 



