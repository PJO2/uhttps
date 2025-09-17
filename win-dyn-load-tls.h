
// win-dyn-load-tls.h
#pragma once

#if defined (_WIN32) && defined (UHTTPS_OPENSSL_DYNAMIC) 
 

#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


	int  tls_dyn_load(void);    // load crypto.DLL + libssl.DLL 
	void tls_dyn_unload(void);  // optionnel

	// --- pointers---
	extern const SSL_METHOD* (*p_TLS_server_method)(void);
	extern SSL_CTX* (*p_SSL_CTX_new)(const SSL_METHOD*);
	extern void      (*p_SSL_CTX_free)(SSL_CTX*);
	extern SSL* (*p_SSL_new)(SSL_CTX*);
	extern int       (*p_SSL_set_fd)(SSL*, int);
	extern int       (*p_SSL_accept)(SSL*);
	extern int       (*p_SSL_read)(SSL*, void*, int);
	extern int       (*p_SSL_write)(SSL*, const void*, int);
	extern int       (*p_SSL_shutdown)(SSL*);
	extern void      (*p_SSL_free)(SSL*);

	extern unsigned long (*p_ERR_get_error)(void);
	extern void          (*p_ERR_error_string_n)(unsigned long, char*, size_t);

	extern int  (*p_OPENSSL_init_ssl)(uint64_t, const void*);
	extern int  (*p_OPENSSL_init_crypto)(uint64_t, const void*);

	extern int  (*p_SSL_CTX_use_certificate_file)(SSL_CTX*, const char*, int);
	extern int  (*p_SSL_CTX_use_PrivateKey_file)(SSL_CTX*, const char*, int);
	extern int  (*p_SSL_CTX_check_private_key)(const SSL_CTX*);
	// extern int  (*p_SSL_CTX_set_min_proto_version)(SSL_CTX*, int);
	extern const SSL_CIPHER* (*p_SSL_get_current_cipher)(const SSL*);
	extern const char* (*p_SSL_CIPHER_get_name)(const SSL_CIPHER*);
	extern const char* (*p_SSL_get_version)(const SSL*);
	extern int               (*p_SSL_CTX_set_cipher_list)(SSL_CTX*, const char*);
	extern int               (*p_SSL_CTX_set_ciphersuites)(SSL_CTX*, const char*);
	extern unsigned long (*p_SSL_CTX_set_options)(SSL_CTX*, unsigned long);
	extern long (*p_SSL_CTX_ctrl)(SSL_CTX* ctx, int cmd, long larg, void* parg);

	// --- sugar syntax to keep compat code ---
#define TLS_server_method              p_TLS_server_method
#define SSL_CTX_new                    p_SSL_CTX_new
#define SSL_CTX_free                   p_SSL_CTX_free
#define SSL_new                        p_SSL_new
#define SSL_set_fd                     p_SSL_set_fd
#define SSL_accept                     p_SSL_accept
#define SSL_read                       p_SSL_read
#define SSL_write                      p_SSL_write
#define SSL_shutdown                   p_SSL_shutdown
#define SSL_free                       p_SSL_free
#define ERR_get_error                  p_ERR_get_error
#define ERR_error_string_n             p_ERR_error_string_n
#define OPENSSL_init_ssl               p_OPENSSL_init_ssl
#define OPENSSL_init_crypto            p_OPENSSL_init_crypto
#define SSL_CTX_use_certificate_file   p_SSL_CTX_use_certificate_file
#define SSL_CTX_use_PrivateKey_file    p_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_check_private_key      p_SSL_CTX_check_private_key
// #define SSL_CTX_set_min_proto_version  p_SSL_CTX_set_min_proto_version
#define SSL_get_current_cipher         p_SSL_get_current_cipher
#define SSL_CIPHER_get_name            p_SSL_CIPHER_get_name
#define SSL_get_version                p_SSL_get_version
#define SSL_CTX_set_cipher_list        p_SSL_CTX_set_cipher_list
#define SSL_CTX_set_ciphersuites       p_SSL_CTX_set_ciphersuites
#define SSL_CTX_set_options            p_SSL_CTX_set_options
#define SSL_CTX_ctrl  p_SSL_CTX_ctrl

#else

// Non-Windows : do not change anythink
static inline int  tls_dyn_load(void) { return 0; }
static inline void tls_dyn_unload(void) {}

#endif // _WIN32

