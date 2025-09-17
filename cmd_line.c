// --------------------------------------------------------
// uhttps : a minimal web server which compile under MacOS, Linux and Windows
// by Ph. Jounin September 2029
// 
// License: GPLv2
// Sources : 
//              - nweb23.c from IBM and Nigel Griffiths
//              - mweb.cpp from Ph. Jounin
//              - uweb.cpp from Ph. Jounin
// ---------------------------------------------------------


// Changes:


#include "compat.h"


#include "uhttps.h"
#include "log.h"

/* Print usage/help text (kept local to avoid extra dependencies) */
 void print_usage(FILE *out) 
 {
        fprintf(out,
            "uhttps - minimal static web server\n"
            "\nUsage:\n"
            "  %s [options]\n"
            "\nNetworking:\n"
            "  -4                    IPv4 only\n"
            "  -6                    IPv6 only\n"
            "  -i ADDR               Bind to this local address (IPv4 or IPv6)\n"
            "  -p PORT               HTTP port (default %s)\n"
            "  --tls                 Enable TLS (HTTPS)\n"
            "  --tls-port PORT       HTTPS port (default %s)\n"
            "  --cert FILE           PEM certificate (fullchain)\n"
            "  --key  FILE           PEM private key\n"
            "  --tls-dir DIR         Directory where OpenSSL DLLs are located (Windows)\n"
            "  --redirect-http       When TLS is enabled, redirect plain HTTP to https://\n"
            "\nContent & files:\n"
            "  -d DIR                Web root (default is current directory)\n"
            "  -x FILE               Default index file for directories (default %s)\n"
            "  -c t|b|TYPE           Default content-type for unknown extensions\n"
            "                        't' or -ct => %s   |  'b' or -cb => %s\n"
            "\nConcurrency & logs:\n"
            "  -s N                  Max simultaneous connections (default %d)\n"
            "  -g MSEC               Slow down: wait MSEC between chunks (dev/testing)\n"
            "  -v                    Increase verbosity (repeatable)\n"
            "  -q                    Decrease verbosity\n"
            "  -t                    Prefix logs with timestamps\n"
            "  -V                    Print version and exit\n"
            "  -h, --help            Show this help and exit\n",
            "uhttps",
            DEFAULT_HTTP_PORT,
            DEFAULT_TLS_PORT,
            DEFAULT_HTMLFILE,
            DEFAULT_TEXT_TYPE,
            DEFAULT_BINARY_TYPE,
            DEFAULT_MAXTHREADS
        );
}; // Usage 

// load default configuration
struct S_Settings sSettings = 
{ 
            WARN, FALSE,                            // logging
            DEFAULT_MAXTHREADS, FALSE,              // system
            TRUE, TRUE, NULL,                     // Global Network
            DEFAULT_HTTP_PORT,                      // HTTP settings
            FALSE, "cert.pem", "private.key", DEFAULT_TLS_PORT, 
            DEFAULT_SSL_DIR, FALSE,                 // tls settings
            ".", DEFAULT_HTMLFILE, NULL             // HTML settings
};



// -------------------
// inits 
// -------------------

/* Fail with message + usage */
void die_bad(const char *msg, const char *opt) 
{
        fprintf(stderr, "Error: %s%s%s\n\n",
                msg ? msg : "invalid option",
                (opt ? " : " : ""), (opt ? opt : ""));
        print_usage(stderr);
        exit(1);
};

/* Parse an integer with bounds (inclusive). If lo==hi, skip range check. */
void parse_int_bounded(const char *opt, const char *val, int *out, int lo, int hi) 
{
    char *end = NULL;
    long v = strtol(val, &end, 10);
    if (!val || *val == '\0' || end == val || *end != '\0')
        die_bad("invalid integer value for", opt);
    if (lo != hi && (v < lo || v > hi))
        die_bad("out-of-range value for", opt);
    *out = (int)v;
} // parse_int_bounded


    /* Set default content-type from token:
       - "t" / "text" / "text/plain" => DEFAULT_TEXT_TYPE
       - "b" / "binary" / "application/octet-stream" => DEFAULT_BINARY_TYPE
       - anything else is taken literally as a MIME type string */
void set_default_ctype(const char *tok) 
{
    if (!tok || !*tok) die_bad("missing value for", "-c");
    if (tok[1] == '\0') 
    {
        char ch = (char)tolower((unsigned char)tok[0]);
        if (ch == 't') sSettings.szDefaultContentType = DEFAULT_TEXT_TYPE;
        else if (ch == 'b') sSettings.szDefaultContentType = DEFAULT_BINARY_TYPE;
        else die_bad("unknown -c value (use t|b|<mime>)", tok);
    }
    else if (strcasecmp(tok, "t") == 0 || strcasecmp(tok, "text") == 0 || strcasecmp(tok, "text/plain") == 0) 
    {
        sSettings.szDefaultContentType = DEFAULT_TEXT_TYPE;
    }
    else if (strcasecmp(tok, "b") == 0 || strcasecmp(tok, "binary") == 0 || strcasecmp(tok, "application/octet-stream") == 0) 
    {
        sSettings.szDefaultContentType = DEFAULT_BINARY_TYPE;
    }
    else
    {
        sSettings.szDefaultContentType = tok; /* literal MIME string */
    }
};


  // process args (mostly populate settings structure)
  // loosely processed : (user can crash with invalid args, may be not anymore)
int ParseCmdLine(int argc, char *argv[])
{
    // Defaults are set elsewhere (sSettings is global). We only parse/override here.
    for (int ark=1; ark < argc; ark++) 
    {
        const char *arg = argv[ark];
        if (!arg || !*arg) continue;

        /* Non-option token? treat as error to keep interface clean */
        if (arg[0] != '-') {
            die_bad("unexpected positional argument", arg);
        }

        /* ---- Long options: --name or --name=value ---- */
        if (arg[1] == '-') {
            const char *name = arg + 2;
            const char *eq   = strchr(name, '=');
            size_t namelen   = eq ? (size_t)(eq - name) : strlen(name);
            const char *val  = NULL;

            /* Compare name (len-limited) to a literal */
#define LONGOPT_IS(lit) (strncasecmp(name, (lit), namelen) == 0 && (lit)[namelen] == '\0')
            /* Fetch value from "--opt=value" or the next argv token */
#define TAKE_STR_VALUE(entry, optlit) \
    do { \
        if (eq) { \
            val = eq + 1; \
            if (!*val) die_bad("missing value for", "--" optlit); \
        } else { \
            if (++ark >= argc) die_bad("missing value for", "--" optlit); \
            val = argv[ark]; \
        } \
        entry = (char *) val; \
    } while (0)

            if (LONGOPT_IS("help")) 
            {
                print_usage(stdout);
                exit(0);
            } 
            else if (LONGOPT_IS("tls")) 
            {
                if (eq) die_bad("option does not take a value", "--tls");
                sSettings.bTLS = TRUE;
            }
            else if (LONGOPT_IS("redirect-http")) 
            {
                if (eq) die_bad("option does not take a value", "--redirect-http");
                sSettings.bRedirectHttp = TRUE;
            }
            else if (LONGOPT_IS("cert")) 
                TAKE_STR_VALUE(sSettings.tls_cert,     "cert");
            else if (LONGOPT_IS("key")) 
                TAKE_STR_VALUE(sSettings.tls_key,      "key");
            else if (LONGOPT_IS("tls-port")) 
                TAKE_STR_VALUE(sSettings.szTlsPort,    "tls-port");
            else if (LONGOPT_IS("tls-dir")) 
                TAKE_STR_VALUE(sSettings.szOpenSSLDir, "tls-dir");
            else 
                die_bad("unknown option", arg);
            continue;
        }

        /* ---- Short options: -p8080, -p 8080, -ct, -c t, -vvt, etc. ---- */
        for (size_t k = 1; arg[k] != '\0'; k++) 
        {
            char ch = arg[k];
            const char *val = NULL;   /* for options that take a value */

// Helpers: value is the rest of this token or next argv 
// TAKE_NEXT_VALUE is string type if low_int=high_int=0
#define REMAINS (&arg[k+1])
#define TAKE_NEXT_VALUE(optlit) \
    do { \
        if (REMAINS[0]) { \
            val = REMAINS; \
            k = strlen(arg) - 1; /* consume the rest of this token */ \
        } else { \
            if (++ark >= argc) die_bad("missing value for", optlit); \
            val = argv[ark]; \
        } \
    } while (0)

            switch (ch) 
            {
            case '4': sSettings.bIPv6 = FALSE; break;
            case '6': sSettings.bIPv4 = FALSE; break;
            case 't': sSettings.timestamp = TRUE; break;
            case 'q': sSettings.uVerbose--; break;
            case 'v': sSettings.uVerbose++; break;

            case 'V':
                /* Print version and exit. Keep this simple to avoid extra deps. */
                fprintf(stdout, "uhttps version %s\n", UHTTPS_VERSION);
                exit(0);

            case 'h':
                print_usage(stdout);
                exit(0);

            case 'd':
                TAKE_NEXT_VALUE("-d");
                sSettings.szDirectory = (char *) val;
                break;

            case 'i':
                TAKE_NEXT_VALUE("-i");
                sSettings.szBoundTo = (char *) val;
                break;

            case 'p':
                TAKE_NEXT_VALUE("-p");
                sSettings.szHTTPPort = (char *) val;
                break;

            case 's':
                TAKE_NEXT_VALUE("-s");
                parse_int_bounded("-s", val, &sSettings.max_threads, 1, 1<<20);
                break;

            case 'g':
                TAKE_NEXT_VALUE("-g");
                parse_int_bounded("-g", val, &sSettings.slow_down, 0, 3600000);
                break;

            case 'x':
                TAKE_NEXT_VALUE("-x");
                sSettings.szDefaultHtmlFile = (char *) val;
                break;

            case 'c':
                /* Accept "-ct" / "-cb" / "-c t" / "-c b" / "-c application/json" */
                if (REMAINS[0]) {
                    set_default_ctype(REMAINS);
                    k = strlen(arg) - 1; /* we consumed the rest of token */
                } else {
                    if (++ark >= argc) die_bad("missing value for", "-c");
                    const char *v = argv[ark];
                    /* Allow legacy tokens "ct"/"cb" as well */
                    if (strcasecmp(v, "ct") == 0)       set_default_ctype("t");
                    else if (strcasecmp(v, "cb") == 0)  set_default_ctype("b");
                    else                                set_default_ctype(v);
                }
                break;

            default: 
                char unk[3] = {'-', ch, 0};
                die_bad("unknown option", unk);
            } /* switch ch */

            /* If we consumed the rest of a clustered token for a value option,
               the inner loop already advanced 'k' to the string end. */
        } /* for each char in clustered short option */
    } /* for argv */

 return 0;
} // ParseCmdLine


// check that args are ok
int SanityChecks (const struct S_Settings *p)
{
   if (p->bTLS) {
        if (!p->tls_cert || !p->tls_key) {
            fprintf(stderr, "TLS enabled but --cert/--key not both provided\n");
            return FALSE;
        }
   }
    /* Final sanity: keep at least one IP family */
    if (!sSettings.bIPv4 && !sSettings.bIPv6)
    {
        die_bad("IPv4 and IPv6 both disabled (use -4 or -6, not both)", NULL);
    }

    /* Clamp verbosity into known range if your enum defines bounds */
    if (sSettings.uVerbose < FATAL) sSettings.uVerbose = FATAL;
    if (sSettings.uVerbose > ALL)   sSettings.uVerbose = ALL;
   return TRUE;
}



  // main program : read args, create listening socket and wait for incoming connections
int main(int argc, char *argv[])
{
    ParseCmdLine(argc, argv); // override default settings
    if (! SanityChecks (& sSettings))
                exit(1);

    if (! Setup ())
        exit(1);

    for (  ;  ; )
    {
        doLoop ();
    } // for (; ; )
      // cleanup

    Cleanup();

    return 0;
}

