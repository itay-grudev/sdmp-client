#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <getopt.h>
#include <iostream>
#include <gnutls/gnutls.h>


#include "utilities.h"

#define MAX_BUF 1024
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define MSG "GET / HTTP/1.0\r\n\r\n"

bool VerboseFlag = false;

// Help and usage
void help();

inline int usage(){
    std::cout << "Usage: sdmp-client [-u <username>] [-p <password>] [-h] [--help]\n";
    return 0;
}

inline int error(){
    std::cerr << "Usage: sdmp-client [-u <username>] [-p <password>] [-h] [--help]" << std::endl;
    return 1;
}

/**
 * Prompts the user for credentials
 * @param  gnutls_session_t
 * @param  username
 * @param  password
 * @return 0 on success -1 on error
 */
int credentials_entry( gnutls_session_t, char*[], char*[] );

int main( int argc, char* argv[] )
{
    char * username = nullptr;
    char * password = nullptr;
    gnutls_session_t session;
    gnutls_srp_client_credentials_t srp_cred;
    gnutls_certificate_credentials_t cert_cred;

    // Parsing command line arguments
    int c;
    while( true ){
        static struct option long_options[] = {
            { "help",      no_argument,       nullptr, 'h' },
            { "verbose",   no_argument,       nullptr, 'v' },
            { "user",      required_argument, nullptr, 'u' },
            { "password",  required_argument, nullptr, 'p' },
            {0, 0, 0, 0}
        };

        int option_index = 0;
        c = getopt_long( argc, argv, "hvu:p:", long_options, &option_index );

        if( c == -1 ) // End of options
            break;

        switch( c ){
            case 0:
                if( long_options[option_index].flag != 0 ) // if set do nothing
                    break;
                std::printf( "option %s", long_options[option_index].name );
                if( optarg )
                    std::printf( " with arg %s", optarg );
                std::printf( "\n" );
                break;
            case 'v':
                VerboseFlag = true;
                std::printf( "VerboseFlag\n" );
                break;
            case 'h':
                return usage();
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            default:
                return error();
        }
    }

    int ret;
    int sd, ii;
    char buffer[MAX_BUF + 1];

    if( gnutls_check_version( "3.1.4" ) == NULL ) {
        std::cerr << "GnuTLS 3.1.4 or later is required." << std::endl;
        return error();
    }

    // For backwards compatibility with gnutls < 3.3.0
    gnutls_global_init();

    gnutls_srp_allocate_client_credentials( &srp_cred );
    gnutls_certificate_allocate_credentials( &cert_cred );

    // Manually set user credentials if provided
    if( username != nullptr && password != nullptr ){
        gnutls_srp_set_client_credentials( srp_cred, username, password );
    } else {
        // Prompt the user to input their credentials via credentials_entry
        gnutls_srp_set_client_credentials_function( srp_cred, credentials_entry );
    }


        gnutls_certificate_set_x509_trust_file( cert_cred, CAFILE, GNUTLS_X509_FMT_PEM );

        // Connects to server
        sd = tcp_connect();

        // Initialize TLS session
        gnutls_init(&session, GNUTLS_CLIENT);


        // Set the priorities.
        gnutls_priority_set_direct(session,
                                   "NORMAL:+SRP:+SRP-RSA:+SRP-DSS",
                                   NULL);

        // Put the SRP credentials to the current session
        gnutls_credentials_set(session, GNUTLS_CRD_SRP, srp_cred);
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cert_cred);

        gnutls_transport_set_int(session, sd);
        gnutls_handshake_set_timeout(session,
                                     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        // Perform the TLS handshake
        do {
                ret = gnutls_handshake(session);
        }
        while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

        if (ret < 0) {
                std::cerr <<"*** Handshake failed" << std::endl;
                gnutls_perror(ret);
                goto end;
        } else {
                char *desc;

                desc = gnutls_session_get_desc(session);
                std::printf("- Session info: %s\n", desc);
                gnutls_free(desc);
        }

        gnutls_record_send(session, MSG, strlen(MSG));

        ret = gnutls_record_recv(session, buffer, MAX_BUF);
        if (gnutls_error_is_fatal(ret) != 0 || ret == 0) {
                if (ret == 0) {
                        std::printf
                            ("- Peer has closed the GnuTLS connection\n" );
                        goto end;
                } else {
                        std::cerr << "*** Error: \n" << gnutls_strerror(ret) << std::endl;
                        goto end;
                }
        } else
                check_alert(session, ret);

        if (ret > 0) {
                std::printf("- Received %d bytes: ", ret);
                for (ii = 0; ii < ret; ii++) {
                        fputc(buffer[ii], stdout);
                }
                fputs("\n", stdout);
        }
        gnutls_bye(session, GNUTLS_SHUT_RDWR);

      end:

        tcp_close(sd);

        gnutls_deinit(session);

        gnutls_srp_free_client_credentials(srp_cred);
        gnutls_certificate_free_credentials(cert_cred);

        gnutls_global_deinit();

        return 0;
}
typedef struct gnutls_srp_client_credentials_st {
	char *username;
	char *password;
};
int credentials_entry( gnutls_session_t session, char** username, char** password ){
    char *tmp;

    gnutls_srp_client_credentials_t *srp_cred;
    gnutls_credentials_get( session, GNUTLS_CRD_SRP, (void**)&srp_cred );
    printf("cred user %s\n", srp_cred->username );
    printf("cred pass %s\n", srp_cred.password );

    // If the username is not specified as a command line argument attempt to
    // get the USER environment variable or abort.
    std::string user;
    tmp = std::getenv( "USER" );
    if( ! tmp ){
        std::cout << "Enter username: " << std::flush;
        std::cin >> user;
        tmp = (char*)user.c_str();
    }
    if( ! tmp ){
        std::cerr << "Error: No username specified!" << std::endl;
        return -1;
    }
    *username = (char*)gnutls_malloc( strlen( tmp ) + 2 );
    strcpy( *username, tmp );

    // If no password is specified prompt the user to enter a password
    tmp = getpass( "Enter password: " );
    if( ! tmp ){
        std::cerr << "Error: No password specified!" << std::endl;
        return -1;
    }
    *password = (char*)gnutls_malloc( strlen( tmp ) + 2 );
    strcpy( *password, tmp );

    return 0;
}
