#ifndef UTILITIES_H
#define UTILITIES_H

#include <gnutls/gnutls.h>

void check_alert( gnutls_session_t session, int ret );
int  tcp_connect( void );
void tcp_close( int sd );

#endif // UTILITIES_H
