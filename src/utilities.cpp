#include "utilities.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>


/**
 * Connects to the peer and returns a socket
 * descriptor.
 */
int tcp_connect(void)
{
        const char *PORT = "5556";
        const char *SERVER = "127.0.0.1";
        int err, sd;
        struct sockaddr_in sa;

        /* connects to server
         */
        sd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&sa, '\0', sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(atoi(PORT));
        inet_pton(AF_INET, SERVER, &sa.sin_addr);

        err = connect(sd, (struct sockaddr *) &sa, sizeof(sa));
        if (err < 0) {
                fprintf(stderr, "Connect error\n");
                exit(1);
        }

        return sd;
}

/**
 * Closes the given socket descriptor.
 */
void tcp_close( int sd ){
        shutdown( sd, SHUT_RDWR ); /* no more receptions */
        close( sd );
}

/**
 * This function will check whether the given return code from
 * a gnutls function (recv/send), is an alert, and will print
 * that alert.
 */
void check_alert(gnutls_session_t session, int ret)
{
        gnutls_alert_description_t last_alert;

        if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
            || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
                last_alert = gnutls_alert_get(session);

                /* The check for renegotiation is only useful if we are
                 * a server, and we had requested a rehandshake.
                 */
                if (last_alert == GNUTLS_A_NO_RENEGOTIATION &&
                    ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
                        printf("* Received NO_RENEGOTIATION alert. "
                               "Client Does not support renegotiation.\n");
                else
                        printf("* Received alert '%d': %s.\n", last_alert,
                               gnutls_alert_get_name(last_alert));
        }
}
