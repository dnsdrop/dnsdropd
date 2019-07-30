#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <event2/event.h>

#include "ddrop/common.h"
#include "ddrop/core/log.h"
#include "ddrop/sock/socket.h"

static int
sk__get_somaxconn_(void)
{
    int    maxconn = SOMAXCONN;
    FILE * fp      = NULL;
    char   buf[1024];

    if ((fp = fopen("/proc/sys/net/core/somaxconn", "r")) == NULL) {
        return maxconn;
    }

    if (fgets(buf, sizeof(buf), fp) != NULL) {
        maxconn = atoi(buf);
    }

    fclose(fp);

    return maxconn;
}

static evutil_socket_t
sk__bind_to_sockaddr_(struct sockaddr * sk_addr,
                      socklen_t         sk_len,
                      int               sk_type,
                      const char      * dev)
{
    evutil_socket_t fd    = -1;
    int             on    = 1;
    int             error = 1;

    if ((fd = socket(sk_addr->sa_family, sk_type, 0)) == -1) {
        log_error("socket (type %d)", sk_type);
        return -1;
    }

    do {
        if (evutil_make_socket_closeonexec(fd) == -1) {
            log_error("closeonexec");
            break;
        }

        if (evutil_make_socket_nonblocking(fd) == -1) {
            log_error("nblocking");
            break;
        }

        if (evutil_make_listen_socket_reuseable(fd) == -1) {
            log_error("reuseable");
            break;
        }

        evutil_make_listen_socket_reuseable_port(fd);

        if (sk_addr->sa_family == AF_INET6) {
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                           &on, sizeof(on)) == -1) {
                break;
            }
        }

        if (dev != NULL) {
            if (setsockopt(fd,
                           SOL_SOCKET,
                           SO_BINDTODEVICE,
                           dev,
                           strlen(dev) + 1) == -1) {
                log_error("BINDTODEVICE");
                break;
            }
        }

        if (bind(fd, sk_addr, sk_len) == -1) {
            log_error("bind");
            break;
        }

        if (sk_type == SOCK_STREAM) {
            if (listen(fd, sk__get_somaxconn_()) == -1) {
                log_error("listen");
                break;
            }
        }

        error = 0;
    } while (0);

    if (error == 1) {
        if (fd != -1) {
            evutil_closesocket(fd);
        }

        return -1;
    }

    return fd;
} /* sk__bind_to_sockaddr_ */

static struct sockaddr *
sk__str_to_sockaddr_(const char * addr,
                     uint16_t     port,
                     socklen_t  * outlen)
{
    struct sockaddr_un  sockun = { 0 };
    struct sockaddr_in6 sin6   = { 0 };
    struct sockaddr_in  sin    = { 0 };
    struct sockaddr   * sa;
    size_t              sin_len;

    log_debug("addr = %s", addr);

    if (strncmp(addr, "ipv6:", 5) == 0) {
        addr            += 5;
        sin_len          = sizeof(struct sockaddr_in6);
        sin6.sin6_port   = htons(port);
        sin6.sin6_family = AF_INET6;

        if (evutil_inet_pton(AF_INET6, addr, &sin6.sin6_addr) != 1) {
            return NULL;
        }

        *outlen = sin_len;
        sa      = malloc(sin_len);
        memcpy(sa, &sin6, sin_len);

        return sa;
    }

    if (strncmp(addr, "unix:", 5) == 0) {
        addr += 5;

        if (strlen(addr) >= sizeof(sockun.sun_path)) {
            return NULL;
        }

        sin_len           = sizeof(struct sockaddr_un);
        sockun.sun_family = AF_UNIX;

        strncpy(sockun.sun_path, addr, strlen(addr));

        *outlen = sin_len;
        sa      = malloc(sin_len);
        memcpy(sa, &sockun, sin_len);

        return sa;
    }

    if (strncmp(addr, "ipv4:", 5) == 0) {
        addr += 5;
    }

    sin_len             = sizeof(struct sockaddr_in);
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = inet_addr(addr);

    *outlen             = sin_len;
    sa = malloc(sin_len);
    memcpy(sa, &sin, sin_len);


    return sa;
}             /* sock__str_to_sockaddr_ */

evutil_socket_t
ddrop_socket_bind_to_sockaddr(struct sockaddr * sk_addr,
                              socklen_t         sk_len,
                              int               sk_type)
{
    return sk__bind_to_sockaddr_(sk_addr, sk_len, sk_type, NULL);
}

evutil_socket_t
ddrop_socket_bind_to_sockaddr_dev(struct sockaddr * sk_addr,
                                  socklen_t         sk_len,
                                  int               sk_type,
                                  const char      * dev)
{
    return sk__bind_to_sockaddr_(sk_addr, sk_len, sk_type, dev);
}

struct sockaddr *
ddrop_socket_str_to_saddr(const char * addr,
                          uint16_t     port,
                          socklen_t  * sk_len)
{
    struct sockaddr * ret;
    struct sockaddr   saddr;

    return sk__str_to_sockaddr_(addr, port, sk_len);
}

static evutil_socket_t
sk__socket_bind_(const char * addr,
                 uint16_t     port,
                 int          type,
                 const char * dev)
{
    struct sockaddr * sk_addr;
    socklen_t         sk_len;
    evutil_socket_t   sock;

    if ((sk_addr = ddrop_socket_str_to_saddr(addr, port, &sk_len)) == NULL) {
        log_error("str_to_saddr");

        return -1;
    }

    if ((sock = sk__bind_to_sockaddr_(sk_addr, sk_len, type, dev)) == -1) {
        log_error("bind_to_sockaddr");
    }

    free(sk_addr);

    return sock;
}

evutil_socket_t
ddrop_socket_bind(const char * addr,
                  uint16_t     port,
                  int          type)
{
    return sk__socket_bind_(addr, port, type, NULL);
}

evutil_socket_t
ddrop_socket_bind_dev(const char * addr,
                      uint16_t     port,
                      int          type,
                      const char * dev)
{
    return sk__socket_bind_(addr, port, type, dev);
}
