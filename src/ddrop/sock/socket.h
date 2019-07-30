#pragma once

CS__EXPORT evutil_socket_t   ddrop_socket_bind(const char * addr, uint16_t port, int type);
CS__EXPORT evutil_socket_t   ddrop_socket_bind_dev(const char * addr, uint16_t port, int type, const char * dev);
CS__EXPORT evutil_socket_t   ddrop_socket_bind_to_sockaddr(struct sockaddr *, socklen_t, int type);
CS__EXPORT evutil_socket_t   ddrop_socket_bind_to_sockaddr_dev(struct sockaddr *, socklen_t, int type, const char * dev);
CS__EXPORT struct sockaddr * ddrop_socket_str_to_saddr(const char * addr, uint16_t port, socklen_t * sk_len);
