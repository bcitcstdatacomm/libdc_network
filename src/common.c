/*
 * Copyright 2021-2021 D'Arcy Smith.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include <dc_posix/dc_netdb.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/sys/dc_socket.h>
#include <netinet/in.h>

void dc_network_get_addresses(const struct dc_posix_env *env,
                              struct dc_error *err,
                              int family,
                              int sock_type,
                              const char *hostname,
                              struct addrinfo **result)
{
    struct addrinfo hints;

    DC_TRACE(env);
    dc_memset(env, &hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = sock_type;
    hints.ai_flags = AI_CANONNAME;
    dc_getaddrinfo(env, err, hostname, NULL, &hints, result);
}

int dc_network_create_socket(const struct dc_posix_env *env, struct dc_error *err, struct addrinfo *addr)
{
    int socket_fd;

    DC_TRACE(env);

    socket_fd = dc_socket(env, err, addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    return socket_fd;
}

void dc_network_bind(const struct dc_posix_env *env,
                     struct dc_error *err,
                     int socket_fd,
                     struct sockaddr *sockaddr,
                     uint16_t port)
{
    socklen_t sockaddr_size;
    in_port_t converted_port;

    DC_TRACE(env);

    // NOLINTNEXTLINE(hicpp-signed-bitwise)
    converted_port = htons(port);

    if(sockaddr->sa_family == AF_INET)
    {
        struct sockaddr_in *addr_in;

        addr_in = (struct sockaddr_in *)sockaddr;
        addr_in->sin_port = converted_port;
        sockaddr_size = sizeof(struct sockaddr_in);
    }
    else
    {
        if(sockaddr->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *addr_in;

            addr_in = (struct sockaddr_in6 *)sockaddr;
            addr_in->sin6_port = converted_port;
            sockaddr_size = sizeof(struct sockaddr_in6);
        }
        else
        {
            DC_ERROR_RAISE_USER(err, "sockaddr->sa_family is wrong", -1);
            sockaddr_size = 0;
        }
    }

    if(dc_error_has_no_error(err))
    {
        dc_bind(env, err, socket_fd, sockaddr, sockaddr_size);
    }
}

void dc_network_listen(const struct dc_posix_env *env, struct dc_error *err, int socket_fd, int backlog)
{
    DC_TRACE(env);
    dc_listen(env, err, socket_fd, backlog);
}

int dc_network_accept(const struct dc_posix_env *env, struct dc_error *err, int server_socket_fd)
{
    int client_socket_fd;

    DC_TRACE(env);
    client_socket_fd = dc_accept(env, err, server_socket_fd, NULL, NULL);

    return client_socket_fd;
}
