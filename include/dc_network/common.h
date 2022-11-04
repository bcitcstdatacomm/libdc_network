#ifndef LIBDC_NETWORK_COMMON_H
#define LIBDC_NETWORK_COMMON_H


/*
 * Copyright 2021-2022 D'Arcy Smith.
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


#include <dc_env/env.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netdb.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 *
 * @param env
 * @param err
 * @param family
 * @param sock_type
 * @param hostname
 * @param result
 */
void dc_network_get_addresses(const struct dc_env *env,
                              struct dc_error *err, int family, int sock_type,
                              const char *hostname, struct addrinfo **result);

/**
 *
 * @param env
 * @param err
 * @param addr
 * @return
 */
int dc_network_create_socket(const struct dc_env *env,
                             struct dc_error *err, struct addrinfo *addr);

/**
 *
 * @param env
 * @param err
 * @param socket_fd
 * @param sockaddr
 * @param port
 */
void dc_network_bind(const struct dc_env *env, struct dc_error *err,
                     int socket_fd, struct sockaddr *sockaddr, uint16_t port);

/**
 *
 * @param env
 * @param err
 * @param socket_fd
 * @param backlog
 */
void dc_network_listen(const struct dc_env *env, struct dc_error *err,
                       int socket_fd, int backlog);

/**
 *
 * @param env
 * @param err
 * @param server_socket_fd
 * @return
 */
int dc_network_accept(const struct dc_env *env, struct dc_error *err,
                      int server_socket_fd);


#ifdef __cplusplus
}
#endif


#endif // LIBDC_NETWORK_COMMON_H
