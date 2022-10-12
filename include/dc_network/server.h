#ifndef LIBDC_NETWORK_SERVER_H
#define LIBDC_NETWORK_SERVER_H

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

#include <dc_posix/dc_posix_env.h>
#include <stdio.h>

struct dc_server_info;
struct dc_server_lifecycle;

/**
 *
 * @param env
 * @param err
 * @param name
 * @param verbose_file
 * @param configuration
 * @return
 */
struct dc_server_info *dc_server_info_create(const struct dc_posix_env *env,
                                             struct dc_error *err,
                                             const char *name,
                                             FILE *verbose_file,
                                             void *configuration);

/**
 *
 * @param env
 * @param pinfo
 */
void dc_server_info_destroy(const struct dc_posix_env *env,
                            struct dc_server_info **pinfo);

/**
 *
 * @param env
 * @param err
 * @return
 */
struct dc_server_lifecycle *
dc_server_lifecycle_create(const struct dc_posix_env *env,
                           struct dc_error *err);

/**
 *
 * @param env
 * @param plifecycle
 */
void dc_server_lifecycle_destroy(const struct dc_posix_env *env,
                                 struct dc_server_lifecycle **plifecycle);

/**
 *
 * @param env
 * @param lifecycle
 * @param creater
 */
void dc_server_lifecycle_set_create_settings(
    const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle,
    void (*creater)(const struct dc_posix_env *env,
                    struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param creator
 */
void dc_server_lifecycle_set_create_socket(
    const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle,
    void (*creator)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param setter
 */
void dc_server_lifecycle_set_set_sockopts(
    const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle,
    void (*setter)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param bind
 */
void dc_server_lifecycle_set_bind(const struct dc_posix_env *env,
                                  struct dc_server_lifecycle *lifecycle,
                                  void (*bind)(const struct dc_posix_env *env,
                                               struct dc_error *err,
                                               void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param listen
 */
void dc_server_lifecycle_set_listen(
    const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle,
    void (*listen)(const struct dc_posix_env *env, struct dc_error *err,
                   void *arg));


/**
 *
 * @param env
 * @param lifecycle
 * @param setuper
 */
void dc_server_lifecycle_set_setup(const struct dc_posix_env *env,
                                   struct dc_server_lifecycle *lifecycle,
                                   void (*setuper)(const struct dc_posix_env *env,
                                                   struct dc_error *err,
                                                   void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param accept
 */
void dc_server_lifecycle_set_accept(
    const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle,
    bool (*accept)(const struct dc_posix_env *env, struct dc_error *err,
                   int *client_socket_fd, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param shutdown
 */
void dc_server_lifecycle_set_shutdown(
    const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle,
    void (*shutdown)(const struct dc_posix_env *env, struct dc_error *err,
                     void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param destroyer
 */
void dc_server_lifecycle_set_destroy_settings(
    const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle,
    void (*destroyer)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param err
 * @param info
 * @param create_lifecycle_func
 * @param destroy_lifecycle_func
 * @return
 */
int dc_server_run(
    const struct dc_posix_env *env, struct dc_error *err,
    struct dc_server_info *info,
    struct dc_server_lifecycle *(*create_lifecycle_func)(
        const struct dc_posix_env *env, struct dc_error *err),
    void (*destroy_lifecycle_func)(const struct dc_posix_env *env,
                                   struct dc_server_lifecycle **plifecycle));

#endif // LIBDC_NETWORK_SERVER_H
