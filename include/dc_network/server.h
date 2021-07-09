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


#include <dc_posix/posix_env.h>
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
                                             struct dc_error           *err,
                                             const char                *name,
                                             FILE                      *verbose_file,
                                             void                      *configuration);

/**
 *
 * @param env
 * @param pinfo
 */
void dc_server_info_destroy(const struct dc_posix_env *env, struct dc_server_info **pinfo);

/**
 *
 * @param env
 * @param err
 * @return
 */
struct dc_server_lifecycle *dc_server_lifecycle_create(const struct dc_posix_env *env,
                                                       struct dc_error *err);

/**
 *
 * @param env
 * @param plifecycle
 */
void dc_server_lifecycle_destroy(const struct dc_posix_env *env, struct dc_server_lifecycle **plifecycle);

/**
 *
 * @param env
 * @param lifecycle
 * @param create_settings
 */
void dc_server_lifecycle_set_create_settings(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*create_settings)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param create_socket
 */
void dc_server_lifecycle_set_create_socket(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*create_socket)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param set_sockopts
 */
void dc_server_lifecycle_set_set_sockopts(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*set_sockopts)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param bind
 */
void dc_server_lifecycle_set_bind(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*bind)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param listen
 */
void dc_server_lifecycle_set_listen(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*listen)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param setup
 */
void dc_server_lifecycle_set_setup(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*setup)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param accept
 */
void dc_server_lifecycle_set_accept(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*accept)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param shutdown
 */
void dc_server_lifecycle_set_shutdown(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*shutdown)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param lifecycle
 * @param destroy_settings
 */
void dc_server_lifecycle_set_destroy_settings(const struct dc_posix_env *env, struct dc_server_lifecycle *lifecycle, int (*destroy_settings)(const struct dc_posix_env *env, struct dc_error *err, void *arg));

/**
 *
 * @param env
 * @param err
 * @param info
 * @param create_lifecycle_func
 * @param destroy_lifecycle_func
 * @return
 */
int dc_server_run(const struct dc_posix_env *env,
                  struct dc_error           *err,
                  struct dc_server_info     *info,
                  struct dc_server_lifecycle *(*create_lifecycle_func)(const struct dc_posix_env *env, struct dc_error *err),
                  void (*destroy_lifecycle_func)(const struct dc_posix_env *env, struct dc_server_lifecycle **plifecycle));


#endif // LIBDC_NETWORK_SERVER_H
