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


#include "dc_network/server.h"
#include <dc_c/dc_stdlib.h>
#include <dc_c/dc_string.h>
#include <dc_fsm/fsm.h>


static int create_settings(const struct dc_env *env, struct dc_error *err, void *arg);
static int create_socket(const struct dc_env *env, struct dc_error *err, void *arg);
static int set_sockopts(const struct dc_env *env, struct dc_error *err, void *arg);
static int do_bind(const struct dc_env *env, struct dc_error *err, void *arg);
static int do_listen(const struct dc_env *env, struct dc_error *err, void *arg);
static int setup(const struct dc_env *env, struct dc_error *err, void *arg);
static int do_accept(const struct dc_env *env, struct dc_error *err, void *arg);
static int do_shutdown(const struct dc_env *env, struct dc_error *err, void *arg);
static int destroy_settings(const struct dc_env *env, struct dc_error *err, void *arg);
static int create_settings_error(const struct dc_env *env, struct dc_error *err, void *arg);
static int create_socket_error(const struct dc_env *env, struct dc_error *err, void *arg);
static int set_sockopts_error(const struct dc_env *env, struct dc_error *err, void *arg);
static int do_bind_error(const struct dc_env *env, struct dc_error *err, void *arg);
static int do_listen_error(const struct dc_env *env, struct dc_error *err, void *arg);
static int setup_error(const struct dc_env *env, struct dc_error *err, void *arg);
static int accept_error(const struct dc_env *env, struct dc_error *err, void *arg);
static int shutdown_error(const struct dc_env *env, struct dc_error *err, void *arg);


enum application_states
{
    CREATE_SETTINGS = DC_FSM_USER_START,    // 2
    CREATE_SOCKET,                          // 3
    SET_SOCKOPTS,                           // 4
    BIND,                                   // 5
    LISTEN,                                 // 6
    SETUP,                                  // 7
    ACCEPT,                                 // 8
    SHUTDOWN,                               // 9
    DESTROY_SETTINGS,                       // 10
    CREATE_SETTINGS_ERROR,                  // 11
    CREATE_SOCKET_ERROR,                    // 12
    SET_SOCKOPTS_ERROR,                     // 13
    BIND_ERROR,                             // 14
    LISTEN_ERROR,                           // 15
    SETUP_ERROR,                            // 16
    ACCEPT_ERROR,                           // 17
    SHUTDOWN_ERROR,                         // 18
};

struct dc_server_lifecycle
{
    void (*create_settings)(const struct dc_env *env, struct dc_error *err, void *arg);

    void (*create_socket)(const struct dc_env *env, struct dc_error *err, void *arg);

    void (*set_sockopts)(const struct dc_env *env, struct dc_error *err, void *arg);

    void (*bind)(const struct dc_env *env, struct dc_error *err, void *arg);

    void (*listen)(const struct dc_env *env, struct dc_error *err, void *arg);

    void (*setup)(const struct dc_env *env, struct dc_error *err, void *arg);

    bool (*accept)(const struct dc_env *env, struct dc_error *err, int *client_socket_fd, void *arg);

    bool (*request_handler)(const struct dc_env *env, struct dc_error *err, int client_socket_fd, void *arg);

    void (*shutdown)(const struct dc_env *env, struct dc_error *err, void *arg);

    void (*destroy_settings)(const struct dc_env *env, struct dc_error *err, void *arg);
};

struct dc_server_info
{
    char                       *name;
    FILE                       *verbose_file;
    struct dc_server_lifecycle *lifecycle;
    void                       *configuration;
};

struct dc_server_lifecycle *dc_server_lifecycle_create(const struct dc_env *env, struct dc_error *err)
{
    struct dc_server_lifecycle *lifecycle;

    DC_TRACE(env);
    lifecycle = dc_calloc(env, err, 1, sizeof(struct dc_server_lifecycle));

    if(dc_error_has_no_error(err))
    {
    }

    return lifecycle;
}

void dc_server_lifecycle_destroy(const struct dc_env *env, struct dc_server_lifecycle **plifecycle)
{
    DC_TRACE(env);
    dc_free(env, *plifecycle);
    *plifecycle = NULL;
}

void dc_server_lifecycle_set_create_settings(const struct dc_env  *env,
                                             struct dc_server_lifecycle *lifecycle,
                                             void (*creater)(const struct dc_env *env,
                                                             struct dc_error           *err,
                                                             void                      *arg))
{
    DC_TRACE(env);
    lifecycle->create_settings = creater;
}

void dc_server_lifecycle_set_create_socket(const struct dc_env  *env,
                                           struct dc_server_lifecycle *lifecycle,
                                           void (*creator)(const struct dc_env *env,
                                                           struct dc_error           *err,
                                                           void                      *arg))
{
    DC_TRACE(env);
    lifecycle->create_socket = creator;
}

void dc_server_lifecycle_set_set_sockopts(const struct dc_env  *env,
                                          struct dc_server_lifecycle *lifecycle,
                                          void (*setter)(const struct dc_env *env,
                                                         struct dc_error           *err,
                                                         void                      *arg))
{
    DC_TRACE(env);
    lifecycle->set_sockopts = setter;
}

void dc_server_lifecycle_set_bind(const struct dc_env  *env,
                                  struct dc_server_lifecycle *lifecycle,
                                  void (*bind)(const struct dc_env *env, struct dc_error *err, void *arg))
{
    DC_TRACE(env);
    lifecycle->bind = bind;
}

void dc_server_lifecycle_set_listen(const struct dc_env  *env,
                                    struct dc_server_lifecycle *lifecycle,
                                    void (*listen)(const struct dc_env *env, struct dc_error *err, void *arg))
{
    DC_TRACE(env);
    lifecycle->listen = listen;
}

void dc_server_lifecycle_set_setup(const struct dc_env  *env,
                                   struct dc_server_lifecycle *lifecycle,
                                   void (*setuper)(const struct dc_env *env, struct dc_error *err, void *arg))
{
    DC_TRACE(env);
    lifecycle->setup = setuper;
}

void dc_server_lifecycle_set_accept(
    const struct dc_env  *env,
    struct dc_server_lifecycle *lifecycle,
    bool (*accept)(const struct dc_env *env, struct dc_error *err, int *client_socket_fd, void *arg))
{
    DC_TRACE(env);
    lifecycle->accept = accept;
}

void dc_server_lifecycle_set_shutdown(const struct dc_env  *env,
                                      struct dc_server_lifecycle *lifecycle,
                                      void (*shutdown)(const struct dc_env *env, struct dc_error *err, void *arg))
{
    DC_TRACE(env);
    lifecycle->shutdown = shutdown;
}

void dc_server_lifecycle_set_destroy_settings(const struct dc_env  *env,
                                              struct dc_server_lifecycle *lifecycle,
                                              void (*destroyer)(const struct dc_env *env,
                                                                struct dc_error           *err,
                                                                void                      *arg))
{
    DC_TRACE(env);
    lifecycle->destroy_settings = destroyer;
}

struct dc_server_info *dc_server_info_create(const struct dc_env *env,
                                             struct dc_error           *err,
                                             const char                *name,
                                             FILE                      *verbose_file,
                                             void                      *configuration)
{
    struct dc_server_info *info;

    DC_TRACE(env);
    info = dc_calloc(env, err, 1, sizeof(struct dc_server_info));

    if(dc_error_has_no_error(err))
    {
        info->name = dc_malloc(env, err, dc_strlen(env, name) + 1);

        if(dc_error_has_no_error(err))
        {
            dc_strcpy(env, info->name, name);
            info->verbose_file  = verbose_file;
            info->configuration = configuration;
        }
        else
        {
            dc_server_info_destroy(env, &info);
            info = NULL;
        }
    }

    return info;
}

void dc_server_info_destroy(const struct dc_env *env, struct dc_server_info **pinfo)
{
    struct dc_server_info *info;

    DC_TRACE(env);
    info = *pinfo;

    if(info->name)
    {
        dc_free(env, info->name);
    }

    dc_free(env, *pinfo);
    *pinfo = NULL;
}

int dc_server_run(const struct dc_env *env,
                  struct dc_error           *err,
                  struct dc_server_info     *info,
                  struct dc_server_lifecycle *(*create_lifecycle_func)(const struct dc_env *env,
                                                                       struct dc_error           *err),
                  void (*destroy_lifecycle_func)(const struct dc_env   *env,
                                                 struct dc_server_lifecycle **plifecycle))
{
    int ret_val;

    DC_TRACE(env);
    info->lifecycle = create_lifecycle_func(env, err);

    if(dc_error_has_no_error(err))
    {
        struct dc_fsm_info             *fsm_info;
        static struct dc_fsm_transition transitions[] = {
            {DC_FSM_INIT, CREATE_SETTINGS, create_settings},
            {CREATE_SETTINGS, CREATE_SOCKET, create_socket},
            {CREATE_SOCKET, SET_SOCKOPTS, set_sockopts},
            {SET_SOCKOPTS, BIND, do_bind},
            {BIND, LISTEN, do_listen},
            {LISTEN, SETUP, setup},
            {SETUP, ACCEPT, do_accept},
            {ACCEPT, ACCEPT, do_accept},
            {ACCEPT, SHUTDOWN, do_shutdown},
            {SHUTDOWN, DESTROY_SETTINGS, destroy_settings},
            {DESTROY_SETTINGS, DC_FSM_EXIT, NULL},
            {CREATE_SETTINGS, CREATE_SETTINGS_ERROR, create_settings_error},
            {CREATE_SOCKET, CREATE_SOCKET_ERROR, create_socket_error},
            {SET_SOCKOPTS, SET_SOCKOPTS_ERROR, set_sockopts_error},
            {BIND, BIND_ERROR, do_bind_error},
            {LISTEN, LISTEN_ERROR, do_listen_error},
            {SETUP, SETUP_ERROR, setup_error},
            {ACCEPT, ACCEPT_ERROR, accept_error},
            {SHUTDOWN, SHUTDOWN_ERROR, shutdown_error},
            {CREATE_SETTINGS_ERROR, DC_FSM_EXIT, NULL},
            {CREATE_SOCKET_ERROR, DESTROY_SETTINGS, destroy_settings},
            {SET_SOCKOPTS_ERROR, DESTROY_SETTINGS, destroy_settings},
            {BIND_ERROR, DESTROY_SETTINGS, destroy_settings},
            {LISTEN_ERROR, DESTROY_SETTINGS, destroy_settings},
            {SETUP_ERROR, DESTROY_SETTINGS, destroy_settings},
            {ACCEPT_ERROR, DESTROY_SETTINGS, do_accept},
            {SHUTDOWN_ERROR, DESTROY_SETTINGS, destroy_settings},
            {DC_FSM_IGNORE, DC_FSM_IGNORE, NULL},
        };

        fsm_info = dc_fsm_info_create(env, err, info->name);

        if(dc_error_has_no_error(err))
        {
            dc_fsm_run(env, err, fsm_info, NULL, NULL, info, transitions);
            dc_fsm_info_destroy(env, &fsm_info);
        }

        destroy_lifecycle_func(env, &info->lifecycle);
    }

    if(dc_error_has_error(err))
    {
        ret_val = -1;
    }
    else
    {
        ret_val = 0;
    }

    return ret_val;
}

static int create_settings(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;

    DC_TRACE(env);
    info = arg;
    info->lifecycle->create_settings(env, err, info->configuration);

    if(dc_error_has_no_error(err))
    {
        ret_val = CREATE_SOCKET;
    }
    else
    {
        ret_val = CREATE_SETTINGS_ERROR;
    }

    return ret_val;
}

static int create_socket(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;

    DC_TRACE(env);
    info = arg;
    info->lifecycle->create_socket(env, err, info->configuration);

    if(dc_error_has_no_error(err))
    {
        ret_val = SET_SOCKOPTS;
    }
    else
    {
        ret_val = CREATE_SOCKET_ERROR;
    }

    return ret_val;
}

static int set_sockopts(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;

    DC_TRACE(env);
    info = arg;

    if(info->lifecycle->set_sockopts)
    {
        info->lifecycle->set_sockopts(env, err, info->configuration);
    }

    if(dc_error_has_no_error(err))
    {
        ret_val = BIND;
    }
    else
    {
        ret_val = SET_SOCKOPTS_ERROR;
    }

    return ret_val;
}

static int do_bind(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;

    DC_TRACE(env);
    info = arg;
    info->lifecycle->bind(env, err, info->configuration);

    if(dc_error_has_no_error(err))
    {
        ret_val = LISTEN;
    }
    else
    {
        ret_val = BIND_ERROR;
    }

    return ret_val;
}

static int do_listen(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;

    DC_TRACE(env);
    info = arg;
    info->lifecycle->listen(env, err, info->configuration);

    if(dc_error_has_no_error(err))
    {
        ret_val = SETUP;
    }
    else
    {
        ret_val = LISTEN_ERROR;
    }

    return ret_val;
}

static int setup(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;

    DC_TRACE(env);
    info = arg;

    if(info->lifecycle->setup)
    {
        info->lifecycle->setup(env, err, info->configuration);
    }

    if(dc_error_has_no_error(err))
    {
        ret_val = ACCEPT;
    }
    else
    {
        ret_val = SETUP_ERROR;
    }

    return ret_val;
}

static int do_accept(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;
    bool                   shutdown_flag;
    int                    client_socket_fd;

    DC_TRACE(env);
    info          = arg;
    shutdown_flag = info->lifecycle->accept(env, err, &client_socket_fd, info->configuration);

    if(shutdown_flag)
    {
        ret_val = SHUTDOWN;
    }
    else
    {
        if(dc_error_has_no_error(err))
        {
            ret_val = ACCEPT;
        }
        else
        {
            ret_val = ACCEPT_ERROR;
        }
    }

    return ret_val;
}

static int do_shutdown(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;
    int                    ret_val;

    DC_TRACE(env);
    info = arg;
    info->lifecycle->shutdown(env, err, info->configuration);

    if(dc_error_has_no_error(err))
    {
        ret_val = DESTROY_SETTINGS;
    }
    else
    {
        ret_val = SHUTDOWN_ERROR;
    }

    return ret_val;
}

static int destroy_settings(const struct dc_env *env, struct dc_error *err, void *arg)
{
    struct dc_server_info *info;

    DC_TRACE(env);
    info = arg;

    info->lifecycle->destroy_settings(env, err, info->configuration);

    return DC_FSM_EXIT;
}

static int create_settings_error(const struct dc_env               *env,
                                 __attribute__((unused)) struct dc_error *err,
                                 __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}

static int create_socket_error(const struct dc_env               *env,
                               __attribute__((unused)) struct dc_error *err,
                               __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}

static int set_sockopts_error(const struct dc_env               *env,
                              __attribute__((unused)) struct dc_error *err,
                              __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}

static int do_bind_error(const struct dc_env               *env,
                         __attribute__((unused)) struct dc_error *err,
                         __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}

static int do_listen_error(const struct dc_env               *env,
                           __attribute__((unused)) struct dc_error *err,
                           __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}

static int setup_error(const struct dc_env               *env,
                       __attribute__((unused)) struct dc_error *err,
                       __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}

static int accept_error(const struct dc_env               *env,
                        __attribute__((unused)) struct dc_error *err,
                        __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}

static int shutdown_error(const struct dc_env               *env,
                          __attribute__((unused)) struct dc_error *err,
                          __attribute__((unused)) void            *arg)
{
    DC_TRACE(env);

    return DESTROY_SETTINGS;
}
