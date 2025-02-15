/*
 * Copyright (c) 2014-2016 DeNA Co., Ltd., Kazuho Oku, Nick Desaulniers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#ifndef __linux__
#include <spawn.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if !defined(_SC_NPROCESSORS_ONLN)
#include <sys/sysctl.h>
#endif
#include "cloexec.h"
#include "vhttp/memory.h"
#include "vhttp/serverutil.h"
#include "vhttp/socket.h"
#include "vhttp/string_.h"

void vhttp_set_signal_handler(int signo, void (*cb)(int signo))
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_handler = cb;
    sigaction(signo, &action, NULL);
}

int vhttp_setuidgid(const char *user)
{
    struct passwd pwbuf, *pw;
    char buf[65536]; /* should be large enough */

    errno = 0;
    if (getpwnam_r(user, &pwbuf, buf, sizeof(buf), &pw) != 0) {
        vhttp_perror("getpwnam_r");
        return -1;
    }
    if (pw == NULL) {
        vhttp_error_printf("unknown user:%s\n", user);
        return -1;
    }
    if (setgid(pw->pw_gid) != 0) {
        vhttp_error_printf("setgid(%d) failed:%s\n", (int)pw->pw_gid, strerror(errno));
        return -1;
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        vhttp_error_printf("initgroups(%s, %d) failed:%s\n", pw->pw_name, (int)pw->pw_gid, strerror(errno));
        return -1;
    }
    if (setuid(pw->pw_uid) != 0) {
        vhttp_error_printf("setuid(%d) failed:%s\n", (int)pw->pw_uid, strerror(errno));
        return -1;
    }

    return 0;
}

size_t vhttp_server_starter_get_fds(int **_fds)
{
    const char *ports_env, *start, *end, *eq;
    size_t t;
    vhttp_VECTOR(int) fds = {NULL};

    if ((ports_env = getenv(SERVER_STARTER_PORT)) == NULL)
        return 0;
    if (ports_env[0] == '\0') {
        vhttp_error_printf("$" SERVER_STARTER_PORT " is empty\n");
        return SIZE_MAX;
    }

    /* ports_env example: 127.0.0.1:80=3;/tmp/sock=4 */
    for (start = ports_env; *start != '\0'; start = *end == ';' ? end + 1 : end) {
        if ((end = strchr(start, ';')) == NULL)
            end = start + strlen(start);
        if ((eq = memchr(start, '=', end - start)) == NULL) {
            vhttp_error_printf("invalid $" SERVER_STARTER_PORT ", an element without `=` in: %s\n", ports_env);
            goto Error;
        }
        if ((t = vhttp_strtosize(eq + 1, end - eq - 1)) == SIZE_MAX) {
            vhttp_error_printf("invalid file descriptor number in $" SERVER_STARTER_PORT ": %s\n", ports_env);
            goto Error;
        }
        vhttp_vector_reserve(NULL, &fds, fds.size + 1);
        fds.entries[fds.size++] = (int)t;
    }

    *_fds = fds.entries;
    return fds.size;
Error:
    free(fds.entries);
    return SIZE_MAX;
}

static char **build_spawn_env(void)
{
    extern char **environ;
    size_t num;

    /* calculate number of envvars, as well as looking for vhttp_ROOT= */
    for (num = 0; environ[num] != NULL; ++num)
        if (strncmp(environ[num], "vhttp_ROOT=", sizeof("vhttp_ROOT=") - 1) == 0)
            return NULL;

    /* not found */
    char **newenv = vhttp_mem_alloc(sizeof(*newenv) * (num + 2) + sizeof("vhttp_ROOT=" vhttp_TO_STR(vhttp_ROOT)));
    memcpy(newenv, environ, sizeof(*newenv) * num);
    newenv[num] = (char *)(newenv + num + 2);
    newenv[num + 1] = NULL;
    strcpy(newenv[num], "vhttp_ROOT=" vhttp_TO_STR(vhttp_ROOT));

    return newenv;
}

pid_t vhttp_spawnp(const char *cmd, char *const *argv, const int *mapped_fds, int cloexec_mutex_is_locked)
{
#if defined(__linux__)
#ifndef _GNU_SOURCE
    extern int pipe2(int pipefd[2], int flags);
#endif

    /* Before glibc 2.24, posix_spawnp of Linux does not return error if the executable does not exist, see
     * https://gist.github.com/kazuho/0c233e6f86d27d6e4f09
     */
    extern char **environ;
    int pipefds[2] = {-1, -1}, errnum;
    pid_t pid;

    /* create pipe, used for sending error codes */
    if (pipe2(pipefds, O_CLOEXEC) != 0)
        goto Error;

    /* fork */
    if (!cloexec_mutex_is_locked)
        pthread_mutex_lock(&cloexec_mutex);
    if ((pid = fork()) == 0) {
        /* in child process, map the file descriptors and execute; return the errnum through pipe if exec failed */
        if (mapped_fds != NULL) {
            for (; *mapped_fds != -1; mapped_fds += 2) {
                if (mapped_fds[0] != mapped_fds[1]) {
                    if (mapped_fds[1] != -1)
                        dup2(mapped_fds[0], mapped_fds[1]);
                    close(mapped_fds[0]);
                }
            }
        }
        char **env = build_spawn_env();
        if (env != NULL)
            environ = env;
        execvp(cmd, argv);
        errnum = errno;
        write(pipefds[1], &errnum, sizeof(errnum));
        _exit(EX_SOFTWARE);
    }
    if (!cloexec_mutex_is_locked)
        pthread_mutex_unlock(&cloexec_mutex);
    if (pid == -1)
        goto Error;

    /* parent process */
    close(pipefds[1]);
    pipefds[1] = -1;
    ssize_t rret;
    errnum = 0;
    while ((rret = read(pipefds[0], &errnum, sizeof(errnum))) == -1 && errno == EINTR)
        ;
    if (rret != 0) {
        /* spawn failed */
        while (waitpid(pid, NULL, 0) != pid)
            ;
        pid = -1;
        errno = errnum;
        goto Error;
    }

    /* spawn succeeded */
    close(pipefds[0]);
    return pid;

Error:
    errnum = errno;
    if (pipefds[0] != -1)
        close(pipefds[0]);
    if (pipefds[1] != -1)
        close(pipefds[1]);
    errno = errnum;
    return -1;

#else

    posix_spawn_file_actions_t file_actions;
    pid_t pid;
    extern char **environ;
    char **env = build_spawn_env();
    posix_spawn_file_actions_init(&file_actions);
    if (mapped_fds != NULL) {
        for (; *mapped_fds != -1; mapped_fds += 2) {
            if (mapped_fds[1] != -1)
                posix_spawn_file_actions_adddup2(&file_actions, mapped_fds[0], mapped_fds[1]);
            posix_spawn_file_actions_addclose(&file_actions, mapped_fds[0]);
        }
    }
    if (!cloexec_mutex_is_locked)
        pthread_mutex_lock(&cloexec_mutex);
    errno = posix_spawnp(&pid, cmd, &file_actions, NULL, argv, env != NULL ? env : environ);
    if (!cloexec_mutex_is_locked)
        pthread_mutex_unlock(&cloexec_mutex);
    free(env);
    posix_spawn_file_actions_destroy(&file_actions);
    if (errno != 0)
        return -1;

    return pid;

#endif
}

int vhttp_read_command(const char *cmd, char **argv, vhttp_iovec_t std_in, vhttp_buffer_t **resp, int *child_status)
{
    int respfds[2] = {-1, -1}, inputfds[2] = {-1, -1};
    pid_t pid = -1;
    int mutex_locked = 0, ret = -1;

    vhttp_buffer_init(resp, &vhttp_socket_buffer_prototype);

    pthread_mutex_lock(&cloexec_mutex);
    mutex_locked = 1;

    /* create pipes for reading the result and for supplying input */
    if (pipe(respfds) != 0)
        goto Exit;
    if (fcntl(respfds[0], F_SETFD, FD_CLOEXEC) < 0)
        goto Exit;
    if (pipe(inputfds) != 0)
        goto Exit;
    if (fcntl(inputfds[1], F_SETFD, FD_CLOEXEC) < 0)
        goto Exit;

    /* spawn */
    int mapped_fds[] = {inputfds[0], 0, /* stdin of the child process is what is being provide as input */
                        respfds[1], 1,  /* stdout of the child process is read from the pipe */
                        -1};
    if ((pid = vhttp_spawnp(cmd, argv, mapped_fds, 1)) == -1)
        goto Exit;
    close(respfds[1]);
    respfds[1] = -1;
    close(inputfds[0]);
    inputfds[0] = -1;

    pthread_mutex_unlock(&cloexec_mutex);
    mutex_locked = 0;

    /* supply input */
    for (size_t off = 0; off < std_in.len;) {
        ssize_t r;
        while ((r = write(inputfds[1], std_in.base + off, std_in.len - off)) == -1 && errno == EINTR)
            ;
        if (r < 0)
            break;
        off += r;
    }
    close(inputfds[1]);
    inputfds[1] = -1;

    /* read the response from pipe */
    while (1) {
        vhttp_iovec_t buf = vhttp_buffer_reserve(resp, 8192);
        ssize_t r;
        while ((r = read(respfds[0], buf.base, buf.len)) == -1 && errno == EINTR)
            ;
        if (r <= 0)
            break;
        (*resp)->size += r;
    }

Exit:
    if (mutex_locked)
        pthread_mutex_unlock(&cloexec_mutex);
    if (pid != -1) {
        /* wait for the child to complete */
        pid_t r;
        while ((r = waitpid(pid, child_status, 0)) == -1 && errno == EINTR)
            ;
        if (r == pid) {
            /* success */
            ret = 0;
        }
    }
#define CLOSE_FD(x)                                                                                                                \
    do {                                                                                                                           \
        if ((x) != -1)                                                                                                             \
            close(x);                                                                                                              \
    } while (0)
    CLOSE_FD(respfds[0]);
    CLOSE_FD(respfds[1]);
    CLOSE_FD(inputfds[0]);
    CLOSE_FD(inputfds[1]);
#undef CLOSE_FD
    if (ret != 0)
        vhttp_buffer_dispose(resp);

    return ret;
}

size_t vhttp_numproc(void)
{
#if defined(_SC_NPROCESSORS_ONLN)
    return (size_t)sysconf(_SC_NPROCESSORS_ONLN);
#elif defined(CTL_HW) && defined(HW_AVAILCPU)
    int name[] = {CTL_HW, HW_AVAILCPU};
    int ncpu;
    size_t ncpu_sz = sizeof(ncpu);
    if (sysctl(name, sizeof(name) / sizeof(name[0]), &ncpu, &ncpu_sz, NULL, 0) != 0 || sizeof(ncpu) != ncpu_sz) {
        vhttp_error_printf("[ERROR] failed to obtain number of CPU cores, assuming as one\n");
        ncpu = 1;
    }
    return ncpu;
#else
    return 1;
#endif
}
