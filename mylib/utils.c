//
//  utils.c
//  exploit-1
//
//  Created by Quote on 2020/12/24.
//  Copyright © 2020 Quote. All rights reserved.
//

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <spawn.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include "mycommon.h"
#include "utils.h"

static void util_vprintf(const char *fmt, va_list ap);

void util_hexprint(void *data, size_t len, const char *desc)
{
    uint8_t *ptr = (uint8_t *)data;
    size_t i;

    if (desc) {
        util_printf("%s\n", desc);
    }
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) {
            util_printf("%04x: ", (uint16_t)i);
        }
        util_printf("%02x ", ptr[i]);
        if (i % 16 == 7) {
            util_printf(" ");
        }
        if (i % 16 == 15) {
            util_printf("\n");
        }
    }
    if (i % 16 != 0) {
        util_printf("\n");
    }
}

void util_hexprint_width(void *data, size_t len, int width, const char *desc)
{
    uint8_t *ptr = (uint8_t *)data;
    size_t i;

    if (desc) {
        util_printf("%s\n", desc);
    }
    for (i = 0; i < len; i += width) {
        if (i % 16 == 0) {
            util_printf("%04x: ", (uint16_t)i);
        }
        if (width == 8) {
            util_printf("%016llx ", *(uint64_t *)(ptr + i));
        }
        else if (width == 4) {
            util_printf("%08x ", *(uint32_t *)(ptr + i));
        }
        else if (width == 2) {
            util_printf("%04x ", *(uint16_t *)(ptr + i));
        }
        else {
            util_printf("%02x ", ptr[i]);
        }
        if ((i + width) % 16 == 8) {
            util_printf(" ");
        }
        if ((i + width) % 16 == 0) {
            util_printf("\n");
        }
    }
    if (i % 16 != 0) {
        util_printf("\n");
    }
}

void util_nanosleep(uint64_t nanosecs)
{
    int ret;
    struct timespec tp;
    tp.tv_sec = nanosecs / (1000 * 1000 * 1000);
    tp.tv_nsec = nanosecs % (1000 * 1000 * 1000);
    do {
        ret = nanosleep(&tp, &tp);
    } while (ret && errno == EINTR);
}

void util_msleep(unsigned int ms)
{
    uint64_t nanosecs = ms * 1000 * 1000;
    util_nanosleep(nanosecs);
}

_Noreturn static void vfail(const char *fmt, va_list ap)
{
    char text[512];
    vsnprintf(text, sizeof(text), fmt, ap);
    util_printf("[!] fail < %s >\n", text);
    util_printf("[*] endless loop\n");
    while (1) {
        util_msleep(1000);
    }
}

void fail_if(bool cond, const char *fmt, ...)
{
    if (cond) {
        va_list ap;
        va_start(ap, fmt);
        vfail(fmt, ap);
        va_end(ap);
    }
}

_Noreturn void fail_info(const char *info)
{
    util_printf("[!] fail < %s >\n", info ? info : "null");
    util_printf("[*] endless loop\n");
    while (1) {
        util_msleep(1000);
    }
    exit(1);
}

void (*log_UI)(const char *text) = NULL;

static void log_vprintf(int type, const char *fmt, va_list ap)
{
    char message[256];

    vsnprintf(message, sizeof(message), fmt, ap);
    switch (type) {
        case 'D': type = 'D'; break;
        case 'I': type = '+'; break;
        case 'W': type = '!'; break;
        case 'E': type = '-'; break;
    }
    fprintf(stdout, "[%c] %s\n", type, message);
    if (0) {
        CF_EXPORT void CFLog(int32_t level, CFStringRef format, ...);
        CFLog(6, CFSTR("[%c] %s\n"), type, message);
    }
    if (log_UI) {
        char ui_text[512];
        snprintf(ui_text, sizeof(ui_text), "[%c] %s\n", type, message);
        log_UI(ui_text);
    }
}

void util_debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vprintf('D', fmt, ap);
    va_end(ap);
}

void util_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vprintf('I', fmt, ap);
    va_end(ap);
}

void util_warning(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vprintf('W', fmt, ap);
    va_end(ap);
}

void util_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vprintf('E', fmt, ap);
    va_end(ap);
}

static void util_vprintf(const char *fmt, va_list ap)
{
    vfprintf(stdout, fmt, ap);
    if (log_UI) {
        char ui_text[512];
        vsnprintf(ui_text, sizeof(ui_text), fmt, ap);
        log_UI(ui_text);
    }
}

void util_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    util_vprintf(fmt, ap);
    va_end(ap);
}

extern char **environ;

static int runCommandv(const char *cmd, int argc, const char * const* argv, void (^unrestrict)(pid_t))
{
    pid_t pid;
    posix_spawn_file_actions_t *actions = NULL;
    posix_spawn_file_actions_t actionsStruct;
    int out_pipe[2];
    bool valid_pipe = false;
    posix_spawnattr_t *attr = NULL;
    posix_spawnattr_t attrStruct;

    valid_pipe = pipe(out_pipe) == 0;
    if (valid_pipe && posix_spawn_file_actions_init(&actionsStruct) == 0) {
        actions = &actionsStruct;
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(actions, out_pipe[1], 2);
        posix_spawn_file_actions_addclose(actions, out_pipe[0]);
        posix_spawn_file_actions_addclose(actions, out_pipe[1]);
    }

    if (unrestrict && posix_spawnattr_init(&attrStruct) == 0) {
        attr = &attrStruct;
        posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    }

    int rv = posix_spawn(&pid, cmd, actions, attr, (char *const *)argv, environ);

    if (unrestrict) {
        unrestrict(pid);
        kill(pid, SIGCONT);
    }

    if (valid_pipe) {
        close(out_pipe[1]);
    }

    if (rv == 0) {
        if (valid_pipe) {
            char buf[256];
            ssize_t len;
            while (1) {
                len = read(out_pipe[0], buf, sizeof(buf) - 1);
                if (len == 0) {
                    break;
                }
                else if (len == -1) {
                    perror("posix_spawn, read pipe");
                }
                buf[len] = 0;
                util_printf("%s", buf);
            }
        }
        if (waitpid(pid, &rv, 0) == -1) {
            util_error("ERROR: Waitpid failed");
        } else {
            util_info("%s(%d) completed with exit status %d", __FUNCTION__, pid, WEXITSTATUS(rv));
        }

    } else {
        util_error("%s(%d): ERROR posix_spawn failed (%d): %s", __FUNCTION__, pid, rv, strerror(rv));
        rv <<= 8; // Put error into WEXITSTATUS
    }
    if (valid_pipe) {
        close(out_pipe[0]);
    }
    return rv;
}

int util_runCommand(const char *cmd, ...)
{
    va_list ap, ap2;
    int argc = 1;

    va_start(ap, cmd);
    va_copy(ap2, ap);

    while (va_arg(ap, const char *) != NULL) {
        argc++;
    }
    va_end(ap);

    const char *argv[argc+1];
    argv[0] = cmd;
    for (int i=1; i<argc; i++) {
        argv[i] = va_arg(ap2, const char *);
    }
    va_end(ap2);
    argv[argc] = NULL;

    int rv = runCommandv(cmd, argc, argv, NULL);
    return WEXITSTATUS(rv);
}
