//
//  utils.h
//  exploit-1
//
//  Created by Quote on 2020/12/24.
//  Copyright © 2020 Quote. All rights reserved.
//

#ifndef utils_h
#define utils_h

#include <stddef.h>
#include <stdint.h>

void util_hexprint(void *data, size_t len, const char *desc);
void util_hexprint_width(void *data, size_t len, int width, const char *desc);
void util_nanosleep(uint64_t nanosecs);
void util_msleep(unsigned int ms);
_Noreturn void fail_info(const char *info);
void fail_if(bool cond, const char *fmt, ...)  __printflike(2, 3);

// don't like macro
void util_debug(const char *fmt, ...) __printflike(1, 2);
void util_info(const char *fmt, ...) __printflike(1, 2);
void util_warning(const char *fmt, ...) __printflike(1, 2);
void util_error(const char *fmt, ...) __printflike(1, 2);
void util_printf(const char *fmt, ...) __printflike(1, 2);

int util_runCommand(const char *cmd, ...);

void post_exploit(void);

#endif /* utils_h */
