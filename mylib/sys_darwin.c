//
//  sys_darwin.c
//  ios-fuzzer
//
//  Created by Quote on 2021/1/26.
//  Copyright © 2021 Quote. All rights reserved.
//

#include <sys/sysctl.h>
#include <string.h>
#include <assert.h>
#include "mycommon.h"
#include "utils.h"

struct exploit_common_s g_exp;

void sys_init(void)
{
    static bool inited = false;
    if (inited) {
        return;
    }
    int err;
    char buf[256];

    size_t oldlen = sizeof(g_exp.physmemsize);
    err = sysctlbyname("hw.memsize", &g_exp.physmemsize, &oldlen, NULL, 0);
    assert(err == 0);
    oldlen = sizeof(g_exp.pagesize);
    err = sysctlbyname("hw.pagesize", &g_exp.pagesize, &oldlen, NULL, 0);
    assert(err == 0);

    oldlen = sizeof(buf);
    err = sysctlbyname("hw.model", buf, &oldlen, NULL, 0);
    assert(err == 0);
    g_exp.model = strdup(buf);
    oldlen = sizeof(buf);
    err = sysctlbyname("kern.osversion", buf, &oldlen, NULL, 0);
    assert(err == 0);
    g_exp.osversion = strdup(buf);
    oldlen = sizeof(buf);
    err = sysctlbyname("kern.osproductversion", buf, &oldlen, NULL, 0);
    assert(err == 0);
    g_exp.osproductversion = strdup(buf);
    oldlen = sizeof(buf);
    err = sysctlbyname("hw.machine", buf, &oldlen, NULL, 0);
    assert(err == 0);
    g_exp.machine = strdup(buf);
    oldlen = sizeof(buf);
    err = sysctlbyname("kern.version", buf, &oldlen, NULL, 0);
    assert(err == 0);
    g_exp.kern_version = strdup(buf);

    inited = true;
}

void print_os_details(void)
{
    util_info("Machine Name: %s", g_exp.machine);
    util_info("Model Name: %s", g_exp.model);
    util_info("Kernel Version: %s", g_exp.kern_version);
//    util_info("Kernel Page Size: %#llx", g_exp.pagesize);
//    util_info("Ram Size: %.1f MB", g_exp.physmemsize / 1024.0 / 1024.0);
    util_info("System Version: iOS %s (%s)", g_exp.osproductversion, g_exp.osversion);
}
