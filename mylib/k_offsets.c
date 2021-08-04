//
//  k_offsets.c
//  ios-fuzzer
//
//  Created by Quote on 2021/1/26.
//  Copyright © 2021 Quote. All rights reserved.
//

#include <string.h>
#include "mycommon.h"
#include "utils.h"
#define Q_INTERNAL
#include "k_offsets.h"

static void offsets_base_iOS_14_x()
{
    kc_kernel_base = 0xFFFFFFF007004000;

    SIZE(ipc_entry)              = 0x18;
    OFFSET(ipc_entry, ie_object) =  0x0;

    OFFSET(ipc_port, ip_bits)       =  0x0;
    OFFSET(ipc_port, ip_references) =  0x4;
    OFFSET(ipc_port, ip_kobject)    = 0x68;

    OFFSET(ipc_space, is_table_size) = 0x14;
    OFFSET(ipc_space, is_table)      = 0x20;

    OFFSET(task, map) = 0x28;
    OFFSET(task, itk_space) = 0x330;
#if __arm64e__
    OFFSET(task, bsd_info) = 0x3a0;
    OFFSET(task, t_flags) = 0x3f4;
#else
    OFFSET(task, bsd_info) = 0x390;
    OFFSET(task, t_flags) = 0x3d8;
#endif

    OFFSET(proc, le_next) = 0x00;
    OFFSET(proc, le_prev) = 0x08;
    OFFSET(proc, task) = 0x10;
    OFFSET(proc, p_pid) = 0x68;
    OFFSET(proc, p_ucred) = 0xf0;
    OFFSET(proc, p_fd) = 0xf8;

    OFFSET(filedesc, fd_ofiles) = 0x00;
    OFFSET(fileproc, fp_glob) = 0x10;
    OFFSET(fileglob, fg_data) = 0x38;
    OFFSET(pipe, buffer) = 0x10;

    OFFSET(ucred, cr_posix) = 0x18;

    SIZE(posix_cred) = 0x60;

    OFFSET(OSDictionary, count)      = 0x14;
    OFFSET(OSDictionary, capacity)   = 0x18;
    OFFSET(OSDictionary, dictionary) = 0x20;

    OFFSET(OSString, string) = 0x10;

    OFFSET(IOSurfaceRootUserClient, surfaceClients) = 0x118;
    OFFSET(IOSurfaceClient, surface) = 0x40;
    OFFSET(IOSurface, values) = 0xe8;
}

static void offsets_iPhone6s_18A373()
{
    offsets_base_iOS_14_x();
}

static void offsets_iPhone11_18A373()
{
    offsets_base_iOS_14_x();

    OFFSET(thread, jop_pid) = 0x510;
}

static void offsets_iPhone12pro_18C66()
{
    offsets_base_iOS_14_x();

    OFFSET(thread, jop_pid) = 0x518;
}

struct device_def {
    const char *name;
    const char *model;
    const char *build;
    void (*init)(void);
};

static struct device_def devices[] = {
    { "iPhone 6s", "N71AP", "18A373", offsets_iPhone6s_18A373 },
    { "iPhone 11", "N104AP", "18A373", offsets_iPhone11_18A373 },
    { "iPhone 12 pro", "D53pAP", "18C66", offsets_iPhone12pro_18C66 },
    { "iPhone ?", "?", "*", offsets_base_iOS_14_x },
};

void kernel_offsets_init(void)
{
    for (int i = 0; i < arrayn(devices); i++) {
        struct device_def *dev = &devices[i];
        if (!strcmp(g_exp.model, dev->model) && !strcmp(g_exp.osversion, dev->build)) {
            dev->init();
            return;
        }
        if (!strcmp(dev->build, "*")) {
            util_warning("fallback to default iOS 14.x offsets");
            dev->init();
            return;
        }
    }
    fail_info("no device defination");
}
