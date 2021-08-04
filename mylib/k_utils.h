//
//  k_utils.h
//  exploit-1
//
//  Created by Quote on 2020/12/24.
//  Copyright © 2020 Quote. All rights reserved.
//

#ifndef k_utils_h
#define k_utils_h

struct kDictEntry {
    kptr_t key;
    kptr_t value;
};

struct kOSDict {
    kptr_t self_addr;
    kptr_t items_addr;
    uint32_t count;
    uint32_t cap;
    char **names;
    struct kDictEntry *items;
    char data[0];
};

kptr_t kproc_find_pid0(kptr_t proc);
kptr_t kproc_find_by_pid(pid_t pid);
kptr_t ipc_entry_lookup(mach_port_t port_name);
kptr_t port_name_to_ipc_port(mach_port_t port_name);
kptr_t port_name_to_kobject(mach_port_t port_name);
void debug_dump_ipc_port(mach_port_t port_name, kptr_t *kobj);

void proc_write_MACF(kptr_t proc, struct kOSDict *macf);
void prepare_fake_entitlements(void);
struct kDictEntry *borrow_fake_entitlement(const char *name);
struct kOSDict *proc_fetch_MACF(kptr_t proc);
void debug_dump_proc_cred(kptr_t proc);

#endif /* k_utils_h */
