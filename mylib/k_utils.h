//
//  k_utils.h
//  exploit-1
//
//  Created by Quote on 2020/12/24.
//  Copyright © 2020 Quote. All rights reserved.
//

#ifndef k_utils_h
#define k_utils_h

kptr_t kproc_find_pid0(kptr_t proc);
kptr_t kproc_find_by_pid(pid_t pid);
kptr_t ipc_entry_lookup(mach_port_t port_name);
kptr_t port_name_to_ipc_port(mach_port_t port_name);
kptr_t port_name_to_kobject(mach_port_t port_name);
void debug_dump_ipc_port(mach_port_t port_name, kptr_t *kobj);

void debug_dump_proc_cred(kptr_t proc);

#endif /* k_utils_h */
