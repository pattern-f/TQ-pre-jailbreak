//
//  kapi.h
//  ios-fuzzer
//
//  Created by Quote on 2021/1/22.
//  Copyright © 2021 Quote. All rights reserved.
//

#ifndef kapi_h
#define kapi_h

#include <sys/cdefs.h>
#include <stdint.h>

__BEGIN_DECLS

extern mach_port_t kernel_task_port;

extern void (^stage0_read)(kptr_t addr, void *data, size_t len);
extern uint32_t (^stage0_read32)(kptr_t addr);
extern uint64_t (^stage0_read64)(kptr_t addr);
extern kptr_t (^stage0_read_kptr)(kptr_t addr);

extern void (^stage0_write)(kptr_t addr, void *data, size_t len);
extern void (^stage0_write64)(kptr_t addr, uint64_t v);

void kapi_read(kptr_t addr, void *data, size_t len);
uint32_t kapi_read32(kptr_t addr);
uint64_t kapi_read64(kptr_t addr);
kptr_t kapi_read_kptr(kptr_t addr);

void kapi_write(kptr_t addr, void *data, size_t len);
bool kapi_write32(kptr_t addr, uint32_t value);
bool kapi_write64(kptr_t addr, uint64_t value);

__END_DECLS

#endif /* kapi_h */
