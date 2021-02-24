//
//  kapi_memory.c
//  ios-fuzzer
//
//  Created by Quote on 2021/1/22.
//  Copyright © 2021 Quote. All rights reserved.
//

#include "mycommon.h"
#include "kapi.h"

mach_port_t kernel_task_port;

void (^stage0_read)(kptr_t addr, void *data, size_t len);
uint32_t (^stage0_read32)(kptr_t addr);
uint64_t (^stage0_read64)(kptr_t addr);
kptr_t (^stage0_read_kptr)(kptr_t addr);

void (^stage0_write)(kptr_t addr, void *data, size_t len);
void (^stage0_write64)(kptr_t addr, uint64_t v);

void kapi_read(kptr_t addr, void *data, size_t len)
{
    if (!kernel_task_port) {
        return stage0_read(addr, data, len);
    }
}

uint32_t kapi_read32(kptr_t addr)
{
    if (!kernel_task_port) {
        return stage0_read32(addr);
    }
    return 0;
}

uint64_t kapi_read64(kptr_t addr)
{
    if (!kernel_task_port) {
        return stage0_read64(addr);
    }
    return 0;
}

kptr_t kapi_read_kptr(kptr_t addr)
{
    if (!kernel_task_port) {
        return stage0_read_kptr(addr);
    }
    return 0;
}

void kapi_write(kptr_t addr, void *data, size_t len)
{
    if (!kernel_task_port) {
        return stage0_write(addr, data, len);
    }
}

bool kapi_write32(kptr_t addr, uint32_t value)
{
    if (!kernel_task_port) {
        stage0_write(addr, &value, sizeof(value));
        return true;
    }
    return false;
}

bool kapi_write64(kptr_t addr, uint64_t value)
{
    if (!kernel_task_port) {
        stage0_write64(addr, value);
        return true;
    }
    return false;
}
