/*
 * iosurface.c
 * Brandon Azad
 */

#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "IOKit/IOKitLib.h"

#include "mycommon.h"
#include "utils.h"

enum {
    kOSSerializeDictionary      = 0x01000000,
    kOSSerializeArray           = 0x02000000,
    kOSSerializeSet             = 0x03000000,
    kOSSerializeNumber          = 0x04000000,
    kOSSerializeSymbol          = 0x08000000,
    kOSSerializeString          = 0x09000000,
    kOSSerializeData            = 0x0a000000,
    kOSSerializeBoolean         = 0x0b000000,
    kOSSerializeObject          = 0x0c000000,
    kOSSerializeTypeMask        = 0x7f000000,
    kOSSerializeDataMask        = 0x00ffffff,
    kOSSerializeEndCollection    = 0x80000000,
    kOSSerializeBinarySignature = 0x000000d3,
};

// This value encodes to 0x00ffffff, so any larger value will cause IOSurface_property_key() to
// wrap and collide with a smaller value.
#define MAX_IOSURFACE_PROPERTY_INDEX    (0x00fd02fe)

// ---- IOSurface types ---------------------------------------------------------------------------

struct _IOSurfaceFastCreateArgs {
	uint64_t address;
	uint32_t width;
	uint32_t height;
	uint32_t pixel_format;
	uint32_t bytes_per_element;
	uint32_t bytes_per_row;
	uint32_t alloc_size;
};

struct IOSurfaceLockResult {
	//uint8_t _pad1[0x18];
    uint8_t *mem;
    uint8_t *shared_B0;
    uint8_t *shared_40;
	uint32_t surface_id;
	uint8_t _pad2[0xf60-0x18-0x4];
};

struct IOSurfaceValueArgs {
	uint32_t surface_id;
	uint32_t field_4;
	union {
		uint32_t xml[0];
		char string[0];
	};
};

struct IOSurfaceValueResultArgs {
	uint32_t field_0;
};

// ---- Global variables --------------------------------------------------------------------------

static uint32_t IOSurface_property_index = 0;

// Is the IOSurface subsystem initialized?
static bool IOSurface_initialized;

// The IOSurfaceRoot service.
mach_port_t IOSurfaceRoot;

// An IOSurfaceRootUserClient instance.
mach_port_t IOSurfaceRootUserClient;

// The ID of the IOSurface we're using.
uint32_t IOSurface_id;

// ---- Initialization ----------------------------------------------------------------------------

uint32_t iosurface_create_fast()
{
    kern_return_t kr;
    struct _IOSurfaceFastCreateArgs create_args = { .alloc_size = (uint32_t) g_exp.pagesize };
    struct IOSurfaceLockResult lock_result;
    size_t lock_result_size = sizeof(lock_result);
    kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            6, // create_surface_client_fast_path
            NULL, 0,
            &create_args, sizeof(create_args),
            NULL, NULL,
            &lock_result, &lock_result_size);
    if (kr != KERN_SUCCESS) {
        util_error("could not create %s: 0x%x", "IOSurfaceClient", kr);
        return 0;
    }
    return lock_result.surface_id;
}

uint32_t iosurface_s_get_ycbcrmatrix(void)
{
    uint64_t i_scalar[1] = { 1 }; // fixed, first valid client obj
    uint64_t o_scalar[1];
    uint32_t i_count = 1;
    uint32_t o_count = 1;

    kern_return_t kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            8, // s_get_ycbcrmatrix
            i_scalar, i_count,
            NULL, 0,
            o_scalar, &o_count,
            NULL, NULL);
    if (kr != KERN_SUCCESS) {
        util_error("s_get_ycbcrmatrix error: 0x%x", kr);
        return 0;
    }
    return (uint32_t)o_scalar[0];
}

void iosurface_s_set_indexed_timestamp(uint64_t v)
{
    uint64_t i_scalar[3] = {
        1, // fixed, first valid client obj
        0, // index
        v, // value
    };
    uint32_t i_count = 3;

    kern_return_t kr = IOConnectCallMethod(
            IOSurfaceRootUserClient,
            33, // s_set_indexed_timestamp
            i_scalar, i_count,
            NULL, 0,
            NULL, NULL,
            NULL, NULL);
    if (kr != KERN_SUCCESS) {
        util_error("s_set_indexed_timestamp error: 0x%x", kr);
    }
}

bool
IOSurface_init() {
	if (IOSurface_initialized) {
		return true;
	}
	IOSurfaceRoot = IOServiceGetMatchingService(
			kIOMasterPortDefault,
			IOServiceMatching("IOSurfaceRoot"));
	if (IOSurfaceRoot == MACH_PORT_NULL) {
		util_error("could not find %s", "IOSurfaceRoot");
		return false;
	}
	kern_return_t kr = IOServiceOpen(
			IOSurfaceRoot,
			mach_task_self(),
			0,
			&IOSurfaceRootUserClient);
	if (kr != KERN_SUCCESS) {
		util_error("could not open %s", "IOSurfaceRootUserClient");
		return false;
	}
	struct _IOSurfaceFastCreateArgs create_args = { .alloc_size = (uint32_t) g_exp.pagesize };
	struct IOSurfaceLockResult lock_result;
	size_t lock_result_size = sizeof(lock_result);
	kr = IOConnectCallMethod(
			IOSurfaceRootUserClient,
			6, // create_surface_client_fast_path
			NULL, 0,
			&create_args, sizeof(create_args),
			NULL, NULL,
			&lock_result, &lock_result_size);
	if (kr != KERN_SUCCESS) {
		util_error("could not create %s: 0x%x", "IOSurfaceClient", kr);
		return false;
	}
	IOSurface_id = lock_result.surface_id;
	IOSurface_initialized = true;
	return true;
}

void
IOSurface_deinit() {
	assert(IOSurface_initialized);
	IOSurface_initialized = false;
	IOSurface_id = 0;
	IOServiceClose(IOSurfaceRootUserClient);
	IOObjectRelease(IOSurfaceRoot);
}
