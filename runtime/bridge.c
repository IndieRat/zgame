#include "bridge.h"

extern int32_t z_host_api(int32_t api, int32_t a0, int32_t a1,
                          int32_t a2, int32_t a3);

static volatile int32_t g_last_api;
static volatile int32_t g_last_result;
static volatile int32_t g_calls;
static volatile int32_t g_unsupported;

__attribute__((export_name("zwasm_api_call")))
int32_t zwasm_api_call(int32_t api, int32_t a0, int32_t a1,
                       int32_t a2, int32_t a3) {
    zwasm_call_t call = { api, a0, a1, a2, a3 };
    return zwasm_bridge_call(&call);
}

int32_t zwasm_bridge_call(const zwasm_call_t *call) {
    if (!call) return Z_BRIDGE_BAD_ARGUMENT;
    g_last_api = call->api;
    g_calls++;
    int32_t result = z_host_api(call->api, call->a0, call->a1, call->a2, call->a3);
    g_last_result = result;
    if (result == Z_BRIDGE_UNSUPPORTED) g_unsupported++;
    return result;
}

__attribute__((export_name("zwasm_bridge_last_api")))
int32_t zwasm_bridge_last_api(void) { return g_last_api; }
__attribute__((export_name("zwasm_bridge_last_result")))
int32_t zwasm_bridge_last_result(void) { return g_last_result; }
__attribute__((export_name("zwasm_bridge_call_count")))
int32_t zwasm_bridge_call_count(void) { return g_calls; }
__attribute__((export_name("zwasm_bridge_unsupported_count")))
int32_t zwasm_bridge_unsupported_count(void) { return g_unsupported; }
