#ifndef ZWASM_BRIDGE_H
#define ZWASM_BRIDGE_H

#include <stdint.h>

enum {
    Z_API_NOP = 0,
    Z_API_K32_GET_TICK_COUNT = 1,
    Z_API_K32_SLEEP = 2,
    Z_API_K32_HEAP_ALLOC = 3,
    Z_API_K32_HEAP_FREE = 4,
    Z_API_U32_GET_ASYNC_KEY_STATE = 100,
    Z_API_U32_GET_KEY_STATE = 101,
    Z_API_U32_GET_CURSOR_POS = 102,
    Z_API_GL_GET_STRING = 200,
    Z_API_GL_CLEAR = 201,
    Z_API_GL_CLEAR_COLOR = 202,
    Z_API_GL_VIEWPORT = 203,
    Z_API_GL_DRAW_ARRAYS = 204,
};

enum {
    Z_BRIDGE_OK = 0,
    Z_BRIDGE_UNSUPPORTED = -1,
    Z_BRIDGE_BAD_ARGUMENT = -2,
};

typedef struct {
    int32_t api;
    int32_t a0;
    int32_t a1;
    int32_t a2;
    int32_t a3;
} zwasm_call_t;

/* Stable dispatch ABI shared by runtime shims and the browser host. */
int32_t zwasm_bridge_call(const zwasm_call_t *call);
int32_t zwasm_bridge_last_api(void);
int32_t zwasm_bridge_last_result(void);
int32_t zwasm_bridge_call_count(void);
int32_t zwasm_bridge_unsupported_count(void);

#endif
