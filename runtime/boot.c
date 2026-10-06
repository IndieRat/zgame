#include <stdint.h>

extern void z_host_log(int32_t ptr, int32_t len);
extern int32_t z_host_image_size(void);
extern int32_t z_host_frame(int32_t frame);
extern int32_t z_host_input(int32_t code, int32_t down);

static volatile int32_t g_image_size;
static volatile int32_t g_frame;
static volatile int32_t g_last_input;
static volatile int32_t g_started;
static const char boot_message[] = "ZWASM boot adapter online";

__attribute__((export_name("zwasm_init")))
int32_t zwasm_init(void) {
    g_image_size = z_host_image_size();
    g_frame = 0;
    g_last_input = 0;
    g_started = 1;
    z_host_log((int32_t)(uintptr_t)boot_message,
               (int32_t)(sizeof(boot_message) - 1));
    return g_image_size >= 0 ? 0 : -1;
}

__attribute__((export_name("zwasm_frame")))
int32_t zwasm_frame(int32_t frame) {
    if (!g_started) return -1;
    g_frame = frame;
    return z_host_frame(frame);
}

__attribute__((export_name("zwasm_input")))
int32_t zwasm_input(int32_t code, int32_t down) {
    if (!g_started) return -1;
    g_last_input = code;
    return z_host_input(code, down);
}

__attribute__((export_name("zwasm_status")))
int32_t zwasm_status(void) { return g_started ? 1 : 0; }

__attribute__((export_name("zwasm_image_size")))
int32_t zwasm_image_size(void) { return g_image_size; }

__attribute__((export_name("zwasm_frame_count")))
int32_t zwasm_frame_count(void) { return g_frame; }

__attribute__((export_name("zwasm_last_input")))
int32_t zwasm_last_input(void) { return g_last_input; }
