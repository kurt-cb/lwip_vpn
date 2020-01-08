#pragma once

#include <stdint.h>

struct BACKBONE {
    void (*ip_stack_init)(uint32_t ipaddr);
};
extern struct BACKBONE udp_backbone;
