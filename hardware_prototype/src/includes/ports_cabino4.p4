#pragma once

// Switch ports
#if __TARGET_TOFINO__ == 1
    #define DEFAULT_EGRESS_PORT 264
    #define RECIRCULATION_PORT 256
#elif __TARGET_TOFINO__ == 2
    #define DEFAULT_EGRESS_PORT 264
    #define RECIRCULATION_PORT 256
#endif
#define RTT_REPORT_PORT 264