#pragma once

// Switch ports
#if __TARGET_TOFINO__ == 1
    #define DEFAULT_EGRESS_PORT 0
    #define RECIRCULATION_PORT 68
#elif __TARGET_TOFINO__ == 2
    #define DEFAULT_EGRESS_PORT 9
    #define RECIRCULATION_PORT 1
#endif
#define RTT_REPORT_PORT 10