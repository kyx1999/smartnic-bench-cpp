#ifndef _CMDLINE_ARGS_
#define _CMDLINE_ARGS_

#include <iostream>
#include <string>
#include <vector>

#include <getopt.h>

class dma_args {
public:
    std::vector <std::string> pci_dev;
    uint64_t random_space = 10 * 1024;
    uint32_t life = 15;
    std::string listen_addr;
    bool huge_page = false;
    uint64_t client_id = 0;
    uint64_t threads = 1;
    uint64_t payload = 32;
    uint64_t local_mr = 4096;
    bool read = false;
    bool fixed = false;
    uint64_t thread_gap = 8192;
    bool latency_test = false;
    size_t batch_size = 64;
    bool server = false;

    static dma_args parse(int argc, char *argv[]);
};

#endif
