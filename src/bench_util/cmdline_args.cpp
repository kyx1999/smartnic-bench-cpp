#include "cmdline_args.h"

dma_args dma_args::parse(int argc, char *argv[]) {
    dma_args ret;

    struct option dma_cmdline_args[] = {
            {"pci_dev",      required_argument, NULL, 'a'},
            {"random_space", optional_argument, NULL, 'b'},
            {"life",         optional_argument, NULL, 'c'},
            {"listen_addr",  required_argument, NULL, 'd'},
            {"huge_page",    optional_argument, NULL, 'e'},
            {"client_id",    optional_argument, NULL, 'f'},
            {"threads",      optional_argument, NULL, 'g'},
            {"payload",      optional_argument, NULL, 'h'},
            {"local_mr",     optional_argument, NULL, 'i'},
            {"read",         optional_argument, NULL, 'j'},
            {"fixed",        optional_argument, NULL, 'k'},
            {"thread_gap",   optional_argument, NULL, 'l'},
            {"latency_test", optional_argument, NULL, 'm'},
            {"batch_size",   optional_argument, NULL, 'n'},
            {"server",       optional_argument, NULL, 'o'},
            {NULL,           0,                 NULL, 0}
    };
    int opt;

    bool pci_dev_exist = false;
    bool listen_addr_exist = false;

    while ((opt = getopt_long_only(argc, argv, "a:b:c:d:ef:g:h:i:jkl:mn:o", dma_cmdline_args, NULL)) != -1) {
        uint64_t i = 0;
        uint64_t last_i = 0;
        switch (opt) {
            case 'a':
                while (optarg[i] != '\0') {
                    if (optarg[i] == ' ' || optarg[i] == ',' || optarg[i] == '\n') {
                        ret.pci_dev.push_back(std::string(optarg + last_i, i - last_i));
                        last_i = i + 1;
                    }
                    i++;
                }
                ret.pci_dev.push_back(std::string(optarg + last_i));
                pci_dev_exist = true;
                break;
            case 'b':
                ret.random_space = std::stoull(optarg);
                break;
            case 'c':
                ret.life = std::stoul(optarg);
                break;
            case 'd':
                ret.listen_addr = std::string(optarg);
                listen_addr_exist = true;
                break;
            case 'e':
                ret.huge_page = true;
                break;
            case 'f':
                ret.client_id = std::stoull(optarg);
                break;
            case 'g':
                ret.threads = std::stoull(optarg);
                break;
            case 'h':
                ret.payload = std::stoull(optarg);
                break;
            case 'i':
                ret.local_mr = std::stoull(optarg);
                break;
            case 'j':
                ret.read = true;
                break;
            case 'k':
                ret.fixed = true;
                break;
            case 'l':
                ret.thread_gap = std::stoull(optarg);
                break;
            case 'm':
                ret.latency_test = true;
                break;
            case 'n':
                ret.batch_size = std::stoull(optarg);
                break;
            case 'o':
                ret.server = true;
                break;
            default:
                break;
        }
    }

    if (!pci_dev_exist) {
        std::cerr << argv[0] << ": option pci_dev error" << std::endl;
        exit(1);
    }
    if (!listen_addr_exist) {
        std::cerr << argv[0] << ": option listen_addr error" << std::endl;
        exit(2);
    }

    return ret;
}
