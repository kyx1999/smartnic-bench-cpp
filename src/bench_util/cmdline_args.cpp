#include "cmdline_args.h"

dma_args dma_args::parse(int argc, char *argv[]) {
    dma_args ret;

    struct option dma_cmdline_args[] = {
            {"pci_dev",      required_argument, nullptr, 'a'},
            {"rep_pci_dev",  optional_argument, nullptr, 'b'},
            {"random_space", optional_argument, nullptr, 'c'},
            {"life",         optional_argument, nullptr, 'd'},
            {"listen_addr",  optional_argument, nullptr, 'e'},
            {"huge_page",    optional_argument, nullptr, 'f'},
            {"client_id",    optional_argument, nullptr, 'g'},
            {"threads",      optional_argument, nullptr, 'h'},
            {"payload",      optional_argument, nullptr, 'i'},
            {"local_mr",     optional_argument, nullptr, 'j'},
            {"read",         optional_argument, nullptr, 'k'},
            {"fixed",        optional_argument, nullptr, 'l'},
            {"thread_gap",   optional_argument, nullptr, 'm'},
            {"latency_test", optional_argument, nullptr, 'n'},
            {"batch_size",   optional_argument, nullptr, 'o'},
            {"server",       optional_argument, nullptr, 'p'},
            {nullptr, 0,                        nullptr, 0}
    };
    int opt;

    bool pci_dev_exist = false;

    while ((opt = getopt_long_only(argc, argv, "a:b:c:d:e:fg:h:i:j:klm:no:p", dma_cmdline_args, nullptr)) != -1) {
        size_t i = 0;
        size_t last_i = 0;
        switch (opt) {
            case 'a':
                while (optarg[i] != '\0') {
                    if (optarg[i] == ' ' || optarg[i] == ',' || optarg[i] == '\n') {
                        ret.pci_dev.emplace_back(optarg + last_i, i - last_i);
                        last_i = i + 1;
                    }
                    i++;
                }
                ret.pci_dev.emplace_back(optarg + last_i);
                pci_dev_exist = true;
                break;
            case 'b':
                while (optarg[i] != '\0') {
                    if (optarg[i] == ' ' || optarg[i] == ',' || optarg[i] == '\n') {
                        ret.rep_pci_dev.emplace_back(optarg + last_i, i - last_i);
                        last_i = i + 1;
                    }
                    i++;
                }
                ret.rep_pci_dev.emplace_back(optarg + last_i);
                break;
            case 'c':
                ret.random_space = std::stoull(optarg);
                break;
            case 'd':
                ret.life = std::stoul(optarg);
                break;
            case 'e':
                ret.listen_addr = std::string(optarg);
                break;
            case 'f':
                ret.huge_page = true;
                break;
            case 'g':
                ret.client_id = std::stoull(optarg);
                break;
            case 'h':
                ret.threads = std::stoull(optarg);
                break;
            case 'i':
                ret.payload = std::stoull(optarg);
                break;
            case 'j':
                ret.local_mr = std::stoull(optarg);
                break;
            case 'k':
                ret.read = true;
                break;
            case 'l':
                ret.fixed = true;
                break;
            case 'm':
                ret.thread_gap = std::stoull(optarg);
                break;
            case 'n':
                ret.latency_test = true;
                break;
            case 'o':
                ret.batch_size = std::stoull(optarg);
                break;
            case 'p':
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

    return ret;
}

void dma_args::coordinate() {
    this->local_mr = std::max(((uint64_t) this->batch_size) * this->payload, this->local_mr);
    this->thread_gap = std::max(this->payload, this->thread_gap);
    this->random_space = std::max(this->payload, this->random_space);
    this->random_space = std::max(this->threads * this->thread_gap, this->random_space);
}
