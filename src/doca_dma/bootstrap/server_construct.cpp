#include "server_construct.h" // TODO 所有doca库的销毁

std::pair<doca_mmap *, size_t> open_doca_device(std::vector<std::string> pci_devs) {
    size_t num_dev = pci_devs.size();
    doca_mmap **local_mmap = NULL;
    if (doca_mmap_create(local_mmap) != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_create error" << std::endl;
        exit(1);
    }

    uint32_t n = 0; // TODO 这样写可以吗？
    doca_devinfo ***dev_list = NULL;
    doca_error_t ret = doca_devinfo_create_list(dev_list, &n);
    if (n == 0 || ret != DOCA_SUCCESS) {
        std::cerr << "doca_devinfo_create_list error" << std::endl;
        exit(1);
    }

    for (size_t i = 0; i < n; i++) {
        for (const auto &d: pci_devs) {
            char *name = NULL; // TODO 这样写可以吗？
            if (doca_devinfo_get_pci_addr_str((*dev_list)[i], name) != DOCA_SUCCESS) {
                std::cerr << "doca_devinfo_get_pci_addr_str error" << std::endl;
                exit(1);
            }
            if (std::string(name) == d) {
                doca_dev **ctx = NULL;
                if (doca_dev_open((*dev_list)[i], ctx) != DOCA_SUCCESS) {
                    std::cerr << "doca_dev_open error" << std::endl;
                    exit(1);
                }
                if (doca_mmap_add_dev(*local_mmap, *ctx) != DOCA_SUCCESS) {
                    std::cerr << "doca_mmap_add_dev error" << std::endl;
                    exit(1);
                }
            }
        }
    }

    return std::make_pair(*local_mmap, num_dev);
}

void send_doca_config(std::string addr, size_t num_dev, doca_mmap *dm, uint8_t *src_buf) {
    // TODO
}

void perform_server_routine(size_t thread_id, bench_runner *runner, bench_stat *stat, dma_args args) {
    for (const auto &d: args.pci_dev) {
        std::cout << "pcie dev 0: " << d << std::endl;
    }

    uint8_t *src_region = NULL;
    uint64_t capacity = round_up(args.random_space, 2 << 20);
    if (args.huge_page) {
        src_region = (uint8_t *) mmap(NULL, capacity, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB, -1, 0);
        if (src_region == MAP_FAILED) {
            std::cerr << "Failed to create huge-page MR" << std::endl;
            exit(1);
        }
    } else {
        src_region = new uint8_t[args.random_space];
    }

    auto [local_mmap, num_dev] {open_doca_device(args.pci_dev)};
    if (doca_mmap_set_memrange(local_mmap, src_region, getpagesize()) != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_set_memrange error" << std::endl;
        exit(1);
    }

    send_doca_config(args.listen_addr, num_dev, local_mmap, src_region);

    if (args.huge_page) {
        munmap(src_region, capacity);
    } else {
        delete[] src_region;
    }

    std::cout << "Server exit." << std::endl;
}
