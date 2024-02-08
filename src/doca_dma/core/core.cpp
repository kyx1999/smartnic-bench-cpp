#include "core.h"

static doca_error_t open_doca_device_with_pci(const char *pci_addr, tasks_check func, struct doca_dev **retval) {
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    uint8_t is_addr_equal = 0;
    doca_error_t res;
    size_t i;

    /* Set default return value */
    *retval = nullptr;

    res = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (res != DOCA_SUCCESS) {
        std::cerr << "open_doca_device_with_pci error" << std::endl;
        return res;
    }

    /* Search */
    for (i = 0; i < nb_devs; i++) {
        res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci_addr, &is_addr_equal);
        if (res == DOCA_SUCCESS && is_addr_equal) {
            /* If any special capabilities are needed */
            if (func != nullptr && func(dev_list[i]) != DOCA_SUCCESS)
                continue;

            /* if device can be opened */
            res = doca_dev_open(dev_list[i], retval);
            if (res == DOCA_SUCCESS) {
                doca_devinfo_destroy_list(dev_list);
                return res;
            }
        }
    }

    std::cerr << "tasks_check or doca_dev_open error" << std::endl;
    res = DOCA_ERROR_NOT_FOUND;

    doca_devinfo_destroy_list(dev_list);
    return res;
}

static doca_error_t
open_doca_device_rep_with_pci(struct doca_dev *local, enum doca_devinfo_rep_filter filter, const char *pci_addr,
                              struct doca_dev_rep **retval) {
    uint32_t nb_rdevs = 0;
    struct doca_devinfo_rep **rep_dev_list = nullptr;
    uint8_t is_addr_equal = 0;
    doca_error_t result;
    size_t i;

    *retval = nullptr;

    /* Search */
    result = doca_devinfo_rep_create_list(local, filter, &rep_dev_list, &nb_rdevs);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_devinfo_rep_create_list error" << std::endl;
        return DOCA_ERROR_INVALID_VALUE;
    }

    for (i = 0; i < nb_rdevs; i++) {
        result = doca_devinfo_rep_is_equal_pci_addr(rep_dev_list[i], pci_addr, &is_addr_equal);
        if (result == DOCA_SUCCESS && is_addr_equal &&
            doca_dev_rep_open(rep_dev_list[i], retval) == DOCA_SUCCESS) {
            doca_devinfo_rep_destroy_list(rep_dev_list);
            return DOCA_SUCCESS;
        }
    }

    std::cerr << "doca_devinfo_rep_is_equal_pci_addr error" << std::endl;
    doca_devinfo_rep_destroy_list(rep_dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

static doca_error_t set_cc_properties(bool is_server, struct doca_comm_channel_ep_t *ep, struct doca_dev *dev,
                                      struct doca_dev_rep *dev_rep) {
    doca_error_t result;

    result = doca_comm_channel_ep_set_device(ep, dev);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_set_device error" << std::endl;
        return result;
    }

    result = doca_comm_channel_ep_set_max_msg_size(ep, CC_MAX_MSG_SIZE);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_set_max_msg_size error" << std::endl;
        return result;
    }

    result = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_set_send_queue_size error" << std::endl;
        return result;
    }

    result = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_set_recv_queue_size error" << std::endl;
        return result;
    }

    if (!is_server) {
        result = doca_comm_channel_ep_set_device_rep(ep, dev_rep);
        if (result != DOCA_SUCCESS)
            std::cerr << "doca_comm_channel_ep_set_device_rep error" << std::endl;
    }

    return result;
}

doca_error_t init_cc(bool is_server, const std::string &cc_dev_pci_addr, const std::string &cc_dev_rep_pci_addr,
                     struct doca_comm_channel_ep_t **ep, struct doca_dev **dev, struct doca_dev_rep **dev_rep) {
    doca_error_t result, tmp_result;

    result = doca_comm_channel_ep_create(ep);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_create error" << std::endl;
        return result;
    }

    result = open_doca_device_with_pci(cc_dev_pci_addr.c_str(), nullptr, dev);
    if (result != DOCA_SUCCESS) {
        std::cerr << "open_doca_device_with_pci error" << std::endl;
        goto destroy_ep;
    }

    if (!is_server) {
        result = open_doca_device_rep_with_pci(*dev, DOCA_DEVINFO_REP_FILTER_NET, cc_dev_rep_pci_addr.c_str(), dev_rep);
        if (result != DOCA_SUCCESS) {
            std::cerr << "open_doca_device_rep_with_pci error" << std::endl;
            goto close_device;
        }
    }

    result = set_cc_properties(is_server, *ep, *dev, *dev_rep);
    if (result != DOCA_SUCCESS) {
        if (!is_server)
            doca_dev_rep_close(*dev_rep);
        std::cerr << "set_cc_properties error" << std::endl;
        goto close_device;
    }

    return result;

    close_device:
    tmp_result = doca_dev_close(*dev);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_dev_close error" << std::endl;
    }
    destroy_ep:
    tmp_result = doca_comm_channel_ep_destroy(*ep);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_destroy error" << std::endl;
    }

    return result;
}

doca_error_t destroy_cc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t *peer, struct doca_dev *dev,
                        struct doca_dev_rep *dev_rep) {
    doca_error_t result;

    if (peer != nullptr) {
        result = doca_comm_channel_ep_disconnect(ep, peer);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_comm_channel_ep_disconnect error" << std::endl;
        }
    }

    result = doca_comm_channel_ep_destroy(ep);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_destroy error" << std::endl;
    }

    if (dev_rep != nullptr) {
        result = doca_dev_rep_close(dev_rep);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_dev_rep_close error" << std::endl;
        }
    }

    result = doca_dev_close(dev);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_dev_close error" << std::endl;
    }

    return result;
}

static doca_error_t open_doca_device_with_capabilities(tasks_check func, struct doca_dev **retval) {
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    doca_error_t result;
    size_t i;

    /* Set default return value */
    *retval = nullptr;

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_devinfo_create_list error" << std::endl;
        return result;
    }

    /* Search */
    for (i = 0; i < nb_devs; i++) {
        /* If any special capabilities are needed */
        if (func(dev_list[i]) != DOCA_SUCCESS)
            continue;

        /* If device can be opened */
        if (doca_dev_open(dev_list[i], retval) == DOCA_SUCCESS) {
            doca_devinfo_destroy_list(dev_list);
            return DOCA_SUCCESS;
        }
    }

    std::cerr << "tasks_check or doca_dev_open error" << std::endl;
    doca_devinfo_destroy_list(dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

static doca_error_t check_dev_dma_capable(struct doca_devinfo *devinfo) {
    return doca_dma_cap_task_memcpy_is_supported(devinfo);
}

doca_error_t open_dma_device(struct doca_dev **dev) {
    doca_error_t result;

    result = open_doca_device_with_capabilities(check_dev_dma_capable, dev);

    return result;
}

doca_error_t
memory_alloc_and_populate(bool is_huge_page, struct doca_mmap *dm, size_t buffer_len, uint32_t access_flags,
                          char **buffer) {
    doca_error_t result;

    result = doca_mmap_set_permissions(dm, access_flags);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_set_permissions error" << std::endl;
        return result;
    }

    uint8_t *src_region;
    uint64_t capacity = round_up(buffer_len, 2 << 20);
    if (is_huge_page) {
        src_region = (uint8_t *) mmap(nullptr, capacity, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB, -1, 0);
        if (src_region == MAP_FAILED) {
            std::cerr << "mmap error" << std::endl;
            return DOCA_ERROR_NO_MEMORY;
        }
    } else {
        src_region = new(std::nothrow) uint8_t[buffer_len];
        if (src_region == nullptr) {
            std::cerr << "new error" << std::endl;
            return DOCA_ERROR_NO_MEMORY;
        }
    }
    *buffer = (char *) src_region;

    result = doca_mmap_set_memrange(dm, *buffer, buffer_len);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_set_memrange error" << std::endl;
        if (is_huge_page) {
            munmap(src_region, capacity);
        } else {
            delete[] src_region;
        }
        return result;
    }

    /* Populate local buffer into memory map to allow access from DPU side after exporting */
    result = doca_mmap_start(dm);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_start error" << std::endl;
        if (is_huge_page) {
            munmap(src_region, capacity);
        } else {
            delete[] src_region;
        }
    }

    return result;
}

doca_error_t fill_buffer_with_memory_content(size_t buffer_size, char *buffer) {
    memset(buffer, '1', buffer_size);
    return DOCA_SUCCESS;
}
