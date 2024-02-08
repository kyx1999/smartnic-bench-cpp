#include "server_construct.h"

static doca_error_t host_negotiate_dma_direction_and_size(dma_args *args, struct doca_comm_channel_ep_t *ep,
                                                          struct doca_comm_channel_addr_t **peer_addr) {
    struct cc_msg_dma_direction host_dma_direction = {};
    struct cc_msg_dma_direction dpu_dma_direction = {};
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };
    doca_error_t result;
    size_t msg_len;

    result = doca_comm_channel_ep_connect(ep, SERVER_NAME, peer_addr); // SERVER_NAME双方必须一致 此处得到peer_addr
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_connect error" << std::endl;
        return result;
    }

    while ((result = doca_comm_channel_peer_addr_update_info(*peer_addr)) ==
           DOCA_ERROR_CONNECTION_INPROGRESS) // 等待连接建立完成
        nanosleep(&ts, &ts); // 小睡10微秒

    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_peer_addr_update_info error" << std::endl;
        return result;
    }

    /* First byte indicates if file is located on Host, other 4 bytes determine file size */
    if (args->read) {
        host_dma_direction.space_size = htonq(args->random_space);
        host_dma_direction.host_to_dpu = true;
    } else {
        host_dma_direction.host_to_dpu = false;
    }

    while ((result = doca_comm_channel_ep_sendto(ep, &host_dma_direction, sizeof(host_dma_direction),
                                                 DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
        nanosleep(&ts, &ts);

    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_sendto error" << std::endl;
        return result;
    }

    msg_len = sizeof(struct cc_msg_dma_direction);
    while ((result = doca_comm_channel_ep_recvfrom(ep, (void *) &dpu_dma_direction, &msg_len, DOCA_CC_MSG_FLAG_NONE,
                                                   peer_addr)) == DOCA_ERROR_AGAIN) {
        nanosleep(&ts, &ts);
        msg_len = sizeof(struct cc_msg_dma_direction);
    }
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        return result;
    }

    if (msg_len != sizeof(struct cc_msg_dma_direction)) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        return DOCA_ERROR_INVALID_VALUE;
    }

    if (!args->read)
        args->random_space = ntohq(dpu_dma_direction.space_size);

    return DOCA_SUCCESS;
}

static doca_error_t
wait_for_successful_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr) {
    struct cc_msg_dma_status msg_status = {};
    doca_error_t result;
    size_t msg_len, status_msg_len = sizeof(struct cc_msg_dma_status);
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };

    msg_len = status_msg_len;
    while ((result = doca_comm_channel_ep_recvfrom(ep, (void *) &msg_status, &msg_len, DOCA_CC_MSG_FLAG_NONE,
                                                   peer_addr)) == DOCA_ERROR_AGAIN) {
        nanosleep(&ts, &ts);
        msg_len = status_msg_len;
    }
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        return result;
    }

    if (!msg_status.is_success) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        return DOCA_ERROR_INVALID_VALUE;
    }

    return DOCA_SUCCESS;
}

static doca_error_t
host_export_memory_map_to_dpu(struct doca_mmap *mmap, struct doca_dev *dev, struct doca_comm_channel_ep_t *ep,
                              struct doca_comm_channel_addr_t **peer_addr, const void **export_desc) {
    doca_error_t result;
    size_t export_desc_len;
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };

    /* Export memory map to allow access to this memory region from DPU */
    result = doca_mmap_export_pci(mmap, dev, export_desc, &export_desc_len);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_export_pci error" << std::endl;
        return result;
    }

    /* Send the memory map export descriptor to DPU */
    while ((result = doca_comm_channel_ep_sendto(ep, *export_desc, export_desc_len, DOCA_CC_MSG_FLAG_NONE,
                                                 *peer_addr)) == DOCA_ERROR_AGAIN)
        nanosleep(&ts, &ts);

    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_sendto error" << std::endl;
        return result;
    }

    result = wait_for_successful_status_msg(ep, peer_addr);
    if (result != DOCA_SUCCESS) {
        std::cerr << "wait_for_successful_status_msg error" << std::endl;
        return result;
    }

    return DOCA_SUCCESS;
}

static doca_error_t
host_send_addr_and_offset(const char *src_buffer, size_t src_buffer_size, struct doca_comm_channel_ep_t *ep,
                          struct doca_comm_channel_addr_t **peer_addr) {
    doca_error_t result;
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };

    /* Send the full buffer address and length */
    uint64_t addr_to_send = htonq((uintptr_t) src_buffer);
    uint64_t length_to_send = htonq((uint64_t) src_buffer_size);

    while ((result = doca_comm_channel_ep_sendto(ep, &addr_to_send, sizeof(addr_to_send), DOCA_CC_MSG_FLAG_NONE,
                                                 *peer_addr)) == DOCA_ERROR_AGAIN)
        nanosleep(&ts, &ts);

    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_sendto error" << std::endl;
        return result;
    }

    result = wait_for_successful_status_msg(ep, peer_addr);
    if (result != DOCA_SUCCESS) {
        std::cerr << "wait_for_successful_status_msg error" << std::endl;
        return result;
    }

    while ((result = doca_comm_channel_ep_sendto(ep, &length_to_send, sizeof(length_to_send), DOCA_CC_MSG_FLAG_NONE,
                                                 *peer_addr)) == DOCA_ERROR_AGAIN)
        nanosleep(&ts, &ts);

    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_sendto error" << std::endl;
        return result;
    }

    result = wait_for_successful_status_msg(ep, peer_addr);
    if (result != DOCA_SUCCESS) {
        std::cerr << "wait_for_successful_status_msg error" << std::endl;
        return result;
    }

    return result;
}

void perform_server_routine(size_t thread_id, bench_runner *runner, bench_stat *stat, dma_args *args,
                            doca_comm_channel_ep_t *ep, doca_comm_channel_addr_t **peer_addr) {
    struct doca_mmap *mmap = nullptr;
    struct doca_dev *dev = nullptr;
    char *buffer = nullptr;
    const void *export_desc = nullptr;
    doca_error_t result, tmp_result;

    /* Negotiate DMA copy direction with DPU */
    result = host_negotiate_dma_direction_and_size(args, ep, peer_addr); // 协商过后更新的信息在dma_cfg里 同时填充了peer_addr
    if (result != DOCA_SUCCESS) {
        std::cerr << "host_negotiate_dma_direction_and_size error" << std::endl;
        exit(1);
    }

    /* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
    uint32_t dpu_access = args->read ? DOCA_ACCESS_FLAG_PCI_READ_ONLY : DOCA_ACCESS_FLAG_PCI_READ_WRITE;

    /* Open DOCA dma device */
    result = open_dma_device(&dev);
    if (result != DOCA_SUCCESS) {
        std::cerr << "open_dma_device error" << std::endl;
        exit(1);
    }

    result = doca_mmap_create(&mmap);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_create error" << std::endl;
        goto close_device;
    }

    result = doca_mmap_add_dev(mmap, dev);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_add_dev error" << std::endl;
        goto destroy_mmap;
    }

    result = memory_alloc_and_populate(args->huge_page, mmap, args->random_space, dpu_access, &buffer);
    if (result != DOCA_SUCCESS) {
        std::cerr << "memory_alloc_and_populate error" << std::endl;
        goto destroy_mmap;
    }

    /* Export memory map and send it to DPU */
    result = host_export_memory_map_to_dpu(mmap, dev, ep, peer_addr, &export_desc);
    if (result != DOCA_SUCCESS) {
        std::cerr << "host_export_memory_map_to_dpu error" << std::endl;
        goto free_buffer;
    }

    // 这里原本应放给buffer填充内容的代码

    /* Send source buffer address and offset (entire buffer) to enable DMA and wait until DPU is done */
    result = host_send_addr_and_offset(buffer, args->random_space, ep, peer_addr);
    if (result != DOCA_SUCCESS) {
        std::cerr << "host_send_addr_and_offset error" << std::endl;
        goto free_buffer;
    }

    /* Wait to DPU status message to indicate DMA was ended */
    result = wait_for_successful_status_msg(ep, peer_addr);
    if (result != DOCA_SUCCESS) {
        std::cerr << "wait_for_successful_status_msg error" << std::endl;
        goto free_buffer;
    }

    if (!args->read) {
        // result = print_buffer(dma_cfg, buffer);
    }

    free_buffer:
    if (args->huge_page) {
        munmap(buffer, round_up(args->random_space, 2 << 20));
    } else {
        delete[] buffer;
    }
    destroy_mmap:
    tmp_result = doca_mmap_destroy(mmap);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_destroy error" << std::endl;
    }
    close_device:
    tmp_result = doca_dev_close(dev);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_dev_close error" << std::endl;
    }
    if (result != DOCA_SUCCESS) {
        exit(1);
    }
}
