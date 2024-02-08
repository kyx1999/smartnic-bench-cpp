#include "client_construct.h"

doca_error_t create_core_objects(struct program_core_objects *state, uint32_t max_bufs) {
    doca_error_t res;

    res = doca_mmap_create(&state->src_mmap);
    if (res != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_create error" << std::endl;
        return res;
    }
    res = doca_mmap_add_dev(state->src_mmap, state->dev);
    if (res != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_add_dev error" << std::endl;
        goto destroy_src_mmap;
    }

    res = doca_mmap_create(&state->dst_mmap);
    if (res != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_create error" << std::endl;
        goto destroy_src_mmap;
    }
    res = doca_mmap_add_dev(state->dst_mmap, state->dev);
    if (res != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_add_dev error" << std::endl;
        goto destroy_dst_mmap;
    }

    if (max_bufs != 0) {
        res = doca_buf_inventory_create(max_bufs, &state->buf_inv);
        if (res != DOCA_SUCCESS) {
            std::cerr << "doca_buf_inventory_create error" << std::endl;
            goto destroy_dst_mmap;
        }

        res = doca_buf_inventory_start(state->buf_inv);
        if (res != DOCA_SUCCESS) {
            std::cerr << "doca_buf_inventory_start error" << std::endl;
            goto destroy_buf_inv;
        }
    }

    res = doca_pe_create(&state->pe);
    if (res != DOCA_SUCCESS) {
        std::cerr << "doca_pe_create error" << std::endl;
        goto destroy_buf_inv;
    }

    return DOCA_SUCCESS;

    destroy_buf_inv:
    if (state->buf_inv != nullptr) {
        doca_buf_inventory_destroy(state->buf_inv);
        state->buf_inv = nullptr;
    }

    destroy_dst_mmap:
    doca_mmap_destroy(state->dst_mmap);
    state->dst_mmap = nullptr;

    destroy_src_mmap:
    doca_mmap_destroy(state->src_mmap);
    state->src_mmap = nullptr;

    return res;
}

static void dma_memcpy_completed_callback(struct doca_dma_task_memcpy *dma_task, union doca_data task_user_data,
                                          union doca_data ctx_user_data) {
    auto *num_remaining_tasks = (size_t *) ctx_user_data.ptr;
    auto *result = (doca_error_t *) task_user_data.ptr;

    (void) dma_task;
    /* Decrement number of remaining tasks */
    --*num_remaining_tasks;
    /* Assign success to the result */
    *result = DOCA_SUCCESS;
}

static void dma_memcpy_error_callback(struct doca_dma_task_memcpy *dma_task, union doca_data task_user_data,
                                      union doca_data ctx_user_data) {
    auto *num_remaining_tasks = (size_t *) ctx_user_data.ptr;
    struct doca_task *task = doca_dma_task_memcpy_as_task(dma_task);
    auto *result = (doca_error_t *) task_user_data.ptr;

    /* Decrement number of remaining tasks */
    --*num_remaining_tasks;
    /* Get the result of the task */
    *result = doca_task_get_status(task);
}

doca_error_t destroy_core_objects(struct program_core_objects *state) {
    doca_error_t result;

    if (state->pe != nullptr) {
        result = doca_pe_destroy(state->pe);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_pe_destroy error" << std::endl;
        }
        state->pe = nullptr;
    }

    if (state->buf_inv != nullptr) {
        result = doca_buf_inventory_destroy(state->buf_inv);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_buf_inventory_destroy error" << std::endl;
        }
        state->buf_inv = nullptr;
    }

    if (state->dst_mmap != nullptr) {
        result = doca_mmap_destroy(state->dst_mmap);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_mmap_destroy error" << std::endl;
        }
        state->dst_mmap = nullptr;
    }

    if (state->src_mmap != nullptr) {
        result = doca_mmap_destroy(state->src_mmap);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_mmap_destroy error" << std::endl;
        }
        state->src_mmap = nullptr;
    }

    if (state->dev != nullptr) {
        result = doca_dev_close(state->dev);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_dev_close error" << std::endl;
        }
        state->dev = nullptr;
    }

    return result;
}

static doca_error_t allocate_dma_copy_resources(struct dma_copy_resources *resources) {
    struct program_core_objects *state;
    doca_error_t result, tmp_result;
    /* Two buffers for source and destination */
    uint32_t max_bufs = 2;

    resources->state = (program_core_objects *) malloc(sizeof(*(resources->state)));
    if (resources->state == nullptr) {
        result = DOCA_ERROR_NO_MEMORY;
        std::cerr << "malloc error" << std::endl;
        return result;
    }
    state = resources->state;

    /* Open DOCA dma device */
    result = open_dma_device(&state->dev); // 这里值得细看 如何获取设备list 检查设备都在里面
    if (result != DOCA_SUCCESS) {
        std::cerr << "open_dma_device error" << std::endl;
        goto free_state;
    }

    result = create_core_objects(state, max_bufs);
    if (result != DOCA_SUCCESS) {
        std::cerr << "create_core_objects error" << std::endl;
        goto destroy_core_objects;
    }

    result = doca_dma_create(state->dev, &resources->dma_ctx);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_dma_create error" << std::endl;
        goto destroy_core_objects;
    }

    state->ctx = doca_dma_as_ctx(resources->dma_ctx);

    result = doca_pe_connect_ctx(state->pe, state->ctx);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_pe_connect_ctx error" << std::endl;
        goto destroy_dma;
    }

    result = doca_dma_task_memcpy_set_conf(resources->dma_ctx, dma_memcpy_completed_callback, dma_memcpy_error_callback,
                                           NUM_DMA_TASKS);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_dma_task_memcpy_set_conf error" << std::endl;
        goto destroy_dma;
    }

    return result;

    destroy_dma:
    tmp_result = doca_dma_destroy(resources->dma_ctx);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_dma_destroy error" << std::endl;
    }
    destroy_core_objects:
    tmp_result = destroy_core_objects(state);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "destroy_core_objects error" << std::endl;
    }
    free_state:
    free(resources->state);

    return result;
}

static doca_error_t get_dma_max_buf_size(struct dma_copy_resources *resources, uint64_t *max_buf_size) {
    struct doca_devinfo *dma_dev_info = doca_dev_as_devinfo(resources->state->dev);
    doca_error_t result;

    result = doca_dma_cap_task_memcpy_get_max_buf_size(dma_dev_info, max_buf_size);
    if (result != DOCA_SUCCESS)
        std::cerr << "doca_dma_cap_task_memcpy_get_max_buf_size error" << std::endl;

    return result;
}

static doca_error_t
send_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr, bool status) {
    struct cc_msg_dma_status status_msg = {};
    doca_error_t result;
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };

    status_msg.is_success = status;

    while ((result = doca_comm_channel_ep_sendto(ep, &status_msg, sizeof(struct cc_msg_dma_status),
                                                 DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
        nanosleep(&ts, &ts);

    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_sendto error" << std::endl;
        return result;
    }

    return DOCA_SUCCESS;
}

static doca_error_t dpu_negotiate_dma_direction_and_size(dma_args *args, struct doca_comm_channel_ep_t *ep,
                                                         struct doca_comm_channel_addr_t **peer_addr,
                                                         uint64_t max_buf_size) {
    struct cc_msg_dma_direction host_dma_direction = {};
    struct cc_msg_dma_direction dpu_dma_direction = {};
    struct cc_msg_dma_status status_msg = {
            .is_success = false
    };
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };
    doca_error_t result;
    size_t msg_len;

    if (!args->read) {
        dpu_dma_direction.host_to_dpu = false;
        dpu_dma_direction.space_size = htonq(args->random_space);
    } else {
        dpu_dma_direction.host_to_dpu = true;
    }

    result = doca_comm_channel_ep_listen(ep, SERVER_NAME); // SERVER_NAME双方必须一致
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_listen error" << std::endl;
        return result;
    }

    /* Wait until Host negotiation message will arrive */
    msg_len = sizeof(struct cc_msg_dma_direction);
    while ((result = doca_comm_channel_ep_recvfrom(ep, (void *) &host_dma_direction, &msg_len, DOCA_CC_MSG_FLAG_NONE,
                                                   peer_addr)) ==
           DOCA_ERROR_AGAIN) { // 此处阻塞 此函数作为服务器时同时兼任等待连接建立的功能 直到对方发来信息后才继续 listen处不阻塞
        nanosleep(&ts, &ts); // 小睡10微秒
        msg_len = sizeof(struct cc_msg_dma_direction);
    }
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return result;
    }

    if (msg_len != sizeof(struct cc_msg_dma_direction)) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return DOCA_ERROR_INVALID_VALUE;
    }

    /* Make sure file is located only on one side */
    if ((!args->read) && host_dma_direction.host_to_dpu) {
        std::cerr << "args or host_dma_direction error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return DOCA_ERROR_INVALID_VALUE;

    } else if (args->read) {
        if (!host_dma_direction.host_to_dpu) {
            std::cerr << "args or host_dma_direction error" << std::endl;
            send_status_msg(ep, peer_addr, STATUS_FAILURE);
            return DOCA_ERROR_INVALID_VALUE;
        }
        args->random_space = ntohq(host_dma_direction.space_size);
    }

    /* Verify file size against the HW limitation */
    if (args->random_space > max_buf_size) {
        /* Send failure message to Host */
        std::cerr << "args or max_buf_size error" << std::endl;
        while ((result = doca_comm_channel_ep_sendto(ep, &status_msg, sizeof(struct cc_msg_dma_status),
                                                     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
            nanosleep(&ts, &ts);

        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_comm_channel_ep_sendto error" << std::endl;
            return result;
        }

        result = DOCA_ERROR_INVALID_VALUE;
    } else {
        /* Send direction message to Host to end negotiation */
        while ((result = doca_comm_channel_ep_sendto(ep, &dpu_dma_direction, sizeof(struct cc_msg_dma_direction),
                                                     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
            nanosleep(&ts, &ts);

        if (result != DOCA_SUCCESS)
            std::cerr << "doca_comm_channel_ep_sendto error" << std::endl;
    }

    return result;
}

static doca_error_t
dpu_receive_export_desc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
                        char *export_desc_buffer, size_t *export_desc_len) {
    size_t msg_len;
    doca_error_t result;
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };

    /* Receive exported descriptor from Host */
    msg_len = CC_MAX_MSG_SIZE;
    while ((result = doca_comm_channel_ep_recvfrom(ep, (void *) export_desc_buffer, &msg_len, DOCA_CC_MSG_FLAG_NONE,
                                                   peer_addr)) == DOCA_ERROR_AGAIN) {
        nanosleep(&ts, &ts);
        msg_len = CC_MAX_MSG_SIZE;
    }
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return result;
    }

    *export_desc_len = msg_len;

    result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
    if (result != DOCA_SUCCESS)
        return result;

    return result;
}

static doca_error_t
dpu_receive_addr_and_offset(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
                            char **host_addr, size_t *host_offset) {
    doca_error_t result;
    uint64_t received_addr, received_addr_len;
    size_t msg_len;
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };

    /* Receive remote source buffer address */
    msg_len = sizeof(received_addr);
    while ((result = doca_comm_channel_ep_recvfrom(ep, (void *) &received_addr, &msg_len, DOCA_CC_MSG_FLAG_NONE,
                                                   peer_addr)) == DOCA_ERROR_AGAIN) {
        nanosleep(&ts, &ts);
        msg_len = sizeof(received_addr);
    }
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return result;
    }

    received_addr = ntohq(received_addr);
    if (received_addr > SIZE_MAX) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return DOCA_ERROR_INVALID_VALUE;
    }
    *host_addr = (char *) received_addr;

    result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
    if (result != DOCA_SUCCESS)
        return result;

    /* Receive remote source buffer length */
    msg_len = sizeof(received_addr_len);
    while ((result = doca_comm_channel_ep_recvfrom(ep, (void *) &received_addr_len, &msg_len, DOCA_CC_MSG_FLAG_NONE,
                                                   peer_addr)) == DOCA_ERROR_AGAIN) {
        nanosleep(&ts, &ts);
        msg_len = sizeof(received_addr_len);
    }
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return result;
    }

    received_addr_len = ntohq(received_addr_len);
    if (received_addr_len > SIZE_MAX) {
        std::cerr << "doca_comm_channel_ep_recvfrom error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        return DOCA_ERROR_INVALID_VALUE;
    }
    *host_offset = (size_t) received_addr_len;

    result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);

    return result;
}

static doca_error_t
dpu_submit_dma_task(dma_args *args, struct dma_copy_resources *resources, size_t bytes_to_copy, char *buffer,
                    struct doca_buf *local_doca_buf, struct doca_buf *remote_doca_buf,
                    const size_t *num_remaining_tasks) {
    struct program_core_objects *state = resources->state;
    struct doca_dma_task_memcpy *dma_task;
    struct doca_task *task;
    union doca_data task_user_data = {};
    void *data;
    struct doca_buf *src_buf;
    struct doca_buf *dst_buf;
    struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = SLEEP_IN_NANOS,
    };
    doca_error_t result;
    doca_error_t task_result;

    /* Determine DMA copy direction */
    if (!args->read) {
        src_buf = local_doca_buf;
        dst_buf = remote_doca_buf;
    } else {
        src_buf = remote_doca_buf;
        dst_buf = local_doca_buf;
    }

    /* Set data position in src_buf */
    result = doca_buf_get_data(src_buf, &data);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_buf_get_data error" << std::endl;
        return result;
    }
    result = doca_buf_set_data(src_buf, data, bytes_to_copy);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_buf_set_data error" << std::endl;
        return result;
    }

    /* Include result in user data of task to be used in the callbacks */
    task_user_data.ptr = &task_result;
    /* Allocate and construct DMA task */
    result = doca_dma_task_memcpy_alloc_init(resources->dma_ctx, src_buf, dst_buf, task_user_data,
                                             &dma_task); // task_user_data貌似时用来回调的 task执行后的结果会被存在里面 但是这里没讲清楚为什么可以这样用
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_dma_task_memcpy_alloc_init error" << std::endl;
        return result;
    }

    task = doca_dma_task_memcpy_as_task(dma_task);

    /* Submit DMA task */
    result = doca_task_submit(task);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_task_submit error" << std::endl;
        goto free_task;
    }

    /* Wait for all tasks to be completed */
    while (*num_remaining_tasks > 0) {
        if (doca_pe_progress(state->pe) == 0)
            nanosleep(&ts, &ts);
    }

    /* Check result of task according to the result we update in the callbacks */
    if (task_result != DOCA_SUCCESS) {
        std::cerr << "doca_task_submit error" << std::endl;
        result = task_result;
        goto free_task;
    }

    if (args->read) {
        // result = print_buffer(dma_cfg, buffer);
    }

    free_task:
    doca_task_free(task);
    return result;
}

doca_error_t request_stop_ctx(struct doca_pe *pe, struct doca_ctx *ctx) {
    doca_error_t result;

    result = doca_ctx_stop(ctx);
    if (result == DOCA_ERROR_IN_PROGRESS) {
        enum doca_ctx_states ctx_state;

        do {
            (void) doca_pe_progress(pe);
            result = doca_ctx_get_state(ctx, &ctx_state);
            if (result != DOCA_SUCCESS) {
                std::cerr << "doca_ctx_get_state error" << std::endl;
                break;
            }
        } while (ctx_state != DOCA_CTX_STATE_IDLE);
    } else if (result != DOCA_SUCCESS) {
        std::cerr << "doca_ctx_stop error" << std::endl;
    }

    return result;
}

static doca_error_t destroy_dma_copy_resources(struct dma_copy_resources *resources) {
    struct program_core_objects *state = resources->state;
    doca_error_t result;

    if (resources->dma_ctx != nullptr) {
        result = doca_dma_destroy(resources->dma_ctx);
        if (result != DOCA_SUCCESS) {
            std::cerr << "doca_dma_destroy error" << std::endl;
        }
    }

    result = destroy_core_objects(state);
    if (result != DOCA_SUCCESS) {
        std::cerr << "destroy_core_objects error" << std::endl;
    }

    free(resources->state);

    return result;
}

void perform_client_routine(size_t thread_id, bench_runner *runner, bench_stat *stat, dma_args *args,
                            doca_comm_channel_ep_t *ep, doca_comm_channel_addr_t **peer_addr) {
    struct dma_copy_resources resources = {};
    struct program_core_objects *state;
    /* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
    uint32_t access_flags = !args->read ? DOCA_ACCESS_FLAG_LOCAL_READ_ONLY : DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint64_t max_buf_size;
    char *buffer;
    char *host_dma_addr = nullptr;
    char export_desc_buf[CC_MAX_MSG_SIZE];
    struct doca_buf *remote_doca_buf = nullptr;
    struct doca_buf *local_doca_buf = nullptr;
    struct doca_mmap *remote_mmap = nullptr;
    size_t host_dma_offset, export_desc_len;
    union doca_data ctx_user_data = {};
    /* Number of tasks submitted to progress engine */
    size_t num_remaining_tasks = 1; // TODO
    doca_error_t result, tmp_result;

    /* Allocate DMA copy resources */
    result = allocate_dma_copy_resources(&resources);
    if (result != DOCA_SUCCESS) {
        std::cerr << "allocate_dma_copy_resources error" << std::endl;
        exit(1);
    }
    state = resources.state;

    result = get_dma_max_buf_size(&resources, &max_buf_size);
    if (result != DOCA_SUCCESS) {
        std::cerr << "get_dma_max_buf_size error" << std::endl;
        goto destroy_dma_resources;
    }

    /* Include tasks counter in user data of context to be decremented in callbacks */
    ctx_user_data.ptr = &num_remaining_tasks; // 将num_remaining_tasks注册进ctx_user_data后 经过doca_ctx_start 后续在dpu_submit_dma_task就可以跟踪剩余task的数量 但是这里没讲清楚为什么可以这样用
    doca_ctx_set_user_data(state->ctx, ctx_user_data);

    result = doca_ctx_start(state->ctx);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_ctx_start error" << std::endl;
        goto destroy_dma_resources;
    }

    /* Negotiate DMA copy direction with Host */
    result = dpu_negotiate_dma_direction_and_size(args, ep, peer_addr,
                                                  max_buf_size); // 协商过后更新的信息在dma_cfg里 同时填充了peer_addr
    if (result != DOCA_SUCCESS) {
        std::cerr << "dpu_negotiate_dma_direction_and_size error" << std::endl;
        goto stop_dma;
    }

    result = memory_alloc_and_populate(args->huge_page, state->src_mmap, args->random_space, access_flags, &buffer);
    if (result != DOCA_SUCCESS) {
        std::cerr << "memory_alloc_and_populate error" << std::endl;
        goto stop_dma;
    }

    /* Receive export descriptor from Host */
    result = dpu_receive_export_desc(ep, peer_addr, export_desc_buf, &export_desc_len);
    if (result != DOCA_SUCCESS) {
        std::cerr << "dpu_receive_export_desc error" << std::endl;
        goto free_buffer;
    }

    /* Create a local DOCA mmap from export descriptor */
    result = doca_mmap_create_from_export(nullptr, (const void *) export_desc_buf, export_desc_len, state->dev,
                                          &remote_mmap);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_create_from_export error" << std::endl;
        goto free_buffer;
    }

    /* Receive remote address and offset from Host */
    result = dpu_receive_addr_and_offset(ep, peer_addr, &host_dma_addr, &host_dma_offset);
    if (result != DOCA_SUCCESS) {
        std::cerr << "dpu_receive_addr_and_offset error" << std::endl;
        goto destroy_remote_mmap;
    }

    /* Construct DOCA buffer for remote (Host) address range */
    result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, remote_mmap, host_dma_addr, host_dma_offset,
                                                &remote_doca_buf);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_buf_inventory_buf_get_by_addr error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        goto destroy_remote_mmap;
    }

    /* Construct DOCA buffer for local (DPU) address range */
    result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->src_mmap, buffer, host_dma_offset,
                                                &local_doca_buf);
    if (result != DOCA_SUCCESS) {
        std::cerr << "doca_buf_inventory_buf_get_by_addr error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        goto destroy_remote_buf;
    }

    /* Fill buffer in file content if relevant */
    if (!args->read) {
        // result = fill_buffer_with_file_content(dma_cfg, buffer);
        result = fill_buffer_with_memory_content(args->random_space, buffer);
        if (result != DOCA_SUCCESS) {
            std::cerr << "fill_buffer_with_memory_content error" << std::endl;
            send_status_msg(ep, peer_addr, STATUS_FAILURE);
            goto destroy_local_buf;
        }
    }

    /* Submit DMA task into the progress engine and wait until task completion */
    result = dpu_submit_dma_task(args, &resources, host_dma_offset, buffer, local_doca_buf, remote_doca_buf,
                                 &num_remaining_tasks);
    if (result != DOCA_SUCCESS) {
        std::cerr << "dpu_submit_dma_task error" << std::endl;
        send_status_msg(ep, peer_addr, STATUS_FAILURE);
        goto destroy_local_buf;
    }

    send_status_msg(ep, peer_addr, STATUS_SUCCESS);

    destroy_local_buf:
    tmp_result = doca_buf_dec_refcount(local_doca_buf, nullptr);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_buf_dec_refcount error" << std::endl;
    }
    destroy_remote_buf:
    tmp_result = doca_buf_dec_refcount(remote_doca_buf, nullptr);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_buf_dec_refcount error" << std::endl;
    }
    destroy_remote_mmap:
    tmp_result = doca_mmap_destroy(remote_mmap);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "doca_mmap_destroy error" << std::endl;
    }
    free_buffer:
    free(buffer);
    stop_dma:
    tmp_result = request_stop_ctx(state->pe, state->ctx);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "request_stop_ctx error" << std::endl;
    }
    state->ctx = nullptr;
    destroy_dma_resources:
    tmp_result = destroy_dma_copy_resources(&resources);
    if (tmp_result != DOCA_SUCCESS) {
        std::cerr << "destroy_dma_copy_resources error" << std::endl;
    }
    if (result != DOCA_SUCCESS) {
        exit(1);
    }
}
