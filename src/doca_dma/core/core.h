#ifndef _DMA_CORE_H_
#define _DMA_CORE_H_

#include <iostream>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ctime>

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <unistd.h>

#include <doca_argp.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_comm_channel.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_pe.h>

#include "../../bench_util/lib.h"
#include "pack.h"

#define CC_MAX_MSG_SIZE 4080                    /* Comm Channel message maximum size */
#define CC_MAX_QUEUE_SIZE 10       /* Max number of messages on Comm Channel queue */
#define MAX_ARG_SIZE 128                    /* PCI address and file path maximum length */
#define NUM_DMA_TASKS (1)                    /* DMA tasks number */
#define SERVER_NAME "doca_dma"                /* Comm Channel service name */ // 双方必须一致
#define SLEEP_IN_NANOS (10 * 1000) /* Sample the task every 10 microseconds  */
#define STATUS_FAILURE false       /* Unsuccessful status */
#define STATUS_SUCCESS true       /* Successful status */

/* Function to check if a given device is capable of executing some task */
typedef doca_error_t (*tasks_check)(struct doca_devinfo *);

struct cc_msg_dma_direction {
    bool host_to_dpu;
    uint64_t space_size;
};

struct cc_msg_dma_status {
    bool is_success;                    /* Indicate success or failure for last message sent */
};

/* DOCA core objects used by the samples / applications */
struct program_core_objects {
    struct doca_dev *dev;            /* doca device */
    struct doca_mmap *src_mmap;        /* doca mmap for source buffer */
    struct doca_mmap *dst_mmap;        /* doca mmap for destination buffer */
    struct doca_buf_inventory *buf_inv;    /* doca buffer inventory */
    struct doca_ctx *ctx;            /* doca context */
    struct doca_pe *pe;            /* doca progress engine */
};

struct dma_copy_resources {
    struct program_core_objects *state;            /* DOCA core objects */
    struct doca_dma *dma_ctx;                /* DOCA DMA context */
};

doca_error_t init_cc(bool is_server, const std::string &cc_dev_pci_addr, const std::string &cc_dev_rep_pci_addr,
                     struct doca_comm_channel_ep_t **ep, struct doca_dev **dev, struct doca_dev_rep **dev_rep);

doca_error_t destroy_cc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t *peer, struct doca_dev *dev,
                        struct doca_dev_rep *dev_rep);

doca_error_t open_dma_device(struct doca_dev **dev);

doca_error_t
memory_alloc_and_populate(bool is_huge_page, struct doca_mmap *dm, size_t buffer_len, uint32_t access_flags,
                          char **buffer);

doca_error_t fill_buffer_with_memory_content(size_t buffer_size, char *buffer);

#endif
