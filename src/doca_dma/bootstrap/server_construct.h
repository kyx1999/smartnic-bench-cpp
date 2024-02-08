#ifndef _DOCA_DMA_SERVER_CONSTRUCT_H_
#define _DOCA_DMA_SERVER_CONSTRUCT_H_

#include <doca_dma.h>
#include <doca_mmap.h>

#include "../../bench_util/cmdline_args.h"
#include "../../bench_util/lib.h"
#include "../../netbencher_core/lib.h"
#include "../core/core.h"
#include "../core/pack.h"

void perform_server_routine(size_t thread_id, bench_runner *runner, bench_stat *stat, dma_args *args,
                            doca_comm_channel_ep_t *ep, doca_comm_channel_addr_t **peer_addr);

#endif
