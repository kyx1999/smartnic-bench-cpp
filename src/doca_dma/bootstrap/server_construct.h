#ifndef _DOCA_DMA_SERVER_CONSTRUCT_
#define _DOCA_DMA_SERVER_CONSTRUCT_

#include "../../bench_util/cmdline_args.h"
#include "../../netbencher_core/lib.h"

void perform_client_routine(dma_args args);

void perform_server_routine(size_t thread_id, bench_runner *runner, bench_stat *stat, dma_args args);

#endif
