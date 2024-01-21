#ifndef _DOCA_DMA_MODS_
#define _DOCA_DMA_MODS_

#include <chrono>

#include "../../bench_util/cmdline_args.h"
#include "../../bench_util/lib.h"
#include "../../netbencher_core/lib.h"
#include "server_construct.h"

void bootstrap_client(dma_args args);

void bootstrap_server(dma_args args);

#endif
