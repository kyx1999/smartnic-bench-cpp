#ifndef _DOCA_DMA_MODS_H_
#define _DOCA_DMA_MODS_H_

#include <chrono>

#include "../../bench_util/cmdline_args.h"
#include "../../bench_util/lib.h"
#include "../../netbencher_core/lib.h"
#include "../../netbencher_core/reporter/simple_bench_reporter.h"
#include "../core/core.h"
#include "client_construct.h"
#include "server_construct.h"

void bootstrap_client(dma_args args);

void bootstrap_server(dma_args args);

#endif
