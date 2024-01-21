#include "mods.h"

void bootstrap_client(dma_args args) {

}

void bootstrap_server(dma_args args) {
    if (args.life < MIN_SERVER_LIFE) {
        args.life = MIN_SERVER_LIFE;
    }

    bench_runner *runner = new bench_runner(1);
    runner->run<dma_args>(perform_server_routine, args);
    std::this_thread::sleep_for(std::chrono::seconds(args.life));
    runner->stop();
    delete runner;
}
