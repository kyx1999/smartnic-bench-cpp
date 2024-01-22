#include "bootstrap/mods.h"

int main(int argc, char *argv[]) {
    dma_args args = dma_args::parse(argc, argv);
    args.coordinate();

    if (args.server) {
        bootstrap_server(args);
    } else {
        bootstrap_client(args);
    }
}
