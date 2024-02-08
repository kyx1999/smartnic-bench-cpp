#include "mods.h"

void bootstrap_client(dma_args args) {
    doca_comm_channel_ep_t *ep = nullptr;
    doca_comm_channel_addr_t *peer_addr = nullptr;
    doca_dev *cc_dev = nullptr;
    doca_dev_rep *cc_dev_rep = nullptr;
    doca_error_t result = init_cc(false, args.pci_dev[0], args.rep_pci_dev[0], &ep, &cc_dev,
                                  &cc_dev_rep); // 目前只支持单设备地址对单设备地址
    if (result != DOCA_SUCCESS) {
        std::cerr << "init_cc error" << std::endl;
    }

    auto *runner = new bench_runner(args.threads);
    runner->run(perform_client_routine, &args, ep, &peer_addr);
    auto *inner_reporter = new simple_bench_reporter(args.client_id);
    for (size_t i = 0; i < args.life; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << runner->report(inner_reporter) << std::endl;
    }
    runner->stop();
    delete inner_reporter;
    delete runner;

    result = destroy_cc(ep, peer_addr, cc_dev, cc_dev_rep);
    if (result != DOCA_SUCCESS) {
        std::cerr << "destroy_cc error" << std::endl;
    }
}

void bootstrap_server(dma_args args) {
    doca_comm_channel_ep_t *ep = nullptr;
    doca_comm_channel_addr_t *peer_addr = nullptr;
    doca_dev *cc_dev = nullptr;
    doca_dev_rep *cc_dev_rep = nullptr;
    doca_error_t result = init_cc(true, args.pci_dev[0], args.rep_pci_dev[0], &ep, &cc_dev,
                                  &cc_dev_rep); // 目前只支持单设备地址对单设备地址
    if (result != DOCA_SUCCESS) {
        std::cerr << "init_cc error" << std::endl;
    }

    args.life = std::max(args.life, (uint32_t) MIN_SERVER_LIFE);
    auto *runner = new bench_runner(1);
    runner->run(perform_server_routine, &args, ep, &peer_addr);
    std::this_thread::sleep_for(std::chrono::seconds(args.life));
    runner->stop();
    delete runner;

    result = destroy_cc(ep, peer_addr, cc_dev, cc_dev_rep);
    if (result != DOCA_SUCCESS) {
        std::cerr << "destroy_cc error" << std::endl;
    }
}
