project(
    'smartnic-bench-cpp',
    'c',
    'cpp',
    license : 'MIT',
    default_options : [
        'cpp_std=c++17'
    ]
)

dep = dependency('doca')

incdir = include_directories('/opt/mellanox/doca/include')

add_global_arguments(
    '-O3',
    '-march=native',
    language : 'cpp'
)

# doca_dma
doca_dma_src = [
    'src/bench_util/lib.cpp',
    'src/bench_util/cmdline_args.cpp',
    'src/netbencher_core/lib.cpp',
    'src/netbencher_core/reporter/simple_bench_reporter.cpp',
    'src/doca_dma/core/pack.c',
    'src/doca_dma/core/core.cpp',
    'src/doca_dma/bootstrap/client_construct.cpp',
    'src/doca_dma/bootstrap/server_construct.cpp',
    'src/doca_dma/bootstrap/mods.cpp',
    'src/doca_dma/doca_dma.cpp'
]
executable(
    'doca_dma',
    doca_dma_src,
    dependencies : dep,
    include_directories : incdir
)
