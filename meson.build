project(
    'smartnic-bench-cpp',
    'cpp',
    license : 'MIT',
    default_options : [
        'cpp_std=c++17'
    ]
)

dep = dependency('doca')
incdir = include_directories('/opt/mellanox/doca/include')

add_global_arguments(
    '-O4',
    '-march=native',
    language : 'cpp'
)

# doca_dma
src = [
    'src/bench_util/cmdline_args.cpp',
    'src/netbencher_core/lib.cpp',
    'src/doca_dma/bootstrap/server_construct.cpp',
    'src/doca_dma/bootstrap/mods.cpp',
    'src/doca_dma/doca_dma.cpp'
]
executable(
    'doca_dma',
    src,
    dependencies : dep,
    include_directories : incdir
)
