# C module: nsid

nsid_src = files([
  'nsid.c',
])
c_src_lint += nsid_src

nsid_mod = shared_module(
  'nsid',
  nsid_src,
  dependencies: [
    luajit_inc,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
