Tunnel 命令行配置与热加载

Windows程序包：build/gui/TunnelUI/TunnelCtl.exe
该控制台程序与同目录TunnelUI.exe共用默认配置目录。它不打开GUI，提供配置编辑和后台管理。
Windows源码入口：python -m tools.tunnel_cli --binary build-reload/tunnel.exe <命令>
Linux/WSL：build-wsl/gui-venv/bin/python -m tools.tunnel_cli --binary build-wsl-reload/tunnel <命令>
需安装gui/requirements.txt所列Python依赖；仅管理隧道无需安装图形桌面。
以下通用示例以 Windows 源码入口为例，在仓库根目录执行；Linux/WSL 使用上一行的完整入口，并保留其后的子命令。
2026-10-19 内核设备后端本轮未重新打包 Windows GUI/CLI；现有成品保留 10-16 的 TCP 封装版本，不含新的后端选项。
本轮请显式指定 --binary；源码默认路径及旧 build/、build-wsl/ 产物保留供既有手工测试使用。
全局选项--binary、--config-dir放在子命令前。Windows创建TUN需要管理员，Linux需要root/CAP_NET_ADMIN。

创建和连接

    python -m tools.tunnel_cli --binary build-reload/tunnel.exe init --address 192.0.2.10:65535 --network 10.1.0.1/24
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe peer add 192.0.2.20:65535
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe start
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe status
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe stop

192.0.2.*为示例，必须替换成实际可达地址。peer add会提示输入PSK；也可用--key-file private-key.txt，从文件读取，避免将密钥写入命令历史。
多网络时添加peer须重复指定--network 10.1.0.0/24，明确授权范围；对端配置相同peer PSK。
peer add默认使用UDP数据封装；需要TCP时加--transport tcp，例如：
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe peer add 192.0.2.30:65535 --transport tcp
双方均支持TCP且任一端选择tcp时，数据与控制共用已认证的TLS连接；UDP受限时可使用，但丢包重传可能阻塞后续数据。
选择tcp后对端不支持会报错，不会回退；UDP连接失败也不会自动切换TCP。status的peers[].transport显示实际协商封装。
从现有完整配置启动：
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe start --config node.json
停止控制台命令不会停止后台；使用stop显式停止。关闭GUI仍遵守原有的无人值守后台策略。

运行时编辑

    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config show
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config show --running
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config check node.json
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config apply node.json
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config set /tun_mtu 1300
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config set /listen/enabled false
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config set /address 192.0.2.11:65535 --string
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config set /peers/0/transport tcp --string
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config unset /tun_mtu
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe peer remove 192.0.2.20:65535
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe network add 10.2.0.1/24
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe config reload

On Linux/WSL the default backend is the kernel device; follow [development.md](development.md) to build and load the module, or explicitly select TUN.
    build-wsl/gui-venv/bin/python -m tools.tunnel_cli --binary build-wsl-reload/tunnel config set /device_backend kernel --string
    build-wsl/gui-venv/bin/python -m tools.tunnel_cli --binary build-wsl-reload/tunnel config set /device_backend tun --string
    build-wsl/gui-venv/bin/python -m tools.tunnel_cli --binary build-wsl-reload/tunnel config unset /device_backend
省略字段时 Linux 选择 kernel，Windows/macOS/Android 选择 tun；config unset 后核心归一化仍会写出该平台的有效值。
显式 tun/kernel 在规范化和保存时都会保留；Linux 缺少模块时明确报错，不会自动回退到 TUN。

config set使用JSON Pointer路径，VALUE默认为JSON；字符串可加--string，数组可用/peers/0/address之类路径。
config show默认隐藏所有shared_key；明确加--show-secrets才输出完整密钥，避免分享其输出。
config apply加载整份文件，config reload重新加载当前profile/configure.json。编辑命令都会校验、保存，并在后台运行时即时应用；未启动时仅保存。
network add保留现有peer及监听的网络授权，不自动扩大已有peer权限。移除网络前应先调整引用它的peer、监听、发布和远控配置；有悬空引用时校验拒绝保存。
需要一次修改多个相关字段时，准备完整JSON后用config apply，避免中间状态无效。
GUI和命令行同时编辑同一配置时使用文件锁及SHA256版本检查；冲突会拒绝覆盖，重新读取后再修改。

指定独立配置目录

    python -m tools.tunnel_cli --binary build-reload/tunnel.exe --config-dir ./my-profile start --config node.json
    python -m tools.tunnel_cli --binary build-reload/tunnel.exe --config-dir ./my-profile config set /tun_mtu 1300
    python gui/main.py --binary build-reload/tunnel.exe --config-dir ./my-profile

必须使用相同目录才能管理同一个后台。运行快照位于该目录background/configure.json；请编辑profile根目录configure.json，勿直接修改运行快照。
原有后台升级为新版本需要首次停止并重新启动；之后可以运行时应用配置。遇到旧后台不认识apply_config时会报错，不静默重启或假报成功。
本轮单独构建的最新核心在build-reload/tunnel.exe和build-wsl-reload/tunnel；以上源码命令均显式选择它们。
Windows程序包和此前手工测试使用的旧核心未替换；旧后台仍需显式停止后用新入口重启，才会运行新版本。

生效范围

- noop：配置未变化，不打断连接。
- remote：仅远控策略变化；网络连接保留，旧远控授权会话按策略关闭。
- peers：新增/删除peer，或修改其PSK/网段授权/数据封装，只重建受影响邻接；未修改邻接与有效端到端会话保留。
- rebuild：设备后端device_backend、公布/监听地址、网络/IP、MTU、地址分配服务、发布网段/SNAT等变更，在相同核心进程内重建网络资源，保留身份密钥，但连接会重新建立。

同一运行中地址分配服务修改公布端点且继续使用同一state_file时，会更新租约文件的服务端点并保留原绑定。
客户端仍需修改对应服务地址后重连。普通启动不会自动接管另一个服务端点的状态文件。

成功应用表示本机配置和资源已接受，邻接仍需正常认证；不会承诺对端立即可达。
校验失败不改变运行状态。资源创建失败会尝试恢复旧配置；若旧资源也无法恢复，会明确报错并显示不可用，可再次应用配置或停止后重启。
持久化失败会恢复旧运行配置；恢复失败也会明确报告。配置提交不因普通请求计时器假报失败，后台存活状态仍可查询。

直接运行原生核心

    .\build-reload\tunnel.exe node.json --watch-config --status-file status.json
    ./build-wsl-reload/tunnel node.json --watch-config --status-file status.json
    sudo ./build-wsl-reload/tunnel node.json --device-backend kernel --watch-config

--device-backend tun|kernel 是原生核心选项，覆盖 JSON 的 device_backend，并持续用于同一进程的 watch/SIGHUP/config_apply 重载。
Linux 默认 kernel；要沿用用户态 TUN，请明确加 --device-backend tun。Linux 使用 --tun-fd 时也必须明确选择 tun。
需要通过界面或配置热切换后端时，将选择写入 JSON，并省略原生核心的 --device-backend 覆盖选项。

每秒检查文件内容，推荐通过临时文件加原子替换来保存。无效JSON/无效配置不会替换正在运行的配置，修正后重新加载。
Linux/macOS独立核心也支持kill -HUP <核心PID>，不需要开启文件监视。Windows使用--watch-config。
直接启动的核心不由TunnelCtl后台管理；上述GUI/CLI后台管理与独立核心监视是两种启动方式，不要针对同一节点重复启动。
--stdio-control由宿主拥有配置，不能与--watch-config同时启用；宿主经认证本机IPC提交配置。
继承外部--tun-fd且没有设备重建回调时，仅允许不需要重建TUN的热变更。Android宿主提供该回调。
