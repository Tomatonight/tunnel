当前实现与运行

程序已能创建 TUN、建立认证连接、同步节点可达信息并转发 IP 数据。
TUN 后端的协议核心是单线程 libevent 循环；每个进程一个 UDP socket，一个 TUN，可配置多个不重叠虚拟网络。
Linux 默认选择自定义内核设备；Windows/macOS/Android 默认 TUN。Linux 的控制面和 TCP/TLS 通道保留用户态。

已完成：
- TCP控制连接、TLS 1.3每peer PSK认证、Hello网络授权及所选数据通道的双向活性探测。
- 每peer可选UDP或TCP数据封装；TCP复用TLS控制连接，支持混合中转及热切换。
- 路径通告/撤回、完整路径防环、按跳数 ECMP、单播按流选路、邻接失效自动重连。
- 单播端到端TLS握手及AES-256-GCM数据保护；相邻数据链路另加逐跳AEAD。
- 广播/组播采用唯一 RPF 上游、逐跳加密和 hop_limit=32；只在共同加入的网络中转发。
- 公钥随可达信息传播；仍有替代路径时保留公钥和端到端会话，完全失联或换钥后重新握手。
- 单 TUN 多地址、IPv4/IPv6、静态 MTU 校验、状态文件、正常退出和设备清理。
- Linux /dev/net/tun、Windows Wintun、macOS utun、Android VpnService/JNI 后端与宿主工程。
- 四平台共用的配置、连接状态和日志界面；桌面 pywebview 窗口、Android WebView/VpnService。
- 可选公网地址分配服务、多 IPv4/IPv6 地址池、单一共享 PSK（兼容逐节点授权）、持久绑定与离线回收。
- TUN 动态增删地址、签名分配凭据和按网段启停；服务失联保留其他网段的 peer 与会话。
- 内网前缀通告/撤回、单主出口与备用出口、可选系统 SNAT、导入系统路由和请求回包检查。
- 独立远程桌面后台、长期设备身份、名单/全部同网节点两种模式、预授权无人值守和实时撤销。
- Windows/Linux X11/macOS 采集输入后端，共享界面的配对、JPEG画面、键鼠、只读权限及后台重连。

Linux/WSL 和 Windows 已完成真实 TUN 互通测试。macOS 后端及 Android 工程尚未在目标平台编译/实机验证。
不包含 NAT 穿透、默认路由接管、动态 PMTU、隧道分片重组、MSS 改写、TAP 或组播成员订阅。
内网访问由桌面发布出口，Android 作为访问端；仅允许隧道节点主动访问，内网通过已有连接回包。
SNAT 可选；关闭时内网仍需正确的回程路径。平台能力边界和访问范围见下文及设计design.md。

远程桌面运行在已登录用户的图形会话；Windows屏幕采集和Linux X11端到端键鼠已有实际验证。
macOS后端已编写但未实机测试；Wayland、登录/安全桌面及Android远控不在当前支持范围。
通过GUI或remote_desktop.daemon启动屏幕服务；直接运行C++核心只创建隧道，不创建屏幕组件。
配对、全员模式、长期身份和后台运行说明见 remote_desktop/README.md；示例见 examples/desktop-host.json、desktop-client.json。

Linux 可选内核设备

2026-10-20 本轮已编译核心：Linux 为 build-wsl-reload/tunnel，Windows 为 build-reload/tunnel.exe。
当前 WSL 的匹配模块及来源哈希在 build/kernel/6.18.40.1-microsoft-standard-WSL2/。
build/kernel/6.8.0-147-generic/ 和 build/kernel/7.0.0-38-generic/ 保留此前对应 Ubuntu 内核的产物与哈希。
旧 build/tunnel.exe、build-wsl/tunnel 和 Windows GUI 成品未在本轮替换；源码 GUI/CLI 需用 --binary 显式选择上述新核心。
device_backend 省略时，Linux 默认 kernel（需加载模块），其他平台包括 Android 默认 tun。也可明确选择：
    "device_backend": "kernel"
Linux 不使用内核模块时必须明确设置 "device_backend": "tun"；缺少模块会报错，不会自动回退。
核心归一化/保存始终写出有效的 tun/kernel，包括显式 tun，保持配置跨平台复制后的选择。
或通过原始核心命令行选择（整个进程及后续热加载持续覆盖配置文件的同名字段）：
    sudo ./build-wsl-reload/tunnel config/default.json --device-backend kernel
    sudo ./build-wsl-reload/tunnel config/default.json --device-backend tun
配置校验和归一化只校验字段；不会加载模块或声称当前主机能够运行该后端。
仅 address_server 的配置不创建设备，device_backend 对其没有作用。
Linux 继承外部 TUN fd 时须同时传入 --device-backend tun，例如 --device-backend tun --tun-fd 7；默认 kernel 不接受 TUN fd。

使用与正在运行的内核匹配的开发头文件和构建目录，先编译并加载模块：
    python3 tools/build_kernel.py
    sudo install -D -m 644 build/kernel/tunnel_kmod.ko /lib/modules/$(uname -r)/extra/tunnel_kmod.ko
    sudo depmod -a
    sudo modprobe tunnel_kmod
构建脚本仅保留模块及构建信息，临时编译文件自动清理；--headers 可指定另一套配置完整的目标内核头文件。
modprobe 会加载所需的 UDP tunnel 等依赖。详细 ABI、容量和生命周期说明见 kernel/README.md。
模块不是跨版本通用二进制；换内核后重新构建。Secure Boot/模块签名遵循宿主系统设置。

当前 WSL 6.18.40.1-microsoft-standard-WSL2 已准备匹配开发树、安装模块并通过完整实际运行测试；未替换内核、重启 WSL 或修改启动配置。
主链路 15/15、ABI 9/9、外层 IPv6/RPF 3/3、子网/NAT 10/10 通过，真实模块 BTF 注册通过；原宿主网络和远控进程保持不变。
The final report is under build/kernel/tests/wsl-6.18.40.1-final/; initial BTF differences and fixes are recorded in [test-results.md](test-results.md).
测试后已重新加载最终模块，/dev/tunnel_kmod 可用；运行核验在模块产物目录的 runtime-ready.json。
标准安装位置为 /lib/modules/6.18.40.1-microsoft-standard-WSL2/extra/tunnel_kmod.ko；启动节点前执行 sudo modprobe tunnel_kmod。
持久副本为 /usr/local/lib/tunnel/6.18.40.1-microsoft-standard-WSL2/tunnel_kmod.ko。
WSL 的 /lib/modules 使用覆盖层；重启后若安装文件丢失，可按当前版本从持久副本恢复：
    sudo install -D -m 644 /usr/local/lib/tunnel/$(uname -r)/tunnel_kmod.ko /lib/modules/$(uname -r)/extra/tunnel_kmod.ko
    sudo depmod -a
    sudo modprobe tunnel_kmod
重新编译当前 WSL 模块时，在项目根目录的 Bash 子 shell 中加载专用工具链，避免影响后续程序运行环境：
    (
        source /home/tunnel-wsl-build/environment.sh
        python3 tools/build_kernel.py --headers /usr/src/tunnel-wsl-6.18.40.1-microsoft-standard-WSL2 --cc "$CC" --btf-base /sys/kernel/btf/vmlinux --output build/kernel/6.18.40.1-microsoft-standard-WSL2
    )
/usr/src/tunnel-wsl-6.18.40.1-microsoft-standard-WSL2 指向保留的匹配源码与构建树；详情见 kernel/README.md。
上述 --btf-base 使用当前运行内核的真实 BTF，解决本地重建 vmlinux 的调试类型编号与官方内核不同的问题；
仅适用于构建目标就是当前运行内核的情况，不能将该路径用于其他版本内核。工具校验重新生成 BTF 前后代码、数据段和导入符号 CRC 均未改变。
新模块构建后需重新安装并更新持久副本；已有节点使用模块时，应先正常停止这些节点再卸载、加载新模块。

Windows/macOS/Android 继续使用原后端；选择 kernel 会明确失败，不会自动回退。
GUI 的“高级设置 → 隧道设备”也可选择后端；修改运行中配置会重建设备和连接，使用原有热加载回滚机制。
UDP 数据通过内核 net_device 发送、接收、加解密和转发；TCP 数据仍通过用户态的已认证 TLS 连接。
用户态每实例独占 /dev/tunnel_kmod 控制 fd；ioctl 发布状态快照、密钥和保活，read/write 交换事件与 TCP 密文。
关闭 fd 释放对应网卡、UDP socket 和内核密钥；模块控制 ABI 不是网络协议，不对公网开放。
路由、密钥或发送资源不可用时直接丢包并计数；当前使用同步 Kernel Crypto API，不等待异步密码队列，不新增隧道层重传。
内核 API 尽量做版本适配，实际支持的内核版本以本次编译/运行测试记录为准。

TCP数据封装

在对应peer对象加入"transport":"tcp"；省略或"udp"保持默认UDP数据封装。
两端都需要支持TCP封装；任一端选择TCP即通过已认证Hello协商使用TCP，不自动回退UDP。
复用同一个address上的TLS连接，不增加数据端口。UDP受阻时可使用TCP；TCP模式不以UDP探测决定存活。
TCP控制及所选数据通道仍每5秒保活，任一20秒没有合法活动/探测回应即撤回邻接。
界面的peer卡片可选数据封装，状态显示协商结果；CLI可用peer add <地址> --transport tcp，
或config set /peers/0/transport tcp --string。运行时修改只重连受影响邻接。
单播端到端加密、广播组播RPF、ECMP与网络权限不变；TCP/UDP混合中转沿用当前MTU限制。
TCP批量输出限流为有界整包丢弃，保留控制消息空间。内层TCP叠加TCP可能增加队头阻塞及重传开销。
配对示例：examples/tcp-node-a.json和examples/tcp-node-b.json，先替换公布地址与共享密钥。

图形界面

Windows 可运行 build/gui/TunnelUI/TunnelUI.exe，保留同目录的 _internal、核心及所有 DLL。
首次载入示例配置；连接前应填写本机公布地址、虚拟 IP/前缀、对端地址和双方一致的 PSK。
配置默认使用表单；本机虚拟地址只写一次，多网络通过勾选限制对端权限，PSK 支持生成/显示/复制。
入站、绑定、MTU 和 JSON 编辑放在高级设置；JSON 修改须先应用到表单。
界面还包含配置导入/校验/保存、连接/断开、邻居状态、ECMP 路径、计数和日志筛选/复制。
桌面开启远控且无人值守时关窗保留后台，重新打开相同配置目录可接回；其他情况关窗停止核心。
显式断开始终停止后台和核心。Android 关闭 Activity 后 VPN 继续运行，使用断开按钮停止。
用户态核心仍为单线程；TUN 后端的 UDP socket 属于用户态，kernel 后端的唯一 UDP socket 属于内核。
内核数据处理可发生在不同 CPU 上，会话状态由实例锁保护；界面和日志读取属于独立宿主线程/进程。
共享资源离线加载，不开放本地HTTP端口；Python宿主经认证的环回IPC连接后台，令牌不传给页面。
保存配置先通过原生核心校验，运行时立即应用。Peer差异只重建受影响邻接，其余网络资源变动在原进程内重建并重新连接，身份密钥保留。
配置无变化不打断连接；校验失败保留原状态，应用失败尝试恢复原资源，恢复失败明确返回错误。GUI和命令行共用配置目录锁、版本检查及保存失败回滚。
The headless configuration tool is documented in [cli.md](cli.md); the Windows package includes TunnelCtl.exe and the source entry point is python -m tools.tunnel_cli.
源码启动、平台依赖、打包与配置目录见 gui/README.md；Android 构建见 android/README.md。

构建

依赖 C++11、CMake、libevent core、OpenSSL 3.x 的 SSL/Crypto。
Linux / WSL 安装：
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends build-essential cmake ninja-build libssl-dev libevent-dev iproute2 iputils-ping nftables

    cmake -S . -B build-wsl -G Ninja -DCMAKE_BUILD_TYPE=Debug
    cmake --build build-wsl --parallel 2
    ctest --test-dir build-wsl --output-on-failure
    ./build-wsl/tunnel --check config/default.json

本机 Windows 已配置 Zig 0.14.1、libevent/OpenSSL 动态库，可直接执行：
    .\.build-tools\cmake\data\bin\cmake.exe --build build --parallel 2
    .\.build-tools\cmake\data\bin\ctest.exe --test-dir build --output-on-failure
    .\build\tunnel.exe --check .\config/default.json

新环境使用 CMAKE_PREFIX_PATH / OPENSSL_ROOT_DIR 指定与编译器 ABI 相符的依赖。
本机 DLL 包括 libcrypto-3-x64.dll、libssl-3-x64.dll、libevent_core-7.dll、libwinpthread-1.dll。
Windows 真正运行还需管理员权限以及位于 tunnel.exe 同目录的官方、架构匹配的 wintun.dll。
本地已放入 Wintun 0.14.1 AMD64 DLL；官方 ZIP SHA256 与 Authenticode 签名均已核验。
官方来源 https://www.wintun.net/ ，再分发时须保留所用依赖的许可证。
.build-tools、.deps 和 build* 是本地构建产物；各平台不能共用 CMake 缓存或二进制。

运行

    tunnel [config/default.json] [--check | --normalize-config] [--tun-name NAME]
           [--tun-fd FD] [--status-file PATH] [--run-for SECONDS] [--stdio-control] [--watch-config]
    tunnel --generate-key
    tunnel server.json --export-client NODE_ADDRESS

    sudo ./build-wsl/tunnel node-a.json --tun-name overlay0 --status-file /tmp/tunnel-status.json
    .\build\tunnel.exe node-a.json --tun-name MyTunnel --status-file .\status.json

--check 只校验配置，不创建 TUN，不需要管理员权限。
--normalize-config 校验并向 stdout 输出新格式 JSON（含配置中的 PSK），不改原文件、不启动隧道。
--generate-key 使用 OpenSSL 生成 32 字节随机 PSK，输出为 64 位十六进制文本。
peer 双方使用同一把 peer 密钥；共享分配模式下服务及其客户端使用同一把服务密钥。
--export-client 从服务配置导出接入配置（含 PSK），不启动服务或修改租约。
共享模式可填写任意合法节点公布地址；旧 clients 模式只能导出已授权节点。
Linux 创建接口需要 root/CAP_NET_ADMIN 和 iproute2；Windows 需要管理员权限。
Linux/Windows 的接口名必须尚未存在；默认自动选名，不接管已有网卡。
macOS 自动创建可用 utun，不接受 --tun-name；需要能配置系统接口及路由的权限。
--tun-fd 适用于已经配置好地址、路由和 MTU 的 POSIX 原始 IP TUN fd，传入后所有权转给程序。
CLI --tun-fd 没有动态配置宿主回调，仅适合静态网络；受管网络由程序创建 TUN，或使用 Android JNI 的设备更新回调。
--run-for 是自动正常退出的秒数（最多一天）；未指定则持续运行，Ctrl+C/SIGTERM 正常退出。
--stdio-control 用于界面宿主，要求管道 stdin；收到 STOP 换行、stop 换行或 EOF 正常停止。
同一管道支持有限JSON RPC remote_info/remote_sign/remote_verify/config_get/config_apply，返回TUNNEL_RPC前缀行；响应不写入日志。
config_apply通过私有候选文件path传递完整配置（最多1 MiB），避免大配置阻塞16 KiB控制消息；config_get仅供认证宿主使用，结果含PSK。
--watch-config每秒检测配置内容变化，在协议线程应用；无效内容只记录错误，修正文件后继续加载。Linux/macOS也可发送SIGHUP强制重载。
--watch-config不能与--stdio-control同时使用；由GUI/CLI后台管理的核心必须经本机配置接口应用，保持核心、远控策略和运行快照一致。
--tun-fd没有重新创建宿主设备的工厂，仍可热改peer/远控策略，但需要重建TUN的变更会返回device_factory_required；Android提供完整设备重建回调。
不指定该参数则不读取 stdin；控制读取仍在唯一事件循环中进行。
状态 JSON 每 250 毫秒更新，含 peers、routes、end_sessions 和丢包/转发计数，不输出 PSK 或私钥。
监控文件写入失败会记录并在下次更新重试，不中断网络转发。

config/default.json 使用演示公网地址和占位 PSK，实际互通须改成两端真实可达的固定公布地址，
并在双方 peers 中相互配置一致的 shared_key，以及本机各自的虚拟地址和共同网络。
顶层 address 是本机身份；peers[].address 是对端地址；顶层 networks 是本机虚拟 IP/前缀。
例如 "networks": ["10.1.0.2/24"] 同时表示本机地址 10.1.0.2 和网段 10.1.0.0/24。
单网络时 peer 可省略 networks；多网络必须显式选择已有子网，如 "networks": ["10.1.0.0/24"]。
增加第二个网络不会自动扩大已有 peer 权限；空 peer 网络列表、未知子网或带主机位的引用报错。
peers 可省略为 []；listen 可省略，默认开启入站并使用全部本机网络作为监听上限。
listen.bind_address 可省略，默认同地址族通配地址及公布端口；TCP 和 UDP 都必须能到达。
公布地址与绑定地址分开支持静态端口映射，但不动态学习 NAT 后地址或端口。
关闭 listen.enabled 仍可主动拨号；入站仅接受配置过的 peer，且网络须同时获 peers 与 listen.networks 授权。
listen.networks 是被动接收连接的额外限制，不影响主动连接；[] 表示不允许任何监听网络。
旧配置继续可读；导入时统一转换并保留原有权限，读取不改磁盘，保存或连接时写入新格式。
不允许混用新顶层 address/networks 和旧 listen.address/重复的网络对象。
每个进程只选择 IPv4 或 IPv6 外层；虚拟网络可同时包含 IPv4 和 IPv6。

tun_mtu 默认 1280，transport_mtu 默认 1500，后者由部署者保证覆盖所有可能路径。
单播封装增加 166 字节，再加 IPv4/UDP 28 字节或 IPv6/UDP 48 字节。
因此外层 MTU 1500 时 TUN 最大分别为 1306 / 1286；有内层 IPv6 时 TUN MTU 至少 1280。
超长包丢弃并计数。不会自动探测或修改 MTU。
配置最多 1 MiB、16 层 JSON、256 个 peer、合计 64 个不同虚拟网络；旧 thread_num 只接受 1。

内网路由分发

发布者示例 examples/subnet-gateway.json；访问端示例 examples/subnet-client.json。
将示例公布地址、peer PSK 和网段改为实际值；发布者必须能经物理接口访问所发布的内网。
发布者顶层添加：
    "advertise_routes": [
      { "tunnel": "10.1.0.0/16", "prefix": "10.2.0.0/16", "snat": true }
    ]
tunnel 引用已加入的规范虚拟网段，prefix 为本机可达的规范内网网段；snat 默认 false。
访问端自动学习并添加系统路由，无需复制 advertise_routes。界面可添加发布网段、选择 tunnel 和 SNAT，
连接状态显示导入前缀、当前出口、发布是否生效及错误原因。Android 隐藏新增出口功能，仍可删除配置中原有出口项。
    ./build-wsl/tunnel examples/subnet-gateway.json --check
    sudo ./build-wsl/tunnel examples/subnet-gateway.json

启用 SNAT 后内网看到出口的内网 IP；关闭时保留访问节点的虚拟 IP，内网网关必须配置回程路由。
Linux 用 MASQUERADE，源地址随实际出接口由内核选择；暂不支持指定某个 SNAT 源 IP。
同一发布前缀应走同一物理出口，规则绑定准备时探测到的接口；宿主出口路由改变后断开重连刷新。
当前支持 TCP、UDP、ICMP/ICMPv6 Echo 及相关 ICMP 错误，不支持内网设备主动建立新连接或内网之间互访。
端到端加密终止于发布者；到内网的一段使用普通 IP。各跳仍保留原有身份校验、AEAD 和 hop_limit。
同一前缀多个发布者按最短跳数再按节点地址选择一个出口，其他备用；到同一出口仍可 ECMP。
已有流尽量保持出口，出口故障不迁移内核 NAT 状态，旧连接可能中断；新流使用备用出口。
相互重叠的不同前缀/不同 tunnel 前缀不安装，已有物理网络、非默认系统路由和传输端点也受到保护。
只有系统后端准备成功才发布可用出口；受管 tunnel 资格撤销同步撤回其出口和导入路由，其他 tunnel 保持。

Linux 依赖 iproute2、nftables 和 root/CAP_NET_ADMIN，规则放入私有 nft table。
已有宿主防火墙若拒绝转发，仍需管理员按原策略放行；程序不会清空或覆盖既有规则。
旧内核没有 IPv6 force_forwarding 时，IPv6 出口要求预先启用全局 IPv6 forwarding；错误会在状态和日志中显示。
Windows 需管理员、IP Helper 和 WinNAT；SNAT 仅 IPv4，一个内部 tunnel 前缀，拒绝已有其他 WinNAT 实例，
同一 tunnel 不能混合启用和关闭 SNAT 的发布。Windows 未在本轮进行真实 WinNAT 出口互通验证。
macOS 需 route/sysctl/PF；SNAT 仅在现有 PF 主规则引用 com.apple/* nat-anchor 时加载自己的 anchor，不替换主规则。
Android 是访问端，通过 VpnService 重建导入路由；Windows/Android 导入内网时同一地址族仅支持一个活动 tunnel 地址。
Linux/macOS 分别使用路由 src/-ifa 指定来源。macOS/Android 本轮仍未在目标平台构建和实机测试。
不要让多个出口进程在同一主机/命名空间共享同一物理接口并同时管理转发开关。
正常断开会恢复自有规则/转发设置；强制杀进程或崩溃后可能需手工清理残留的 tunnel_<pid>_<编号> 规则。
只撤回部分发布时立即删除其规则，曾用出接口的转发开关保留到全部出口撤回或正常停止时恢复。
请求/回包授权每 tunnel 上限1024项，TCP/UDP/Echo空闲超时7200/120/30秒；达到上限拒绝新流并计数。
状态 JSON 增加 subnet_routes 和 local_exports；NAT/路由安装错误不会导致整个节点退出。

可选 IP 分配

服务示例：examples/address-server.json；客户端示例：examples/address-client.json。
先把示例的公布地址改成真实可达地址，生成一把随机 PSK，填入 server 的 shared_key 和各客户端对应 shared_key。
服务端示例只需公布地址、shared_key 和地址池，不用逐个登记客户端。
    ./build-wsl/tunnel examples/address-server.json --check
    ./build-wsl/tunnel examples/address-server.json --status-file server-status.json
    ./build-wsl/tunnel examples/address-server.json --export-client 192.0.2.1:65535
仅 address_server 的配置运行独立 TCP 服务，不使用 TUN/UDP，也不需要创建网卡的权限。
普通节点配置也可同时包含 address_server；服务监听端点需与 overlay TCP 监听分开。
本机静态网络不能与内嵌服务的地址池重叠；需要加入自己的池时，也通过 address_clients 向自己申请。
address_server.networks 是独立子网地址池；shared_key 模式下所有认证通过的节点可申请其中任意池。
address_clients.networks 决定本次申请哪些池，不会自动申请服务端后来新增的池。
旧 clients 模式仍可配置每节点身份、独立 PSK 和允许申请的子网，保留逐节点撤销与网络授权。
shared_key 和 clients 必须二选一；旧配置导入、校验和保存保持原模式，不会自动扩大授权。
address_clients 配置服务地址、对应 PSK 与申请的网段；本机静态 networks 可省略或保留其他不重叠网段。
peer 授权列表可引用静态及受管网段；未取得有效分配时不会给该网段配置占位 IP 或发布路径。
服务分配权限和原有 peer 通信权限分开管理；导入接入配置后仍需配置要连接的 peer。
共享接入密钥只能证明属于持钥组，不能阻止成员冒充其他节点或服务端；适用于互信节点。
不能只撤销一个成员而继续使用同一共享密钥。更强身份管理可选择旧逐节点模式，或后续采用证书/注册机制。
每个受管网段的两端必须使用同一服务，并验证对方的有效分配凭据；不能与手动模式混接该网段。

reclaim_after 为确认离线后的回收等待秒数，默认86400；回收还须等待最后签发的60秒凭据失效加5秒保护期。
server 采用5秒保活/刷新、20秒活动超时；明确TCP关闭立即失效。服务重连后重新验证地址才能恢复网络。
state_file 默认 address-leases.json，命令行相对配置文件目录；界面运行时定位到持久私有配置目录。
文件保存失败、损坏或被另一服务锁定时停止分配；不要删除/复制正在使用的状态库来启动另一个相同服务。
共享模式不维护手写授权名单，但仍保存租约表；服务最多同时接受256个已认证客户端和64个待认证连接。
节点离线后回收，再上线时若原地址已被占用将重新分配；池耗尽会逐池报告，其他池继续工作。
分配凭据带到期时间，服务与客户端需保持系统时钟同步；发生明显时钟差异时拒绝使用凭据。
某个网段失去分配资格只撤回该网段的地址、路径和会话；其他网段继续使用同一 peer 通道。
状态 JSON 新增 networks、address_service、address_errors 和 device_error，界面区分服务连接和地址实际可用状态。
若系统接口更新失败导致设备不可用，会停用所有 overlay 网段并显示需重连，避免继续发布不可用路径。
Android 地址变化通过 VpnService 重建接口并在同一协议线程替换 fd；Node、TCP/UDP 会话保留。

代码入口

main.cpp：CLI、信号、状态文件与运行周期。
node.cpp：相邻连接、可达信息同步、端到端会话和转发流程。
address_service.cpp：TLS 地址服务/客户端、签名凭据、地址池、持久租约和失联回收。
tls.cpp：TLS 1.3 外部 PSK、身份公钥精确校验、TLS exporter。
wire.cpp：控制消息帧和路径消息；protocol.cpp：UDP 转发头。
crypto.cpp：Ed25519、HKDF、AES-GCM、方向隔离和防重放。
gossip.cpp：按来源保存候选路径、ECMP、RPF、撤回和公钥选择。
tcp_transport.cpp / udp_transport.cpp：有界非阻塞传输。
device.cpp：平台设备创建、地址/MTU 配置和 IP 包读写。
subnet_platform.cpp：导入路由、各平台内核 NAT、转发设置与正常退出恢复。
return_flows.cpp：内网请求和允许回包对应关系，不进行 NAT 地址/端口转换。
gui/：共享页面、桌面宿主和 Windows 打包脚本；见 gui/README.md。
remote_desktop/：独立后台、OpenSSL TLS协议、持久设备授权、核心成员证明桥与原生采集/输入后端。
android/：VpnService、WebView 界面宿主、JNI 与 Gradle 工程；见 android/README.md。

默认运行参数

TCP/UDP 保活 5 秒；任一通道 20 秒未验证活动即撤回邻接；初始握手 10 秒超时。
重连退避 1/2/4/8 秒；每小时更新会话，进程身份密钥不变。进程重启才生成新身份密钥。
控制帧最大 64 KiB，TLS 缓冲 256 KiB，TCP 发送队列 1 MiB；UDP/Posix TUN 队列各最多 256 包。
最多 8192 条来源路径记录、256 个端到端会话，每个待握手会话最多缓存 64 个 IP 包。
端到端握手因路径收敛或中转切换而无进展时，以新会话 ID 重试，保留待发包但不延长总握手超时。
Windows Wintun 用同一协议线程每 2 毫秒最多读取 64 包，不额外创建协议 worker。
组播没有跨路径严格去重保证，路由切换时可能短暂重复/丢包；稳定拓扑按唯一 RPF 上游投递。

测试

普通 CTest 无需 TUN 权限：
    ctest --test-dir build-wsl --output-on-failure
    .\.build-tools\cmake\data\bin\ctest.exe --test-dir build --output-on-failure

tunnel_core 覆盖配置、MTU、AEAD 篡改和重放、方向隔离、路径撤回、ECMP/RPF 与 UDP。
runtime 使用实际 TCP/UDP 和内存设备建立四节点菱形拓扑，覆盖认证、端到端传输、
双路径转发、IPv4/IPv6、组播、故障切换、重启换钥、IPv6 外层、错误 PSK 和关闭入站监听。
config_check 校验仓库示例。
address_service 覆盖 TLS/PSK、逐池授权、独立地址池、签名凭据、租约落盘与损坏拒绝、重启和回收。
managed_node 覆盖同一 peer 的静态/受管网络混合、双栈数据、资格撤销、错误服务与模式不匹配。
device_addresses 覆盖宿主设备 fd 更新；真实动态地址检查另行执行：
    sudo ./build-wsl/device_address_tests --live
    .\build\device_address_tests.exe --live
定时换会话、宿主持有的进程身份、POSIX 继承 TUN fd 的读写/释放也有回归覆盖。
Platform check counts and raw result paths are listed in [test-results.md](test-results.md).

真实 Linux 网络测试（root）：
    sudo python3 tests/network_integration.py --binary build-wsl/tunnel

内网路由与内核 NAT 测试（独立网络命名空间，root）：
    sudo python3 tests/subnet_network_integration.py --binary build-wsl/tunnel
覆盖多跳、双出口主备、真实 TCP/UDP/ICMP、LAN 看到的源地址、新建连接拦截、全撤回和规则恢复，
以及关闭 SNAT 的回程路由、IPv6纯路由和IPv6 SNAT实际源地址。结果位于 build-wsl/subnet-network-tests/results.json。
CTest subnet 另覆盖配置/wire兼容、前缀冲突、主备/ECMP、回包元组、ICMP关联错误和分片；
runtime 和 managed_node 覆盖端到端数据及受管资格生命周期。

远程桌面测试（先安装 python -m pip install -r gui/requirements.txt）：
    python tests/remote_runtime_test.py
    python tests/remote_race_test.py
    python tests/remote_bridge_test.py
    python tests/remote_platform_test.py
    python tests/remote_stdio_test.py --binary build/tunnel.exe
CTest新增remote_control，覆盖可信成员签验、新旧配置、RPC边界、撤回与换钥。
CTest的tcp_data覆盖TCP二进制帧、UDP不可达、混合中转、保活失效、按peer热切换、错误PSK及有界队列；
tcp_legacy用真实TLS模拟旧版Hello，验证默认UDP兼容、TCP不支持时拒绝，以及未协商二进制帧拒绝。
TCP真实设备测试：
    sudo python3 tests/tcp_network_integration.py --binary build-wsl-reload/tunnel --work build-wsl-reload/tcp-network-tests
    python tests/windows_wsl_integration.py --transport tcp --windows-binary build-reload/tunnel.exe --linux-binary build-wsl-reload/tunnel --work build/windows-wsl-tcp-tests
前者只在新建网络命名空间内阻断外层UDP，验证TCP/UDP混合三节点双栈、内层TCP/UDP/ICMP、MTU、保活和SIGHUP切换，退出清理。
后者需要Windows管理员权限及WSL，使用独立Wintun/TUN和10.253.248.0/30，不改宿主防火墙。
runtime测试使用真实TLS和合成桌面，不操作当前用户键鼠；race测试用受控线程屏障验证撤权/关闭竞态。
Linux实际TUN、Xvfb桌面与键鼠整链路（root，iproute2/Xvfb/libXtst及Python依赖）：
    sudo python tests/remote_network_integration.py --binary build-wsl/tunnel
脚本创建独立命名空间和独立X11桌面，验证截图像素、键鼠、配对、名单/全员模式、只读、撤销、重启及断网释放。
原始结果在build-wsl/remote-network-tests/results.json；退出清理专属进程、命名空间和接口。

脚本创建独立网络命名空间、veth 和四个进程；只修改测试命名空间中的路由、防火墙与 TUN。
退出清理测试进程/接口/命名空间，结果和日志默认在 build-wsl/network-tests/。
14 项场景：单线程/单 UDP/单 TUN、多跳双向 IPv4、IPv6 与多地址、网络隔离、MTU 边界、
外层抓包密文检查、广播/IPv4 组播/IPv6 组播 RPF、UDP 故障切换、仅 TCP 故障撤回、
最后路径消失和接口释放、重启新公钥及新会话恢复。

地址分配真实网络测试（root，约两分钟）：
    sudo python3 tests/address_network_integration.py --binary build-wsl/tunnel
    sudo python3 tests/address_network_integration.py --binary build-wsl/tunnel --auth-mode per-node --work build-wsl/address-per-node-tests
独立命名空间中启动分配服务与三个节点，验证双栈地址生效、部分池耗尽、受管多跳、服务重启保址、
仅阻断一个节点的服务连接后20秒撤销、其他网络保持、自动恢复间接路径，以及凭据到期后回收再分配。
结果和日志：build-wsl/address-network-tests/；脚本退出清理测试进程、设备和命名空间。
默认使用共享密钥且不登记 clients；--auth-mode per-node 用于旧逐节点模式回归。
节点同时提供分配服务并向自身申请地址（root）：
    sudo python3 tests/embedded_allocation_test.py --binary build-wsl/tunnel
报告：build-wsl/embedded-allocation-result.json；检查单事件循环、真实双栈地址与持久绑定。

真实 Windows-Wintun 与 WSL-TUN 测试（Windows 管理员 Python）：
    python tests/windows_wsl_integration.py

需要已构建的 build/tunnel.exe、build-wsl/tunnel 和官方 wintun.dll；使用 Ubuntu 发行版。
8 项场景：双方认证、状态文件锁定不中断 VPN、IPv4/IPv6 TCP 回显、两种 IP 的 MTU 边界、
正常退出和 Wintun 网卡清理。结果位于 build/windows-wsl-tests/results.json。
脚本只创建临时接口与两个窄测试网段，不修改主机防火墙或默认路由。

内存检查（Linux）：
    cmake -S . -B build-wsl-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
    cmake --build build-wsl-asan --parallel 2
    ctest --test-dir build-wsl-asan --output-on-failure
    sudo python3 tests/network_integration.py --binary build-wsl-asan/tunnel --work build-wsl-asan/network-tests

Linux 真设备 14 项已在 ASan/UBSan 构建下执行，无检测报告。
平台结果只代表上述环境和场景；本机没有 Android SDK/NDK/设备或 macOS 编译环境，
尚不能据此声称 Android/macOS 构建成功、后台生命周期通过或达到某个吞吐量。
热加载JNI另使用临时解压的JDK17在WSL进行宿主JVM测试，不能替代Android设备验证，见android/README.md。
