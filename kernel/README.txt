Linux 可选内核数据后端
=====================

tunnel_kmod 创建三层 net_device。Linux 默认选择 kernel，需要加载本模块；
明确设置 device_backend 为 tun 可使用原 TUN 后端。其他平台包括 Android
默认 tun。模块与现有 TUN 节点使用相同的版本 1 线路格式。

内核负责 UDP 收发、AES-256-GCM 逐跳及端到端加解密、防重放、ECMP、
广播/组播 RPF、跳数限制、子网出口的回包授权。配置、TLS 握手、公钥传播、
地址分配、邻接存活判定仍由 tunnel 用户态进程负责。

TCP 数据也由内核加解密，只把已加密的逐跳记录通过控制设备交给用户态，
复用现有 OpenSSL TLS 连接；接收的密文记录写回控制设备。没有明文 IP
用户态慢路径。链路和端到端会话的 nonce/序列号均只有内核一处拥有。

使用
----
1. 安装目标 Linux 内核对应的开发头文件、make、C 编译器及 iproute2。
2. 推荐在项目根目录执行：
     python3 tools/build_kernel.py
   工具在临时目录编译，仅保存 .ko 和构建信息，避免源码目录积累中间文件。
   也可在本目录执行 make。默认使用 /lib/modules/$(uname -r)/build。
   指定另一套配置完整的目标头文件：make KDIR=/path/to/kernel/build
3. 使用工具构建后，在项目根目录安装并加载（root）：
     install -D -m 644 build/kernel/tunnel_kmod.ko /lib/modules/$(uname -r)/extra/tunnel_kmod.ko
     depmod -a
     modprobe tunnel_kmod
   若在 kernel/ 直接 make 构建，也可用该目录的 make install 安装。
   开发测试也可先 modprobe udp_tunnel，再 insmod ./tunnel_kmod.ko；部分
   内核还需 ip6_udp_tunnel。modprobe 安装后的模块会自动处理依赖。
4. Linux 节点省略 device_backend 即使用 kernel，也可明确指定："device_backend": "kernel"。
   设置 "device_backend": "tun" 即使用原来的 TUN 后端，无需加载本模块。
   归一化和保存始终写出实际的 tun/kernel，显式 tun 不会省略。
   使用 --tun-fd 继承用户态 TUN 时必须同时指定 --device-backend tun。

模块必须针对实际运行内核构建，包括其配置、编译 ABI 与符号版本。
未加载模块或 ABI 不匹配会明确报错，不会自动退回 TUN。Secure Boot
系统按发行版要求签名并信任模块。WSL 若不提供当前内核开发包，需要
准备匹配源码、运行配置和完整构建产物；只有 UAPI/kheaders 或执行
modules_prepare 不足以为启用 MODVERSIONS 的内核提供 Module.symvers。

当前 WSL 的开发环境与安装
------------------------
2026-10-20 已为运行中的 6.18.40.1-microsoft-standard-WSL2 构建、安装
匹配模块并完成实际运行测试；没有替换运行内核、重启 WSL 或修改启动配置。
最终主链路 15/15、ABI 9/9、外层 IPv6/RPF 3/3、子网/NAT 10/10 全部通过，
真实 BTF 注册为 5868 字节。报告见 build/kernel/tests/wsl-6.18.40.1-final/。
测试前后宿主网络和原远控进程保持不变；初次 BTF 差异及修复见 测试结果.txt。
测试清理后已普通 modprobe 加载最终模块留用，/dev/tunnel_kmod 可用；
产物目录中的 runtime-ready.json 记录模块、BTF 与原远控进程核验结果。
产物：build/kernel/6.18.40.1-microsoft-standard-WSL2/tunnel_kmod.ko。
标准安装：/lib/modules/6.18.40.1-microsoft-standard-WSL2/extra/tunnel_kmod.ko。
持久副本：/usr/local/lib/tunnel/6.18.40.1-microsoft-standard-WSL2/tunnel_kmod.ko。
启动节点前执行 sudo modprobe tunnel_kmod；不自动配置开机加载。

开发树使用 Microsoft 官方 tag linux-msft-wsl-6.18.40.1，commit：
14794180686c2fb6307fbe359c359bec765249f3；保留位置：
/home/tunnel-wsl-build/WSL2-Linux-Kernel-14794180686c2fb6307fbe359c359bec765249f3。
/usr/src/tunnel-wsl-6.18.40.1-microsoft-standard-WSL2 指向该树，包含运行
配置、生成头文件、Module.symvers 和完整构建产物，请保留以便重编模块。
/lib/modules/6.18.40.1-microsoft-standard-WSL2/build 也指向该 /usr/src 路径。
独立工具链使用 GCC 13.2.0、binutils 2.41、pahole 1.25，配置项与运行
内核一致；未覆盖 Ubuntu 的编译器。重编时从项目根目录在 Bash 执行：
  (
    source /home/tunnel-wsl-build/environment.sh
    python3 tools/build_kernel.py --headers /usr/src/tunnel-wsl-6.18.40.1-microsoft-standard-WSL2 --cc "$CC" --btf-base /sys/kernel/btf/vmlinux --output build/kernel/6.18.40.1-microsoft-standard-WSL2
  )
子 shell 让工具链环境仅用于构建。显式 /usr/src 路径避免依赖 WSL 覆盖层
中的 build 链接。重新构建后安装到标准位置，并更新上述持久副本。

本地重建 vmlinux 的 BTF 类型编号可能与官方运行内核不同；上例显式使用
/sys/kernel/btf/vmlinux，按目标内核的真实 BTF 重新生成模块调试类型信息。
该路径只适用于构建目标就是当前运行内核的情况；为其他内核构建时必须使用
对应目标的 BTF，不能沿用本机文件。工具不会自动选择或修改 BTF 基础文件。
--btf-base 要求开发树具备 vmlinux、启用 BTF，且 pahole/resolve_btfids 可用。
工具先正常构建，再复用 Kbuild 实际参数重生成模块 BTF，并确认全部 ALLOC
段和导入符号 CRC 保持不变；校验失败拒绝输出。来源、命令及校验保存在 build-info.json。

WSL 的 /lib/modules 使用覆盖层；若重启后标准安装消失，且 uname -r
仍与持久副本的版本一致，可执行：
  sudo install -D -m 644 /usr/local/lib/tunnel/$(uname -r)/tunnel_kmod.ko /lib/modules/$(uname -r)/extra/tunnel_kmod.ko
  sudo depmod -a
  sudo modprobe tunnel_kmod
更新已加载模块前先正常停止使用它的节点，再卸载、加载新模块。
WSL 更新内核后必须重新准备对应开发树并构建，不能复用旧版本 .ko。

兼容方式
--------
当前已为 6.18.40.1-microsoft-standard-WSL2 构建并实际运行验证匹配模块；此前版本通过
6.8.0-147-generic 和 7.0.0-38-generic 开发头文件编译，对应产物按原哈希保留。
实际加载和功能验证范围见项目根目录的 测试结果.txt。
其他版本需在目标系统构建并验证，不声称所有 Linux 版本均可直接使用。
Makefile 检查目标头文件
中的 UDP tunnel 函数声明，适配 socket/sock 和发送参数变化，避免仅依赖
版本号而误判发行版回移补丁。支持范围以实际编译和运行结果为准，不能
将一套内核生成的 .ko 直接用于另一套内核。

内核需启用 INET、NET_UDP_TUNNEL、CRYPTO_AEAD、CRYPTO_GCM、CRYPTO_AES；
IPv6 外层还需要 IPV6 和相应 UDP tunnel 支持。选择同步 gcm(aes) 实现；
没有同步实现时安装会话失败并报错。可用的硬件加速由 Kernel Crypto API
选择，不使用内核中的 OpenSSL，也不等待异步密码队列。

丢包与生命周期
--------------
ndo_start_xmit 直接完成查路由、加密和封装，接管 skb 后总是返回
NETDEV_TX_OK。无路由、密钥未就绪、资源不足、超过 MTU、队列满或发送
失败时立即丢弃；不会等待会话、缓存待协商的明文或做隧道层重传。
首次需要端到端会话时发送限速控制事件，当前包丢弃；协商后的后续包可用。

TCP 控制设备事件队列有 512 条和 512 KiB 双重上限，满了丢弃完整记录。
已进入 TCP 字节流的记录由现有 TCP/TLS 通道处理。

每次打开 /dev/tunnel_kmod 创建独立实例，要求对应网络命名空间的
CAP_NET_ADMIN。CREATE 绑定唯一 UDP socket 并注册设备；关闭最后一个
控制 fd 会注销设备、释放 socket、擦除密钥、清除回包权限和事件。
配置是完整且原子生效的快照。同一个会话 ID 重复发布时保留发送序列号
和接收防重放窗口，不能使用相同 ID 悄悄更换密钥或传输方式。

用户态定期更新控制租约。租约过期后停止处理数据；RENEW 和 SNAPSHOT
均拒绝恢复过期实例，必须关闭并重新创建，以免恢复已失效的连接资格。
路由、网段、节点 IP、会话或导出权限被撤回时，对应回包授权同时撤回；
无关路径更新和仍可到达的 ECMP 备用路径不清除其他连接的授权。

实现限制
--------
每实例最多 128 个虚拟网络、256 个直连 peer、4096 个节点路由、
256 个端到端会话、4096 条发布前缀，每条路由最多 32 个等价下一跳。
子网回包授权最多 1024 条流及 1024 条分片关联；TCP/UDP/ICMP echo
及相关 ICMP 错误均按已有 TUN 规则校验。达到容量直接拒绝配置或丢包。
SNAT 由系统内核 NAT 处理，模块只校验回包是否属于获准请求。

本版本使用每实例短临界区串行保护会话状态，不保证多核线性扩展。
不提供 IP 分片重组或 GSO，TUN MTU 仍需为封装预留空间。
