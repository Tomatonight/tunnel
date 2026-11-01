验证结果（2026-10-20）

当前 WSL 匹配开发环境、模块安装与实际运行
  运行内核为 6.18.40.1-microsoft-standard-WSL2；已安装完整匹配开发环境并编译、安装模块。
  使用 Microsoft 官方源码 commit 14794180686c2fb6307fbe359c359bec765249f3，
  GCC 13.2.0、binutils 2.41、pahole 1.25；配置项与 /proc/config.gz 相同，完整构建生成 Module.symvers。
  工具链解包在独立目录，保留开发树与 environment.sh；未替换运行内核、重启 WSL 或修改启动配置。
  标准模块安装在 /lib/modules/6.18.40.1-microsoft-standard-WSL2/extra/tunnel_kmod.ko，
  持久副本在 /usr/local/lib/tunnel/6.18.40.1-microsoft-standard-WSL2/tunnel_kmod.ko。
  移除不适用于动态 misc 设备的 devname MODULE_ALIAS，修复 depmod 报错；最终 depmod 无 stderr。

  首轮 all 功能检查通过，但发现本地重建 vmlinux 的 BTF 类型编号与官方运行内核不同。
  首轮记录保留在 build/kernel/tests/wsl-6.18.40.1/，不作为最终 BTF 通过记录。
  构建工具新增显式 --btf-base /sys/kernel/btf/vmlinux，以运行内核的真实 BTF 重生成模块调试信息；
  调整前后全部 26 个 ALLOC 段及 82 项导入符号 CRC 相同。来源、哈希、执行命令和校验保存在 build-info.json。
  最终普通加载后 /sys/kernel/btf/tunnel_kmod 实际存在，大小 5868 字节。

  修复后的最终模块完整重跑 all：主链路 15/15、ABI 9/9、外层 IPv6/RPF 3/3、子网/NAT 10/10 全部通过。
  主链路覆盖默认 kernel、明确 TUN、缺模块拒绝、无 TUN fd、UDP/TCP 混合中转、双向 IPv4/IPv6
  TCP/UDP/ICMP、MTU、暂停用户态后已有 UDP 会话继续、后端热切换、身份保持及 peer 撤回。
  ABI 覆盖非法输入、快照原子性、序列号/防重放保持、篡改认证失败、权限、租约过期和 fd 关闭清理。
  外层 IPv6 与环路广播/组播 RPF、双出口 SNAT/无 SNAT、IPv6 SNAT、出口切换和内网主动连接拒绝均通过。
  报告：build/kernel/tests/wsl-6.18.40.1-final/results.json；同目录 uapi/、flood/、subnet/ 保存分项结果，
  btf-runtime.json 保存真实 BTF 注册信息，console.log 和 dmesg-test.log 保存运行日志。

  测试在独立网络命名空间进行；退出码 0，无清理错误，无新增内核 oops/调用栈。
  宿主地址、IPv4/IPv6 路由与 rule、nftables、sysctl、命名空间前后不变；原远控 PID 695、starttick 60823 未变。
  测试接口、命名空间和模块均完成清理，随后已普通 modprobe 加载最终模块留用；未中断既有远控实例。
  /dev/tunnel_kmod 为字符设备，运行状态记录在模块产物目录的 runtime-ready.json。
  宿主比对：同目录 host-preservation.json、host-before.json、host-after.json。
  最终模块：build/kernel/6.18.40.1-microsoft-standard-WSL2/tunnel_kmod.ko，SHA256：
  fc0307712a9707cf55e1879e10802e7942fe46246ba3ec9071ca1d77065d957f。
  测试核心：build-wsl-reload/tunnel，SHA256：
  6e331b3c2cf02326edde04626084b77fe56fafbfe7240142b57fa5d8364cdc24。
  6.8/7.0 的旧模块产物与历史记录按原哈希保留，未将此次 WSL 结果视为它们重新验证。
Rebuild, load, and WSL overlay recovery commands are in [development.md](development.md) and [kernel README](../kernel/README.md); throughput and long-duration stress tests remain separate.

Linux 默认使用内核隧道设备
  省略 device_backend 时，Linux（不含 Android）选择 kernel，其他平台选择 tun。
  显式 tun/kernel 在配置规范化和保存后保留，避免在 Linux 重载或跨平台传递时丢失选择。
  GUI 增加平台默认项；原生 --device-backend 持续覆盖与热加载规则不变。

  Windows 核心重新编译，597 项基础检查通过，实际规范化结果仍为 tun。
  Linux 全部目标重编译，11 个 CTest 项目最终通过；首次并发负载下 address_service
  在短时限重连测试中出现 map::at，其余 10 项通过；未改生产代码，单独重跑该项通过（12.1 秒）。
  日志：build-wsl-reload/default-kernel-regression-first.log、default-kernel-address-service-retry.log。
  前端 81/81，通过平台默认、显式后端的导入/保存与界面状态检查。
  报告：build/gui-tests/platform-default-frontend/results.json。

  Linux 7.0 虚拟机主集 15/15、ABI 9/9：省略后端的 A 实际使用 kernel 且没有 TUN fd，
  与显式 TUN 节点双栈 TCP/UDP/ICMP 互通；缺模块时默认选择明确失败，不静默回退。
  显式切到 TUN 后删除字段，热加载恢复默认 kernel，保持 PID/身份并恢复双栈通信。
  报告：build/kernel/tests/default-kernel/results.json 与 console.log。
  当前 WSL 的独立命名空间中显式 TUN 热加载 4/4，包含 MTU、地址替换、失败回滚和节点/地址服务器切换。
  报告：build-wsl-reload/default-kernel-tun-reload/；测试命名空间清理通过，原远控进程未受影响。
  以上默认值调整阶段未修改模块源码、未重复 NAT/RPF 全套；后续当前 WSL 的完整验证见本节开头。Windows GUI 成品未重新打包。

以下为此前版本验证记录。

验证结果（2026-10-19）

Linux 可选三层 net_device 后端
  默认仍为 TUN；JSON device_backend、原生 --device-backend 和源码 GUI 均可选择 kernel。
  UDP 数据收发、逐跳/E2E 加解密、选路与转发在内核；TCP 密文仍复用用户态 TLS。
  无路由、无会话或无法发送时丢弃；不缓存待协商的明文包，不做隧道层重传。

  Windows 最新核心编译通过，基础检查 592 项通过；Linux 最新构建及 CTest 11/11 通过。
  Linux 套件包含 core、config、runtime、address_service、managed_node、device_addresses、
  subnet、remote_control、reload、tcp_data、tcp_legacy；总耗时约 60.5 秒。
  日志：build-wsl-reload/Testing/Temporary/LastTest.log。
  前端 78 项通过，页面错误 0；报告 build/gui-tests/kernel-frontend/results.json。
  本轮未重新打包 Windows GUI；源码 GUI/CLI 请显式选择 build-reload/tunnel.exe 或 build-wsl-reload/tunnel。

  相同模块源码针对 Ubuntu x86_64 的 6.8.0-147-generic、7.0.0-38-generic 编译通过。
  7.0 额外 W=1 编译无模块源码告警。产物在 build/kernel/<内核版本>/，build-info.json 保存来源和 SHA256。
  6.8 本轮仅做编译验证；实际模块加载和流量测试使用独立 QEMU 7.0 虚拟机。
  当前 WSL 为 6.18.40.1-microsoft-standard-WSL2，缺少匹配开发头文件，没有强行加载这些模块或更换 WSL 内核。

  真实主链路 15/15：默认 TUN/CLI/JSON 选择、缺模块明确报错、模块加载、真实设备 fd 检查，
  A(kernel)→UDP→B(kernel)→TCP→C(TUN) 的双向 IPv4/IPv6 TCP/UDP/ICMP、MTU 边界，
  内核中转计数及中转不终止 E2E、TCP→UDP 热加载、暂停 A 用户态进程后已建 UDP 会话仍能传输，
  B 的 kernel→TUN→kernel 热切换保持 PID/身份并恢复双栈 TCP/UDP、peer 撤回与全部退出清理。
  报告：build/kernel/tests/main/results.json；同目录 console.log 保存虚拟机输出。
  main 与 extras 两轮使用相同核心和模块 SHA256，最终可执行文件与报告记录一致。

  真实模块 ABI 9 组检查通过：MTU/长度/数量/ABI/指针等非法输入拒绝、地址与重叠检查、
  同会话 ID 换钥拒绝、快照原子性、发送序列号和重放窗口保持、伪造记录不推进窗口，
  权限下降后的控制调用拒绝、失效租约不可恢复、控制 fd 关闭释放设备和 UDP 绑定。
  外层 IPv6/RPF 3 组通过：内核与 TUN 的 UDP6 邻接、内层双栈 TCP/UDP、
  三节点环路中 IPv4 广播及 IPv4/IPv6 组播单份交付，错误上游产生 RPF 丢弃计数。
  内核后端子网/NAT 10 组通过：双出口前缀传播、TCP/UDP/ICMP 的 SNAT 源地址、
  拒绝内网主动连接、出口切换、最后出口撤回、关闭后防火墙/转发恢复、
  无 SNAT 的 IPv4/IPv6 回程及虚拟源地址选择、IPv6 SNAT、路由撤回和系统清理。
  报告：build/kernel/tests/extras/results.json；同目录 console.log 保存完整虚拟机输出。
  测试使用独立虚拟机与网络命名空间，清理检查通过，无内核 oops。

  模块需按部署主机的实际运行内核重编译；本轮不代表其他内核/架构已经验证。
  未进行吞吐量、长时间压力、ASan/UBSan 或 macOS/Android 实机回归。
Build the module with python3 tools/build_kernel.py; usage is documented in [development.md](development.md) and [kernel README](../kernel/README.md).

以下为此前版本验证记录，不能视为本轮重新执行。

验证结果（2026-10-16）

TCP数据封装（本轮）
  新增peers[].transport="tcp"，默认UDP；任一端选择TCP且双方支持时使用TCP，旧版不支持时明确拒绝。
  数据使用现有认证TLS连接内的二进制帧，保持链路AEAD、单播端到端加密、ECMP和RPF。
  支持TCP/UDP混合中转，TCP模式不依赖UDP可达；运行时切换仅重连对应邻接。

  Windows、WSL重新构建通过；原有9项CTest通过，新增tcp_data与tcp_legacy亦均通过。
  tcp_data两端各1404项断言（含1200次突发注入检查）；tcp_legacy两端各23项。
  验证二进制拆包/粘包及控制帧交错、大小限制、旧版Hello及UDP密钥上下文兼容、禁止未经协商的数据帧，
  单侧TCP选择、UDP不可达、IPv4/IPv6外层、真实TCP代理黑洞超时撤回、内层双栈/广播组播、混合中转，
  Peer热切换、无关邻接/E2E保留、错误PSK拒绝，以及发送队列有界丢包后全部已接收帧送达。
  突发测试独立使用生产20秒失效窗口；Windows接受356包、丢弃844包，连接/E2E保持并可继续发送。
  旧版模拟节点补充首次探测丢失重试；短时断链用例与生产5秒保活的数据/E2E用例分开，
  避免把测试专用500毫秒E2E重试阈值在慢调度下的重复握手当作传输失败；生产保活仍为5秒/20秒。
  复现：ctest --test-dir <构建目录> -R tcp_ --output-on-failure。
  最新专项日志：build-reload/Testing/Temporary/LastTest.log、build-wsl-reload/Testing/Temporary/LastTest.log。

  Linux真实TUN混合三节点9/9：A→TCP→B→UDP→C，A外层UDP在独立命名空间中完全阻断。
  验证双向IPv4/IPv6的TCP流、UDP回显、ICMP及1280 MTU；TCP连接经超过20秒UDP阻断仍保持；
  SIGHUP切换TCP→UDP→TCP，进程/身份不变且B–C邻接保持。全部测试进程和命名空间清理无错误。
  报告：build-wsl-reload/tcp-network-tests/results.json。
  Windows Wintun↔WSL TUN真实TCP封装9/9：认证、IPv4/IPv6 TCP回显、双栈MTU边界、
  TCP记录收发且UDP数据记录为零、状态文件锁定不影响VPN、正常退出和网卡清理。
  状态监控脚本对原子替换期间的临时PermissionError重试，不改核心逻辑。
  报告：build/windows-wsl-tcp-tests/results.json。

  前端76/76：新增封装选择、JSON导入/保存、协商状态和计数显示；CLI原生配置集成6/6。
  报告：build/gui-tests/tcp-frontend/results.json；CLI复现tests/cli_transport_test.py。
  Windows成品已重新打包：build/gui/TunnelUI/TunnelUI.exe、TunnelCtl.exe和同目录最新核心。
  打包CLI的TCP配置测试6/6，覆盖新增、切换、默认省略、非法值拒绝与PSK不泄露；
  成品WebView自检7/7、退出码0，报告build/gui-tests/tcp-package.json。
  成品核心及app.js/index.html的SHA256与当前构建/源文件逐一一致；两份TCP配对示例已随包附带。
  示例examples/tcp-node-a.json、tcp-node-b.json已通过核心校验。
  macOS/Android共用核心和配置/界面逻辑，但本轮未进行目标平台构建或设备TCP互通测试；
  本轮未重跑ASan、远程桌面整链路或进行吞吐量基准测试。

配置热加载与命令行配置（前一轮）
  Windows与WSL最终构建、CTest均9/9通过；新增reload用例两端各69项。
  验证无变更不重连、远控单独更新、Peer增删/PSK/网络授权变更、未修改邻接和端到端会话保留，
  网络资源重建、身份不变、资源失败恢复、双重失败报告与再次应用、外部TUN回调及重入拒绝。
  原始记录：build-reload/Testing/Temporary/LastTest.log、build-wsl-reload/Testing/Temporary/LastTest.log。
  原生核心输出位于build-reload/tunnel.exe和build-wsl-reload/tunnel。

  命令行与真实后台集成：Windows9项、WSL10项通过。覆盖同PID热加载、密钥默认隐藏、无效配置拒绝、
  端口占用恢复、重新读取外部配置、Peer/网络编辑、文件监视；WSL另验证SIGHUP。
  分配服务热换公布端点时迁移原租约元数据并保留IP；普通启动仍拒绝误用其他服务的状态文件。
  复现：python tests/reload_cli_test.py --binary <核心路径>。
  真实设备：Windows Wintun与WSL TUN各4/4通过，含MTU1300实际查询、IP替换/移除、
  绑定失败恢复原设备、隧道节点→仅地址服务→隧道节点、同PID/身份及退出清理。
  复现（管理员/root）：python tests/reload_device_test.py --binary <核心路径>。

  后台配置提交/落盘失败与恢复单元测试8/8；Windows界面宿主含live测试23/23；前端72/72。
  GUI/CLI使用配置文件锁及SHA256版本检查；冲突拒绝覆盖，应用失败保留编辑内容。
  Windows原生stdio RPC15项、双向管道压力3/3通过。修复热加载日志穿插RPC响应的问题。
  复现：tests/config_manager_test.py、tests/gui_host_test.py、tests/gui_frontend_test.js。
  报告：build/gui-tests/reload-frontend/results.json、build-reload/remote-bridge-tests.json。

  Windows成品已更新：build/gui/TunnelUI/TunnelUI.exe及同目录TunnelCtl.exe。
  控制台成品6/6：带BOM配置导入、重复JSON键拒绝、独立启动冻结后台、同核心PID应用配置、
  运行配置隐藏密钥、显式停止与清理。复现：python tests/cli_package_test.py。
  成品真实WebView自检7/7，退出码0；报告build/gui-tests/reload-package.json。
  正在运行的旧手工远控测试实例未强制停止；使用新功能需首次停止旧实例，再启动新版本。

  Android生产JNI在WSL使用私有JDK17编译并经JVM调用，25项通过；未安装系统JDK包。
  复现：JAVA_HOME=<JDK路径> bash android/tests/run_host_tests.sh build-wsl-reload。
  覆盖重载队列、协议线程应用、Java结果回调、MTU与设备重建回调、停止时拒绝排队请求。
  尚无Android SDK/NDK或设备，未编译APK、未验证真实VpnService；macOS本轮未编译或实机验证。
  本轮未重跑ASan或之前的四节点/远控整链路测试；下列为早期对应版本的独立验证记录。

以下保留2026-10-15及之前的验证记录。

远程桌面与访问授权（本轮）
  已实现remote_desktop配置、独立后台、长期设备身份、仅授权设备/同虚拟网络全部成员两种策略，
  配对与无人值守、只读/键鼠权限、即时撤销、后台接回、单屏JPEG与原生输入。
  普通连接仍需当前有效网络成员证明；全员模式仅跳过逐台授权，不关闭认证或TLS。
  同时只允许一个控制端。策略收紧、名单撤销、断网和关闭均释放已按下的键/鼠标按钮。

  Windows/WSL最终C++构建通过，CTest各8/8；新remote_control各124项。
  涵盖严格配置/规范化、真实三节点多跳IPv4/IPv6成员签验、篡改/跨网/错IP拒绝、撤回与换钥。
  真实stdin/stdout RPC：Windows15项、WSL16项通过，覆盖分片/批量/过长帧/中文ID/未知方法/STOP及无密钥日志。
  报告：build/remote-core-test-results.json；CTest详情见各构建目录Testing/Temporary/LastTest.log。
  修复测试中双向同时拨号的连接替换窗口：待双方路径和连接仲裁完成后再验证稳定状态，未放宽生产认证/超时。

  Python真实TLS运行时测试：Windows16/16、WSL16/16。
  涵盖首次固定设备公钥、全员免逐台批准、名单配对、仅查看的服务端输入拒绝、旧证明失效、成员撤回、
  策略切换、设备撤销、重复控制端拒绝、持久身份/损坏库拒绝、backend清理异常及有界帧/IPC认证。
  日志：build/remote-runtime-final.log、build-wsl/remote-runtime-final.log。
  竞态回归：Windows11/11、WSL11/11；已接收的poll在撤权后不再执行输入，过期批准不能恢复授权，
  重复批准不能提升权限，线程启动与关闭交错可清理，慢TLS握手/取消连接可结束，无poll也定期重验成员资格。
  测试脚本：tests/remote_race_test.py。
  核心桥压力：Windows3/3、WSL3/3，真实4096字节双向管道，32线程共128次4KiB请求/响应正确关联；
  验证32 pending上限与恢复、核心EOF唤醒等待者，未发生读写锁互锁。
  报告：build/remote-bridge-tests.json、build-wsl/remote-bridge-tests.json。

  平台后端：Windows16项通过并真实只读截图1920×1080→JPEG1600×900；没有向用户正在使用的桌面注入测试按键。
  Linux15项通过、1项Windows专用检查跳过；另在独立Xvfb实测截图颜色、指针、鼠标键、键盘与释放。
  真实整链路7/7：两个私有netns内运行真实TUN/core/daemon/TLS，被控端使用隔离Xvfb图形会话。
  验证仅监听虚拟IP、真实JPEG像素和键鼠跨隧道、断线释放、名单批准与只读、记住授权与撤销、
  全员→名单即时取消控制、后台重启保留身份和授权、物理链路失联后释放输入。
  报告：build-wsl/remote-network-tests/results.json；remaining_test_namespaces=[]，cleanup_errors=[]。

  前端浏览器68/68，Windows宿主/live18/18；真实Windows窗口7/7，含新远控DOM/样式与桥接检查。
  前端覆盖首次信任/实时JPEG/输入及失焦释放、只读、授权操作、网络权限不自动扩张、XSS文本呈现，
  及Android保留导入配置但禁用不支持的被控功能，并允许显式移除该设置。
  Windows打包后台实际启动/长期身份/重新attach/配置热更新/退出清理5/5；成品WebView自检7/7。
  报告：build/gui-tests/remote-frontend/results.json、remote-host-final.log、remote-window.json、
  remote-window-live.json、remote-package-background.json、remote-package.json。

  平台限制：本版只支持已登录桌面。Linux仅X11，Wayland明确拒绝；登录界面、UAC安全桌面、FileVault未实现。
  macOS采集/输入源码已编写，未在Mac上安装、编译打包或实机验证；Android本版不提供远控端。
  无自动安装开机系统服务；无人值守后台在当前用户图形会话中运行，重启后需重新启动或自行配置登录启动。
  单屏JPEG最多8fps，未声称硬件视频编码、高帧率、音频/剪贴板/文件传输或多屏支持。
  示例examples/desktop-host.json、desktop-client.json已通过核心配置校验；运行方式见remote_desktop/README.md。

以下保留此前内网路由阶段的验证记录。

内网路由分发与可选内核 SNAT
  已实现 advertise_routes、同 tunnel 前缀传播/撤回、最短跳数主出口和备用出口、到同一出口的原有 ECMP，
  以及访问端系统路由、桌面出口 NAT 和有界请求/回包授权。内网不能主动建立到隧道节点的新连接。
  受管地址失效仅撤回对应 tunnel 的出口/导入路由；静态网络保持。
  界面可编辑发布前缀/SNAT 并显示出口和错误；Android 作为访问端。

  Windows、WSL 全部构建通过；最终 CTest 两端各7/7通过。
  核心各492项；运行时 Windows119、Linux127；地址服务各181；受管节点各70；子网各395。
  普通设备检查 Windows28、Linux75；测试端口预留不再计入地址服务断言，数量不与旧记录直接比较。
  新覆盖：新旧 wire兼容、静态/受管配置、前缀冲突隔离、主备和同出口ECMP、后端失败不发布/不导入、
  TCP/UDP/Echo 回包与错误元组拒绝、关联ICMP错误、IPv4/IPv6分片与扩展头、atomic fragment、容量和超时、
  TCP SYN不能作为回包、退网清理及恢复、多个来源最新前缀/公钥快照一致性。
  日志：build/subnet-tests-final.log、build-wsl/subnet-tests-final.log；
  逐项断言输出：两端 Testing/Temporary/LastTest.log。

  真实 Linux 子网集成10/10通过：独立6个网络命名空间，访问端经中转到两个内网出口。
  验证 IPv4 SNAT TCP/UDP/ICMP 的实际内网源地址、拒绝LAN主动连接、主出口失效后新连接走备用、
  所有出口退出后撤销导入路由且普通overlay仍可用，以及无SNAT的IPv4/IPv6自动源地址和回程路由。
  已修复测试发现的IPv6 subnet-router anycast被误查成lo出口，重测IPv6 TCP/UDP/ICMP全部通过。
  IPv6 SNAT额外实测：客户端自动选源时，H看到TCP/UDP/ICMP的源均为出口LAN地址fd00:91::1；
  关闭SNAT时三者源均为客户端虚拟地址fd00:90::1。原始记录：同目录host-ipv6.jsonl。
  正常退出恢复 nft规则、全局及LAN接口转发设置；测试命名空间全部清理。
  报告：build-wsl/subnet-network-tests/results.json。

  真设备导入路由：Windows194项、Linux171项通过，覆盖真实IPv4/IPv6路由添加/撤回和接口失效处理。
  Windows仅修改测试自有Wintun；Linux使用独立临时命名空间；未修改宿主NAT。
  报告：build/subnet-device-live-results.json、build-wsl/subnet-device-live-results.json。

  前端62/62；Windows和Linux宿主各14/14；Windows实际窗口7/7；成品自检4/4。
  成品核心、3个页面资源和4个示例共8文件SHA-256核对一致。
  成品：build/gui/TunnelUI/TunnelUI.exe；配对示例 examples/subnet-gateway.json、subnet-client.json。
  报告：build/gui-tests/subnet-*、build-wsl/gui-tests/subnet-host.*；
  命名空间清理记录：build-wsl/gui-tests/subnet-namespace-cleanup.json。

  回归修复了测试框架只预留UDP、TCP临时源端口可能占用后续监听端口的问题；
  改为非默认临时端口范围内预留TCP/UDP双通道，再按平台顺序运行，最终全套通过。
  真实主备测试等待确定性主出口完成通告收敛后再采样，避免把初始临时备用出口当成固定预期。
  Windows WinNAT出口数据互通未在本轮验证；macOS/Android仅源代码/静态检查，无目标SDK/实机验证。
  Windows SNAT仅IPv4且受WinNAT内部前缀限制；Windows/Android同族多tunnel地址不导入内网路由。
A published prefix must use one physical egress; reconnect after the host egress changes. See [development.md](development.md) for platform limits.

共享接入密钥简化
  address_server 现可仅配置 address、shared_key 和 networks，无需手写 clients 名单。
  任意持有对应服务密钥的节点可申请配置池；旧逐节点授权模式保持兼容，两种配置严格互斥。
  服务端仍自动保存租约，原有回收、断线撤销、peer 授权和数据加密流程保持适用。

  Windows、WSL 构建均通过，无编译告警；CTest 两端各6/6通过。
  核心各492项；运行时 Windows 91项、Linux 99项；地址服务各254项；受管节点各50项。
  普通设备检查 Windows 2项、Linux 33项。
  地址服务新增共享模式规范化、互斥与空密钥拒绝、17个未登记成员同时双栈接入，
  错误密钥/未声明池拒绝、同身份并发拒新保旧、34条绑定重启保址、旧签名失效，
  旧池和旧节点租约保留、防止配置变更提前复用地址、损坏持久化身份与重复IP拒绝。
  日志：build/shared-key-tests-final.log、build-wsl/shared-key-tests-final.log；
  逐项输出：两端 build 目录下 Testing/Temporary/LastTest.log。

  命令行31项通过：未登记IPv4/IPv6端点导出、导出配置校验、非法端点拒绝且无部分输出，
  旧名单按节点保留密钥和池范围、未登记节点拒绝、空名单不转为开放接入。
  报告：build/shared-key-cli-results.json。
  真实 Linux 共享密钥网络测试12/12通过：独立服务和三个节点、双栈真实TUN、多跳，
  部分池耗尽、服务退出或20秒黑洞仅撤销受管网、静态会话保留、重连与重启保址，
  等待旧凭据失效后回收再分配、旧节点回归不抢占已重新分配的IP。
  报告：build-wsl/shared-key-network-tests/results.json，auth_mode=shared。
  内嵌服务4项通过：同节点同事件循环、共享密钥向自身申请、双栈TUN和持久绑定。
  报告：build-wsl/shared-key-embedded-result.json。测试命名空间均已清理。

  前端54项通过：默认共享表单、生成/显示/复制密钥、共享导出全部地址池，
  导出用的客户端地址不写入服务配置；旧模式保权、显式切换与取消、混用配置拒绝。
  Windows/Linux 宿主 --live 各13项通过；Windows WebView2 实际窗口7/7通过。
  报告：build/gui-tests/shared-key-frontend.json、两端 gui-tests/shared-key-host.log，
  build/gui-tests/shared-key-window.json；新表单桌面/手机截图在 build/gui-tests/frontend/。
  Windows 成品 build/gui/TunnelUI/TunnelUI.exe 已重打包，自检4/4通过，
  核心、三份页面资源和两份示例共6文件与源文件SHA256一致。
  报告：build/gui-tests/shared-key-package.json、shared-key-package-files.json。

  Android 已把 address_server.shared_key 纳入日志脱敏；4个Java文件语法检查通过。
  本轮未构建Android APK或macOS程序，未运行这两端实机测试；未重跑压力、吞吐或密码学审计。
  共享PSK只认证组成员；持钥成员可声明其他端点，不能用它实现独立身份或单独撤销成员。
  本轮之前的结果如下，不能视为本轮重新执行。

可选地址分配服务与同步界面
  Windows、WSL 最终构建通过；CTest 各 6/6 通过，无编译告警。
  核心各492项；运行时 Windows 91项、Linux 99项；地址服务各117项；受管节点各50项。
  普通设备检查 Windows 2项、Linux 33项；真实动态地址检查 Windows 45项、Linux 62项通过。
  最终套件日志：build/windows-tests-final.log、build-wsl/linux-tests-final.log；
  逐项输出：build/Testing/Temporary/LastTest.log、build-wsl/Testing/Temporary/LastTest.log。

  地址服务覆盖独立 PSK、授权网段、错误密钥/未知节点、重复接入、双栈独立地址池与池耗尽，
  凭据签名/节点/IP/到期校验、服务重连与重启保址、旧服务签名失效、延迟回收，
  数据库损坏、锁冲突、写入失败、时间戳溢出、宽前缀分配及本机静态网/服务池冲突拒绝。
  受管节点覆盖既有静态连接上新增双栈资格、服务关闭仅撤销受管网、保留静态端到端会话，
  恢复原地址、不同分配服务隔离、手动模式不可绕过分配、续期不重复配置接口。
  新增双事件循环回归：确定性暂停对端握手处理，验证新会话重试、迟到响应隔离和排队包单次送达。

  真实 Linux 地址分配网络测试 12/12：独立服务器和三个节点、真实 TUN 双栈、多跳、
  部分地址池耗尽、无服务时静态网可用、服务进程无 TUN/UDP 且单线程，
  服务退出仅撤销受管网、重启保留绑定、单节点服务连接黑洞20秒撤销与自动恢复，
  旧凭据到期后回收再分配、旧节点回归不能复用已经重新分配的 IP。
  报告：build-wsl/address-network-tests/results.json。
  内嵌服务额外4项通过：同一节点/事件循环提供服务并向自身认证申请、真实双栈TUN、绑定落盘。
  报告：build-wsl/embedded-allocation-result.json。
  既有真实四节点回归 14/14：新旧配置、双栈多网、ECMP/RPF、MTU、密文、TCP/UDP失效和重启换钥。
  报告：build-wsl/address-regression-network-tests/results.json。
  所有真实网络测试使用独立命名空间，结束后已确认无残留。

  GUI 前端47项通过，包括分配客户端/服务表单、独立密钥、按节点导出接入配置，
  明确合并或替换导入、保留 peer 权限、部分分配/错误/离线绑定/设备故障展示与手机布局。
  报告及截图：build/gui-tests/frontend/。
  桌面宿主 Windows 11项常规及1项真实TUN分别通过；Linux --live 12/12通过。
  实际窗口 Windows WebView2、WSLg GTK/WebKit 各7/7通过；Linux 仅有 MESA 显卡探测提示。
  报告：build/gui-tests/window-final.json、build-wsl/gui-tests/window-address-final.json。
  Windows 成品 build/gui/TunnelUI/TunnelUI.exe 已更新，含最新核心和两份地址服务示例；
  成品自检4/4通过，核心/三份页面资源/两份示例共6文件与源文件哈希一致。
  报告：build/gui-tests/package-final.json、build/gui-tests/package-files-final.json。

  本轮发现并修复：Windows租约文件覆盖时读取句柄未关闭、动态恢复后间接路径缓存未重发、
  地址重新分配时旧映射清理、初始端到端握手丢失后的重试及迟到旧尝试覆盖新会话的问题。
  测试中的高频同步落盘放大了Windows短超时，受管节点测试改为1秒续期并实际观察凭据更新；
  生产5秒保活/20秒失效参数未改。回收测试先确认服务端离线和持久化reclaim_at，
  再等待凭据保护期限及续签/状态发布；不将状态文件读取失败当作网络已撤销。

  Android 已更新动态 VpnService 接口/JNI与持久目录，Java语法及JNI签名静态检查通过。
  本机没有Android SDK/NDK/JDK/设备或macOS环境，未进行APK构建、macOS编译或目标平台运行。
  本轮未执行ASan/UBSan、长时间压力、吞吐量测试或密码学审计；此前记录仅代表此前版本。

以下为此前版本的验证记录。

验证结果（2026-10-14）

简化配置与表单界面更新
  Windows 和 WSL 均重新构建通过，CTest 各 3/3；核心检查各 492 项（本次新增 116 项）。
  覆盖新旧格式、默认值、IPv4/IPv6 主机 CIDR、重叠拒绝、多网显式授权、监听限制，
  以及序列化后再次解析，保持 PSK、绑定地址、禁用监听和空监听网络列表。
  原始日志：build/Testing/Temporary/LastTest.log、build-wsl/Testing/Temporary/LastTest.log。
  桌面宿主 Windows、WSL 各 9/9：包括旧配置只读加载、显式保存转换、无效配置保留、
  增网不扩大授权、OpenSSL 密钥生成，以及真实 TUN 启停、重连和关闭清理。
  共享前端浏览器回归 33/33，无 JS 页面异常；桌面与 390px 手机布局检查通过。
  覆盖表单编辑、生成/显示/复制密钥、网络授权、高级设置、JSON 显式应用和导入、
  未保存编辑保护、实时状态与日志，以及桌面和 Android 桥接契约。
  报告及截图：build/gui-tests/frontend/；浏览器截图使用测试夹具，不表示真实节点状态。
  Windows WebView2 与 WSLg WebKit 实际窗口各 7/7，通过旧配置加载不改文件、表单修改
  虚拟 IP、保存新格式、按钮启动真实 TUN、实时状态显示与停止清理。
  报告：build/gui-tests/simple-config-window.json、build-wsl/gui-tests/simple-config-window.json。
  Windows 目录包已重新生成，成品 TunnelUI.exe 的窗口/桥接/配置加载/核心校验 4/4 通过，
  退出码 0。报告：build/gui-tests/simple-config-packaged-window.json。
  四节点新旧格式混用测试 14/14：A/C 使用新格式，B/D 使用旧格式；双栈、多网、ECMP、
  RPF、MTU、TCP/UDP 20 秒失效回撤、最后路径撤回及重启换钥均通过。
  报告：build-wsl/simple-config-network-tests/results.json。
  Android 同步接入核心配置规范化和 OpenSSL 密钥生成，通过 Java/XML/JNI/桥接静态检查。
  Android APK 和 macOS 窗口仍未在目标环境构建或运行；本次未重跑 ASan 或 Windows/WSL 互通。

以下为此前版本的验证记录，当前版本结果以上述更新为准。

图形界面与 5 秒 / 20 秒保活更新
  Windows 和 WSL 核心重新构建通过；CTest 两端各 3/3 通过。
  stdin 控制：Windows 真实 Wintun 5/5，WSL 真实 TUN 5/5。
  覆盖 STOP 分段、CRLF、EOF、非法/超长命令、未启用时不读取 stdin、正常退出和网卡清理。
  结果：build/stdio-tests/results.json、build-wsl/stdio-tests/results.json。
  桌面宿主：Windows 与 WSL 各 5/5，含配置校验/原子保存、日志脱敏和上限、页面令牌、
  关闭后拒绝排队启动，以及真实核心启动/停止/再次连接/关窗清理。
  复现：tests/gui_host_test.py --binary <核心路径> --live。
  Windows WebView2 实际窗口通过按钮启动/停止真实 Wintun、状态显示与清理，共 5 项检查。
  复现：tests/gui_window_smoke.py。
  WSLg / GTK 3.24.52 / WebKit2GTK 2.52.6 实际窗口同样 5/5 通过，默认沙箱设置未修改；
  在独立网络命名空间内创建真实 TUN，退出码 0，命名空间和设备已清理。
  报告：build-wsl/gui-tests/window-smoke.json；仅有 MESA ZINK 显卡探测警告，无功能失败。
  Windows 免安装目录已打包；TunnelUI.exe --check-ui 的窗口、桥接、配置读取和核心校验 4 项通过，
  退出码 0。报告：build/gui-tests/packaged-window.json。
  共享页面离线浏览器回归 18/18：导入/校验/保存、编辑保护、状态/ECMP、日志、文本注入防护、
  启停、超时重试、快照过期、手机布局、桌面/Android 桥接等；无 JS 页面异常。
  结果及截图：build/gui-tests/frontend/；截图使用测试夹具，不代表实际已连接节点。
  新默认参数下真实四节点故障注入 14/14：单独阻断 TCP/UDP 后按 20 秒已验证活动超时撤回，
  保留 ECMP 替代路径及其公钥/端到端会话；结果：build-wsl/gui-network-tests/results.json。
  Android 新界面通过 Java 语法解析、Manifest XML、资源路径、JNI 签名和桥接动作静态检查；
  当前仍没有 SDK/NDK/JDK/设备，未生成 APK 或运行实机。macOS 窗口和 utun 未在目标环境验证。

  测试中修正了两处时序假设：Windows 适配器查询初始化可能超过 3 秒，stdin 非控制用例
  改为运行 15 秒；网络 UDP 接收/抓包助手增加启动屏障，避免接收窗口在其他助手就绪前耗尽。
  Windows runtime 首次在并行负载下使用测试专属短超时失败，独立重跑 3/3 通过；未改核心逻辑。
  Windows 隐藏窗口首次初始化超过原 20 秒等待，窗口 smoke 改为等待加载完成最多 60 秒后通过。

下列 ASan、Windows/WSL 互通及既有核心测试是此前核心版本的验证记录；未对新 Python/Java 宿主宣称 ASan 覆盖。

Windows（Zig 0.14.1 / OpenSSL 3.6.5 / libevent 2.1.13）
  编译通过，无编译告警；CTest 3/3 通过。
  核心检查 376 项；运行时检查 79 项；配置校验通过。
  原始日志：build/Testing/Temporary/LastTest.log

WSL 2 / Ubuntu 26.04.1（GCC 15.2 / OpenSSL 3.5.5 / libevent 2.1.12）
  编译通过，无编译告警；CTest 3/3 通过。
  核心检查 376 项；运行时检查 87 项；配置校验通过。
  比 Windows 多出的 8 项覆盖 POSIX 继承设备 fd 的非阻塞读写和所有权释放。
  原始日志：build-wsl/Testing/Temporary/LastTest.log

ASan + UBSan
  编译通过；CTest 3/3 通过，376 项核心检查和 87 项运行时检查通过。
  四进程真实 TUN 测试 14/14 通过，测试进程均正常退出，未报告内存错误、泄漏或未定义行为。
  原始日志：build-wsl-asan/Testing/Temporary/LastTest.log
  网络结果：build-wsl-asan/network-tests/results.json（同目录保存四个节点日志与状态）

真实 Windows Wintun / WSL Linux TUN 互通
  8/8 通过：TLS/UDP 认证、状态文件被锁定不中断 VPN、IPv4 TCP 回显、IPv6 TCP 回显、
  IPv4/IPv6 MTU 1280 边界、正常退出、Wintun 网卡清理。
  结果：build/windows-wsl-tests/results.json

真实四节点拓扑与故障注入
  A-B-D 与 A-C-D 等价路径；三个虚拟网络，C 只加入其中一个。
  验证：单协议线程/单 UDP socket/单 TUN、多跳双向 IPv4、IPv6、多地址、授权网络隔离，
  MTU 边界及超限拒绝、外层抓包无测试业务明文、广播/组播的稳定 RPF 单次投递，
  仅 UDP 阻断时 ECMP 切换且保留端到端会话、仅 TCP 阻断时邻接失效，
  最后路径消失后撤回密钥与会话、进程重启发布新公钥并恢复通信。
  脚本所有路由和防火墙操作限制在新建测试命名空间，已清理临时进程和接口。

新增边界回归
  TLS exporter 上下文隔离及长上下文、错误 PSK、错误身份公钥、超长控制帧，
  配置大小/嵌套深度/peer 数量/总网络数量，定时换会话但保留进程身份，
  Android 宿主重建 Node 时复用身份、网络切换重连、临时文件锁及 Windows UDP 立即重绑。

验证边界
  macOS utun 后端和 Android VpnService/JNI/Gradle 工程已编写，未进行目标平台编译或实机测试。
  当前没有 Android SDK/NDK、JDK/设备和 macOS 环境。Android 构建脚本已通过 bash 语法检查；
  共享 C++ 核心和继承 fd 测试不能替代 APK 编译、VPN 授权/撤销、前后台与网络切换实机测试。
  未执行吞吐量、长时间压力或密码学审计；RPF 只验证稳定拓扑，未承诺切换期间严格跨路径去重。

Reproduction and deployment commands are in [development.md](development.md); Android dependencies and build steps are in [Android README](../android/README.md).
