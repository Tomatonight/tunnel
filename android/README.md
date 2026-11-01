Android 工程

最低 API 26，目标 API 36；arm64-v8a 和 x86_64；JDK 17、Gradle 8.13、AGP 8.13.0、
NDK 27.2.12479018、CMake 3.22.1。可用 Android Studio 打开本目录。

依赖必须是 Android NDK 构建的静态 OpenSSL 3.x 和 libevent，不能使用 Windows/Linux 桌面库。
每个 ABI 的目录布局为：
    android-deps/arm64-v8a/include/openssl/...
    android-deps/arm64-v8a/include/event2/...
    android-deps/arm64-v8a/lib/libssl.a
    android-deps/arm64-v8a/lib/libcrypto.a
    android-deps/arm64-v8a/lib/libevent_core.a
x86_64 同样布局。依赖也需 PIC，NDK 27 使用 16 KB 页兼容设置。
可使用 tools/build_android_deps.sh 从已下载的 OpenSSL/libevent 源码构建。

构建：
    gradle -p android -PtunnelDeps=/absolute/path/to/android-deps assembleDebug

安装 app/build/outputs/apk/debug/app-debug.apk；导入与桌面相同的 JSON 配置，再点击连接并授予系统 VPN 权限。
四个平台共用 gui/assets 中的界面：配置编辑/导入/校验/保存、连接/断开、节点与路径状态、计数和日志。
配置表单支持节点地址、虚拟网络和 peer；可为每个 peer 生成独立的 32 字节随机预共享密钥（64 位十六进制文本）。
规范配置将公布 address 放在根对象；networks 使用本机 IP/前缀字符串（如 10.1.0.2/24），
peer.networks 使用子网引用，单一虚拟网络时可省略；listen 为可选对象，MTU 可使用核心默认值。
peer.transport可选择udp（默认）或tcp，表单提供同一选项。TCP数据复用受保护的TLS连接，
保留端到端加密与原MTU预算，不依赖UDP探测；两端程序需支持TCP封装，任一端选择即可协商。
导入旧版配置时由同一个 C++ 解析器转为规范格式，仅在界面中转换，不自动覆写磁盘。
无法解析的已存配置仍返回原文本和错误说明供修复；保存或连接时才校验并写入规范格式。
Gradle 从仓库的 gui/assets 打包 index.html、app.css、app.js，不依赖远程网页，也不另开 HTTP 服务。
Android 原生宿主使用受限 WebView 和 VpnService；Android 系统线程不参与协议处理。
Android本机仍需配置固定公布地址；UDP模式要求TCP/UDP可达，TCP模式要求可建立TCP连接。
本版不提供NAT穿透或移动公网端点学习。
配置保存在应用私有目录，不备份；通知和日志不输出 PSK。
日志保留最近 256 条（每条最多 2048 字符），运行状态每 500 毫秒从协议线程发布一次快照。
关闭界面不会断开已经启动的 VPN；再次打开可查看同一服务的状态与日志。
拒绝或撤销授权、启动失败、停止过程会在界面中显示；运行时点击“保存并应用”即可热加载配置。
修改peer时仅重建地址、密钥、数据封装或网络授权发生变化的邻接，未修改的连接保留。
修改公布/监听地址、网络、MTU、地址分配设置等网络资源时，在原进程内重建核心资源，身份密钥保留，连接可能短暂中断。
修改 MTU 后，当前接口和随后租约/路由更新建立的替代接口均使用新 MTU。
无变化的配置不重建资源；校验或应用失败时保留原配置。资源重建失败会尝试恢复旧资源，恢复失败会明确显示错误。
配置文件先暂存，协议线程确认成功后才原子替换；若写入失败则请求恢复原运行配置，并报告恢复结果。
启动/停止期间拒绝应用新配置，待该操作完成后重试；停止状态只保存，下次连接时生效。
TCP/UDP 默认每 5 秒保活；任一通道 20 秒未验证活动即撤回邻接，与桌面核心相同。

只有 TunnelProtocol 线程运行 C++ 协议和 libevent；Android UI/系统网络回调通过非阻塞管道通知停止、重连或应用配置。
热加载请求以有界队列传递标准 UTF-8 文本；JNI 仅入队，Node::apply_config 和 TUN 重建都在原协议线程执行。
WebView 桥线程等待独立请求结果时不持有 service gate，也不阻塞 Android 主线程；停止/撤销授权会拒绝未完成请求。
VpnService 为已有静态地址或有效租约的虚拟网络配置地址和路由，并转移 TUN fd 所有权给 C++；所有 TCP/UDP socket 都调用 protect，包括地址分配服务连接。
仅配置动态地址的客户端可以先运行地址分配连接，等待首个有效租约时不创建占位 TUN，也不通告未分配的网络。
有效地址集合改变时，协议线程同步调用 VpnService.Builder 建立替代接口；成功后切换事件注册、关闭旧 fd，Node 和 peer 会话保留。
重建使用全部仍有效的网络，保证撤回一个网络时保留其他网络；空集合关闭 TUN。相同集合（含仅顺序变化）不重建。
Android 系统以替代接口实现地址变更，切换期间可能短暂丢包；建立失败则关闭旧 TUN 并停止全部 overlay 收发，状态显示 device_error，需手动断开重连恢复。
单独的 address_server 配置可运行分配服务而不建立 TUN；地址服务仍使用同一协议线程。
共享接入模式只需 address_server.shared_key 和地址池，无需 clients 名单；客户端使用相同服务密钥，peer 密钥另行配置。旧逐节点授权模式仍可导入和使用。
Android 将 address_server.state_file 的文件名映射到应用私有 files/address-state 目录，导入桌面绝对路径也不写出该目录；保存的配置文本保持原路径。
私有租约状态随应用数据保留，用于重启后恢复分配；清除应用数据或卸载将同时删除配置与租约记录。
停止、撤销授权及网络切换均通过协议线程处理；切换网络不重新生成进程身份密钥。
默认接管配置中的虚拟网段，以及核心确认有效的远端通告子网；不支持 Always-on 自动启动，公布地址变化后可保存并应用新配置。
Android 只作为通告子网的访问端：advertise_routes 非空会在配置校验和启动前被拒绝，出口和 SNAT 应配置在桌面网关。
导入子网变动通过完整 DeviceUpdate(networks,routes) 重建同一个 VpnService 接口；删除路由保留其他地址和路由。
导入路由不得覆盖配置中的公网控制端点、虚拟网段或当前底层网络地址；网络切换仍通过控制管道通知核心重连。
VpnService 没有按路由指定源地址的 API：导入子网时，同一地址族只允许一个有效 tunnel 地址；IPv4 与 IPv6 各一个可以并存。
出现同地址族多个有效地址时，导入操作会明确失败并关闭 TUN，避免安装源地址不确定的路由；需调整配置后重新连接。

界面隔离与桥接：
    页面来源固定为 https://tunnel.local/index.html；只拦截并返回三个打包资源。
    外部导航、网络加载、任意 file/content URL、混合内容、iframe 和内联脚本均禁用。
    文件导入只接收系统 ACTION_OPEN_DOCUMENT 用户选择的 content URI；作为 FileReader 文本读取，不加载为网页。
    window.TunnelHost.request(JSON.stringify({action, payload})) 同步返回 JSON 字符串。
    成功为 {ok:true,data:...}，失败为 {ok:false,error:...}。
    动作：load_config、normalize_config、generate_key、validate_config、save_config、reload_config、start、stop、get_state、clear_logs、copy_text。
    normalize_config/validate_config/save_config/reload_config/start 的 payload 为 {text:配置文本}，copy_text 为 {text:待复制文本}。
    normalize_config 返回 {text:规范 JSON}；generate_key 无需 payload 字段，返回 {key:64位十六进制密钥}。
    load_config 返回 {text:规范 JSON}；文件为空则 text 为空字符串，文件无效则返回 {text:原文本,error:错误说明}；不修改磁盘。
    save_config/reload_config/start 接受新旧两种配置，均由核心规范化后保存；本次启动使用规范化文本的独立快照。
    save_config 与 reload_config 等效；运行时成功返回 {saved:true,applied:true,text,message,mode,interrupted,...}。
    mode 为 noop / remote / peers / rebuild；停止状态返回 applied:false，没有运行结果字段。
    应用失败返回 {ok:false,error}，磁盘配置不更新，编辑器保留未保存的内容。
    load_config/save_config/start 返回 revision（已保存文件的 SHA-256，不存在时为 null）。
    保存/启动可携带 expected_sha256；与当前文件不符时拒绝覆盖，需重新载入后再操作。
    配置输入和规范输出上限均为 1 MiB，JNI 使用标准 UTF-8 byte[] 传递配置，支持非 ASCII PSK。
    随机密钥使用 OpenSSL RAND_bytes；日志和错误会遮盖已识别的 peer、address_clients、address_server.shared_key、address_server.clients PSK，密钥仅通过生成/配置 API 显式返回。
    get_state 返回 phase、error、status、logs、config_path、platform、status_stale；status 为 Node.status() 的脱离线程快照。
    status_stale 使用单调时钟，仅有效协议快照更新计时；运行期间超过 3 秒未更新即显示过期，界面轮询不会刷新此计时。
    phase 为 stopped / starting / running / stopping / error，running 表示核心运行，并不表示所有 peer 均在线。
    日志项为 {id,time,level,message}，time 为 Unix 毫秒时间戳。
    JS 桥不提供命令执行、任意文件路径读写或任意 URL 加载。

此工作区缺少 Android SDK/NDK、JDK 和设备，尚未完成 APK 编译和 Android 实机验证。
需在目标设备验证：WebView 页面和文件导入、授权拒绝/撤销、旋转/关闭界面、状态/日志刷新、
通知权限、切换 Wi-Fi/移动网络、后台运行、停止后 fd 释放、IPv4/IPv6 和 MTU。
动态地址还需真机验证：等待首个租约、增加/撤回单网段时其他网段继续通信、租约失效关闭 TUN、Builder 失败的 device_error，以及重连后恢复。
子网访问还需真机验证：通告添加/撤回后的路由刷新、源地址选择、IPv4/IPv6、底层网络重叠拒绝，以及所有 TCP/UDP 控制 socket 持续绕过 VPN。
热加载还需真机验证：peer 增删/改密钥时未修改连接保持、MTU 与地址修改后 Builder 替换、地址服务器状态路径隔离、
重建失败恢复、保存文件失败恢复、与停止/撤销 VPN 授权并发、界面旋转和关闭时结果处理。

参考：
https://developer.android.com/develop/connectivity/vpn
https://developer.android.com/reference/android/net/VpnService.Builder
https://developer.android.com/build/releases/agp-8-13-0-release-notes
https://developer.android.com/develop/ui/views/layout/webapps/load-local-content
