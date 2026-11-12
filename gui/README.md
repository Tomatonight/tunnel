Tunnel 图形界面

Windows、Linux、macOS 桌面窗口采用 pywebview；Android 使用系统 WebView 和 VpnService。
四个平台共用 assets/ 下的本地 HTML/CSS/JS，不加载 CDN，也不开放 HTTP 管理端口。
本版包含：表单配置、JSON 导入/高级编辑、校验/保存，连接/断开，邻居和 ECMP 路径、会话与计数，日志筛选/复制/清空。
桌面启动器保留远程桌面入口：Tunnel 负责虚拟网络、节点认证和路由，GUI 调用已安装的 RustDesk 负责画面、编码、鼠标键盘和全屏。旧版 RFB/noVNC 代码保留为兼容回退，主界面不再依赖它。需要只运行基础隧道时，可显式加入 `--basic-mode`；该模式会隐藏远程桌面页面并直接管理核心，不启动远控 Runtime 或本地 IPC。
“运行中”表示本机核心已启动；邻居是否已认证连接，要查看邻居列表。
PSK 在表单中默认隐藏，可以显示、生成或复制；高级 JSON 中保留完整配置。运行日志会遮盖已知 PSK。

简单配置
填写本机绑定 IP，添加本机虚拟 IP/前缀（例如 10.1.0.2/24），再添加对端 IP 和 PSK。主隧道控制与数据默认共用端口 65535；需要时仍可写成 IP:端口。节点身份按每个虚拟网络的 tunnel_ip 区分。
每个节点可选择“数据封装”：默认 TCP；只有需要 UDP 时才选择 UDP。任一端选择 TCP 且双方配置支持时使用 TCP，不会自动回退到 UDP。
TCP 数据与控制消息共用已认证的 TLS 连接；丢包重传可能阻塞后续数据。UDP 模式不因连通失败自动切换 TCP。
概览的“数据封装”列显示已连接节点实际协商的 UDP/TCP；连接前显示请求的封装。运行时更改封装会重连对应邻接，其他节点保持原封装。
每个本机网络只填写一次。只有一个网络时自动关联；多个网络时勾选每个对端允许通信的网络。
给本机新增网络不会自动给已有对端授权；移除网络后没有有效授权的对端需要修正或删除。
生成密钥使用 OpenSSL 的 32 字节随机数；同一对节点使用相同的生成结果，不能两边各自生成。
高级设置保留设备后端、入站开关、入站网络限制、绑定地址、MTU 和 JSON 编辑，默认参数不必填写。
隧道设备可选择“平台默认”“TUN”或“Linux 内核设备”。平台默认在 Linux 使用 kernel，其他平台（含 Android）使用 TUN。
On Linux, build and load the tunnel_kmod module first; see [development.md](../docs/development.md). You can explicitly select TUN when the module is unavailable.
导入未写 device_backend 时表单保持“平台默认”；明确的 tun/kernel 原样保留，保存后核心会写出并显示实际后端，避免跨平台复制时改变选择。
内核后端的 UDP 数据在内核处理，TCP 沿用用户态 TLS；切换后端会重建设备与连接。
非 Linux 平台可以查看/编辑该字段，但选择内核后端启动会明确报错，不会自动回退。导入及保存保持原选择。
编辑 JSON 后先点“应用到表单”；未应用的 JSON 不会被旧表单默默覆盖或忽略。
配置只接受当前 JSON schema；无效配置原文保留供修改。

Windows 成品
    build/gui/TunnelUI-live/TunnelUI.exe
    build/gui/TunnelUI-live/TunnelCtl.exe
现有成品保留 2026-10-16 的 TCP 封装版本。2026-10-19 内核设备后端本轮未重新打包 Windows GUI/CLI；新后端选择界面请使用下方源码入口。
TunnelCtl提供独立命令行配置，与界面共用配置目录和后台。例如：
    TunnelCtl.exe config show
    TunnelCtl.exe config set /tun_mtu 1300
    TunnelCtl.exe config apply node.json
    TunnelCtl.exe config reload
See the packaged CLI-README.md or the repository [CLI guide](../docs/cli.md) for complete commands.
保留整个 TunnelUI 文件夹（包括 _internal、核心程序、DLL 和许可证），不要只复制 EXE。
窗口请求管理员权限以创建 Wintun。电脑需要 Microsoft Edge WebView2 Runtime。
首次打开载入仓库示例，必须按实际节点修改地址和 shared_key 后连接。关闭“接受对端主动建立 TCP 连接”后可只主动连接已配置节点，并省略本机绑定地址；开启监听时可填写具体地址或 `0.0.0.0:端口`/`[::]:端口` 绑定所有网卡。高级设置中的监听共享密钥可让持钥节点直接建立入站邻接，无需在本机逐一添加 peer；入站网络仍按监听网络授权限制。
默认关闭窗口会停止后台与核心；关闭窗口不会保留远程桌面后台连接。
界面的“断开网络”始终停止后台、核心和远控会话。关闭控制端窗口也会断开其正在查看的桌面，释放远端按键。
核心 stdin 由独立后台持有；后台退出或管道 EOF 才通知核心停止，GUI 的关闭不再直接关闭核心管道。

源码启动（Python 3.10+；先构建当前平台的 tunnel 核心）
    python -m pip install -r gui/requirements.txt
    python gui/main.py --binary build-reload/tunnel.exe

本轮新核心分别位于 build-reload/tunnel.exe 和 build-wsl-reload/tunnel；务必显式传入 --binary。
未传时源码仍查找 build/tunnel[.exe]，本工作区旧产物保留供既有手工远控测试使用，不代表本轮新版本。

Linux 安装桌面后端，例如 Ubuntu 的 python3-gi、python3-gi-cairo、gir1.2-gtk-3.0、
gir1.2-webkit2-4.1 和 python3-venv；Python 环境必须能够导入系统 gi。
    python3 -m venv --system-site-packages .venv-gui
    .venv-gui/bin/python -m pip install -r gui/requirements.txt
也可使用 pywebview 的 Qt 后端并按官方文档安装对应依赖。
    .venv-gui/bin/python gui/main.py --binary build-wsl-reload/tunnel
连接时核心需要 root/CAP_NET_ADMIN 权限；配置校验不需要。
开发阶段可以在有显示会话和权限的终端启动宿主。Linux/macOS 本版未实现独立提权服务。
Linux 日志复制需要 wl-clipboard 或 xclip；中文显示需要可用的中文系统字体。
本工作区已安装 WSLg 的 GTK/WebKit，隔离 Python 环境为 build-wsl/gui-venv。
从 WSL 有显示会话的终端运行（推荐使用仓库根目录的 `run-gui.sh`）：
    bash run-gui.sh
Linux 先执行仓库根目录的 `bash build.sh`，再运行 `bash run-gui.sh`；核心没有 `CAP_NET_ADMIN` 时，脚本会直接提示执行 `sudo bash run-gui.sh`，不会在后台弹出密码请求。以 sudo 启动时脚本设置文件能力后切回桌面用户运行 WebView，避免窗口卡在“正在启动”。Wayland 会自动切换到当前桌面的 XWayland 显示。使用 `device_backend=kernel` 时，还需预先为当前内核安装模块和设备权限。Windows 先执行 `build.bat --gui`，再使用 `run-gui.bat`/`.vbs` 无黑框启动并保留远程桌面功能。
构建脚本会同时准备 RustDesk：Linux 自动安装官方 `.deb`，Windows `build.bat --gui` 优先使用 winget，找不到 winget 包时下载官方便携版。离线或只构建核心可加入 `--skip-rustdesk`。
macOS 使用 Cocoa/WKWebView 后端；系统权限还必须允许核心配置 utun 和路由。

启动脚本会先清理当前 `TUNNEL` 目录下残留的 GUI、后台宿主和核心进程，再启动新实例。需要手动退出时可运行 `stop-gui.sh`（Linux）或 `stop-gui.bat`（Windows）；脚本只匹配当前项目目录，不会结束其他目录的 Tunnel。
    python3 gui/main.py --binary build/tunnel
依赖安装说明：https://pywebview.flowrl.com/guide/installation.html

自动 IP 分配（可选）
普通手动配置不变。需要统一管理地址时，展开“提供 IP 分配服务”，启用服务并填写服务 endpoint、接入密钥和地址池。
默认共享一把 address_server.shared_key；所有持钥节点均可申请全部地址池，不需要填写客户端列表。
共享模式不能单独撤销一个节点，持钥者也能使用其他节点的 endpoint。需要按节点限制时，在服务高级设置中明确切换到逐节点授权。
逐节点授权保留各节点的密钥和地址池限制；shared_key 与 clients 两种模式互斥。
服务使用独立 TCP 地址；同一机器与隧道监听共存时使用不同端口。改变授权方式只修改当前表单，保存或重新连接后才生效。
“仅提供分配服务”只保存 address_server，不创建 TUN；高端口独立服务本身不需要创建虚拟网卡的权限。
共享模式新增的地址池对所有持钥节点开放；逐节点模式新增池不会自动授权给已有节点。地址池不会使服务端自动加入对应虚拟网络。
共享模式下填写“客户端绑定地址”后导出接入配置；该地址只用于导出，不保存到服务配置。导出包含接入密钥和所有地址池。
逐节点模式仍可从对应节点卡片导出，只包含该节点的密钥及授权池。复制完整客户端 JSON，交给对应节点。
客户端在“自动获取虚拟 IP”中导入这份 JSON，也可直接填写分配服务地址、密钥和申请网段。
导入可明确选择合并或替换：合并保留现有静态地址、peer、监听设置和授权，不会覆盖已有不同密钥；绑定地址不一致时拒绝合并。
替换会先确认，再替换整个当前配置。导入后仍需保存或连接；分配服务不会代替 peer 连接配置。
自动申请的网段参与 peer 和入站网络授权；新增网段不会扩大已有 peer 的权限。静态网络与自动申请网段不能重叠。
“IP 地址分配”概览分别显示等待、连接、已取得地址、各池失败原因，以及服务端在线/离线保留的绑定记录。
部分地址池成功时显示“部分地址已分配”；核心运行不等于已拿到全部地址或 TUN 已就绪。设备或地址安装失败会在顶部提示。
服务默认在节点离线 86400 秒后允许回收地址；state_file 默认 address-leases.json。
桌面启动时只在私有运行快照中将相对 state_file 解析到以下持久配置目录，使地址绑定位置不随运行快照改变。
保存的配置继续保留相对路径；已分配记录跨核心/窗口重启保留。服务、客户端和 peer 的 PSK 均纳入日志脱敏。

发布与访问内网（可选）
在连接配置中展开“发布内网”，选择本机已加入的虚拟网络，再填写本机后方的内网网段，例如 192.168.10.0/24。
所属虚拟网络既可以是静态地址网络，也可以是自动分配地址的网络。发布前缀应为规范网段地址，与所属网络使用同一 IP 版本。
配置写为 advertise_routes: [{"tunnel":"10.1.0.0/16","prefix":"10.2.0.0/16","snat":true}]；未启用 SNAT 时省略 snat 字段（仍保留发布项）。
发布网段不能覆盖虚拟网络地址段，也不能与另一虚拟网络发布的网段重叠；不符合规则的配置不会覆盖已保存文件。
SNAT 默认关闭，内网需要有返回虚拟网络的路由。开启后由系统完成源地址转换，内网设备看到发布节点的地址。
多个节点发布同一内网时自动选择入口并在故障后切换，界面无需配置优先级或选举参数。
“内网访问”概览分别列出本机发布状态、当前入口和具体错误。系统能力或权限不足时显示失败，程序正在运行不代表发布已成功。
Android 只作为访问端，不支持发布内网；已导入的发布项保持可见，可明确移除后保存。新增虚拟网络不会扩大已有 peer 的授权。
examples/subnet-gateway.json 与 subnet-client.json 提供配对示例；先替换 endpoint 和双方共享密钥，并将发布网段改为实际可访问的内网。
真实 Linux 子网回归 tests/subnet_network_integration.py 使用独立命名空间验证两级转发、双出口切换、SNAT 与无 SNAT 的 TCP/UDP/ICMP、返回流量限制及 IPv6 路由。

远程桌面（Windows、Linux、macOS 桌面宿主）
两端先安装 RustDesk，在 RustDesk 设置中启用直连 IP；Tunnel 两端配置相同的 peer 密钥、虚拟 IP 和网段，确认虚拟 IP 互通。
控制端在“远程桌面”页选择共同虚拟网络，填写对端虚拟 IP，点击“用 RustDesk 打开”。RustDesk 密码由 RustDesk 自己管理，可以留空让客户端提示；RustDesk 的全屏、画质、鼠标和键盘也由客户端负责。
GUI 只允许启动所选 Tunnel 网络中的虚拟 IP，不接受 RustDesk ID，避免绕过 Tunnel 的节点认证和路由。
远控配置不再支持设备授权名单、批准请求或无人值守开关；旧配置中的这些字段必须删除后才能导入。
运行中“保存并应用”会同时应用当前表单的全部配置，包括远控策略和网络配置。节点增删及密钥修改只影响相关连接；虚拟网络、监听、MTU 等资源变更可能短暂重连。应用失败会显示原因并保留编辑内容，不宣称已保存生效。
本版支持已登录桌面的单屏操作。GUI 可运行在 Linux Wayland，但屏幕采集和输入后端仍要求 X11。macOS 需首次本机授予屏幕录制和辅助功能权限。
尚未实现系统开机服务、登录界面、UAC/锁屏安全桌面、音频、剪贴板与文件传输。关闭 GUI 会停止后台，重启后需要重新启动应用。
远控预共享密钥独立于 peer 的 PSK；加入隧道后仍必须提供正确的远控密钥，才能建立桌面会话。
协议、身份文件、后台命令行和具体平台边界见 ../remote_desktop/README.md。

配置存储位置
源码运行或打包运行时，`configure.json` 和 `background/configure.json` 默认保存在
Tunnel 应用/项目目录中，也就是本仓库的 `TUNNEL` 文件夹。可用 `--config-dir PATH`
指定独立配置目录；POSIX 下新配置文件权限为 0600。
保存通过核心 --normalize-config 校验并转成新格式；错误配置不会覆盖已保存文件。
加载配置只转换返回给界面的文本，不修改原文件；显式保存或连接才写入规范格式。
运行期间保存的全部配置即时应用；无需先手动断开。核心按照配置差异更新节点或重建网络资源，界面会提示重连；只有保存配置尚未启动服务时，才在下次连接生效。
运行配置应用成功后才提交用户保存文件；提交失败会尝试恢复原运行配置，回滚失败会明确报告。界面和命令行共享配置应用入口，同一配置目录的保存操作串行执行。
如果另一窗口或命令行已修改保存文件，界面会拒绝覆盖并保留当前编辑；先重新载入，再合并需要保留的修改。
后台使用持久目录中的 background/configure.json 运行快照与 background/status.json 状态文件；应用重新启动后会读取当前配置并重新建立后台。
界面保留最近 500 条日志，包含核心输出和远控事件。核心输出保存在 remote-core.log，后台诊断写入 desktop-host.log；关闭界面不会删除这些文件。
“清空日志”只清除当前界面记录，不删除磁盘日志。日志和身份文件应与配置一样保存在用户私有目录。

Windows 重新打包（在 Windows 上执行）
    python -m pip install -r gui/requirements.txt pyinstaller
    python gui/build_windows.py --core-dir build-reload
要求 build-reload/ 中已有 tunnel.exe、依赖 DLL、wintun.dll 和 WINTUN-LICENSE.txt。
构建会收集 remote_desktop、cryptography、mss、Pillow 及 GUI 依赖，并将桌面主控/被控示例一并放入 examples/。
依赖和许可证需随分发保留；此目录是本地开发产物，尚未代码签名。

Android
见 ../android/README.md。Gradle 直接打包共享 assets，宿主通过 JNI 控制同一个协议线程。
退出 Activity 不停止 VPN；使用界面的断开按钮或系统撤销 VPN 授权停止。
应用私有目录保存配置；导入使用系统文件选择器；VPN 需要系统授权，不要求 root。
Android 本版没有远程桌面控制端或被控端，页面明确显示不支持并禁用连接与本机服务开关。
导入启用被控服务的配置时保留其字段，阻止保存/连接，并提供“移除本机远控配置”按钮；不会静默忽略启用设置。

开发与验证
用户态控制面仍是单协议线程。TUN 后端的 UDP socket 属于用户态；Linux 默认内核后端的 UDP socket 和数据处理属于内核，会话由实例锁保护。
屏幕采集、编码、输入和 GUI 在独立 Python 宿主进程/线程运行。
--stdio-control 仅接受管道 stdin；STOP 换行或 EOF 正常停止，并接受受限的 remote_info/remote_sign/remote_verify JSON RPC。未指定参数则不读取 stdin。
浏览器只调用带初始页面随机令牌的本机桥接。Python GUI 与独立后台通过 127.0.0.1 随机端口 IPC 通信，使用私有随机密钥的双向 HMAC 挑战。
后台发现文件 desktop-host.json 包含认证凭据，不能分享；不运行 HTTP 管理服务器，也不把 IPC 密钥暴露给页面。
桌面桥接仅接受初始页面的随机令牌；Android 仅加载受限本地资源，禁止外部导航和请求。
配置和日志通过文本控件呈现，不解释为 HTML。
打包后的窗口/桥接/核心校验自检，不建立连接：
    TunnelUI.exe --check-ui ui-check.json

    python tests/gui_host_test.py --binary build-reload/tunnel.exe
    python tests/gui_host_test.py --binary build-reload/tunnel.exe --live
    python tests/gui_window_smoke.py --binary build-reload/tunnel.exe
    python tests/gui_package_test.py --package build/gui/TunnelUI-live
打包后台检查使用隔离的 loopback 地址分配服务，验证冻结程序后台入口、持久身份、重新接回、策略更新与停止，不创建 TUN 或操作屏幕输入。
--live 和窗口测试会临时创建 198.18.253.0/30 的 TUN；需要权限且该网段不应已被占用。
The browser regression is tests/gui_frontend_test.js; platform results are listed in [test-results.md](../docs/test-results.md).
macOS 和 Android 当前只有源代码/静态检查，仍需在目标环境构建及验证生命周期。
Windows WebView2 和 WSLg GTK/WebKit 窗口已通过真实 TUN 启停与状态测试。
