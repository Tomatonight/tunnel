远程桌面

当前 GUI 的远程桌面入口使用已安装的 RustDesk。Tunnel 只负责虚拟网络、节点认证和路由；RustDesk 负责屏幕采集、编码、鼠标键盘和全屏。旧的 RFB/noVNC 实现仍保留在源码中，作为升级期间的兼容回退，但不再是 GUI 的主入口。
Android 当前只提供隧道配置/访问功能，不提供桌面控制或被控后端。

## RustDesk 集成

GUI 可以调用已安装的 RustDesk 客户端。GUI 运行时不下载程序，按 `TUNNEL_RUSTDESK_BIN`、`third_party/rustdesk/rustdesk`、`.deps/rustdesk` 或系统 PATH 顺序查找客户端。未安装时，按钮会保持禁用。

构建脚本会准备客户端：Linux/Ubuntu 的 `bash build.sh` 自动安装官方 x86_64/aarch64 `.deb`，Windows 的 `build.bat --gui` 优先使用 winget，找不到包时下载官方便携版到 `.deps/rustdesk`。已有 RustDesk 会跳过下载，但会通过 RustDesk 的管理选项启用直连 IP 和 21118 端口；离线或只构建核心时使用 `--skip-rustdesk`。

RustDesk 入口只接受对端 Tunnel 虚拟 IP，并要求先连接 Tunnel、选择包含该 IP 的虚拟网络。请在 RustDesk 的设置中启用直连 IP；直连端口使用 RustDesk 默认的 21118。开启 Tunnel 配置中的 `remote_desktop.enabled` 后，构建脚本和 `run-gui.sh` 会以服务权限同步 `remote_desktop.shared_key`，GUI 会自动启动被控端，连接按密码接受，不需要对端点击批准。控制端可以复用同一密钥，也可以留空让 RustDesk 提示。
点击连接前 GUI 会先从 Tunnel 虚拟网络探测 `IP:21118`；探测失败会提示检查对端 Tunnel、直连 IP 和路由，不再只显示 RustDesk 的通用“请稍后再试”。

RustDesk 进程由 GUI 以参数列表启动，不经过 shell；GUI 关闭时只清理本次 GUI 启动的 RustDesk 子进程，不会误杀用户手动启动的其他 RustDesk 实例。
旧版 RFB 网关仍可由兼容代码调用，便于已有配置平滑升级；新配置和主界面不再依赖它。
noVNC 资源及 MPL-2.0 许可说明位于 `gui/assets/novnc.js` 和 `third_party/novnc-LICENSE.txt`。

界面使用

1. 在两端安装 RustDesk，并在 RustDesk 设置中启用直连 IP。Tunnel 两端使用相同的 peer PSK，分别配置各自的虚拟 IP 和共同网段。
2. 启动 Tunnel GUI，勾选“开启本机远程桌面”并填写预共享密钥，保存后连接网络；GUI 会自动配置 RustDesk 被控端，无需再点击允许控制。
3. 控制端在“远程桌面”页选择同一虚拟网络，填写被控端虚拟 IP，点击“用 RustDesk 打开”。控制端密码可以留空让 RustDesk 提示，也可以填写与被控端相同的预共享密钥。
4. RustDesk 的全屏、画质、鼠标和键盘由 RustDesk 客户端负责；Tunnel GUI 只负责启动客户端并维护 Tunnel 连接。

兼容 RFB 网关仍使用 Tight JPEG、输入队列和 60 FPS 节流，供旧版配置或回退测试使用；它不影响 RustDesk 主路径，也不会被 RustDesk 连接自动启动。

身份与成员验证

Tunnel 仍使用自己的 peer 共享密钥、成员证明和虚拟 IP 路由；RustDesk 只会被 GUI 指向已选择 Tunnel 网络中的虚拟 IP。
RustDesk 的设备身份和桌面密码由 RustDesk 自己管理，不写入 Tunnel 配置，也不替代 Tunnel 的节点认证。

后台与命令行

桌面界面通过独立Python后台进程管理核心与远控服务。关闭界面会停止后台、隧道和远控服务；
控制端窗口关闭会断开其正在查看的远控。
后台在当前登录用户的图形会话中运行。本版不自动安装系统开机服务，不提供尚未登录时的远程登录能力。
首次macOS部署仍须在系统设置授予屏幕录制和辅助功能权限；GUI会显示权限错误。

从源码安装依赖：
    python -m pip install -r gui/requirements.txt
GUI启动：
    python gui/main.py --binary build/tunnel.exe
独立后台（Linux示例，在具有DISPLAY的登录会话中运行；TUN需要对应权限）：
    python -m remote_desktop.daemon --binary build-wsl/tunnel --config examples/desktop-host.json --state-dir /path/to/private-state --status-file /path/to/private-state/status.json
macOS同理使用该平台编译的tunnel；Windows可使用build/tunnel.exe。
直接运行C++ tunnel只启动隧道和成员证明接口，不启动Python屏幕服务；远控应由GUI或上述daemon启动。

状态目录只允许当前用户访问，Windows额外保留SYSTEM权限；后台实例锁阻止同目录重复运行。
desktop-host.json仅供本机Python宿主发现后台IPC，包含随机认证凭据，不应分享。
本机IPC仅监听127.0.0.1随机端口，使用随机密钥的双向HMAC挑战；浏览器不能直接访问，不运行HTTP服务器。
后台日志为remote-core.log/desktop-host.log，核心状态为GUI目录下background/status.json。
GUI保存整份配置后即时应用。Peer差异保留未变化邻接；网络/MTU/监听/地址服务等变更在原进程重建资源并重连，进程身份密钥不变。
远控策略变更会撤销旧桌面会话；网络重建也可能中断桌面连接。无变化的保存不重建资源。
Use python -m tools.tunnel_cli for headless configuration. The Windows package includes TunnelCtl.exe; the GUI and CLI share the same profile directory. See the [CLI guide](../docs/cli.md).

验证

    python tests/remote_runtime_test.py
    python tests/remote_platform_test.py
    python tests/remote_platform_test.py --live-capture
    python tests/remote_stdio_test.py --binary build/tunnel.exe
Linux隔离真实键鼠（需要Xvfb、libXtst；不会操作当前用户桌面）：
    python tests/remote_platform_test.py --xvfb
真实双节点TUN+TLS+Xvfb（root，需要iproute2、Xvfb、libXtst及Python依赖）：
    sudo python tests/remote_network_integration.py --binary build-wsl/tunnel
Use [test-results.md](../docs/test-results.md) for platform validation; macOS source checks are not hardware validation.
