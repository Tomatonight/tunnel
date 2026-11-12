# Tunnel

一个跨平台三层加密组网工具，支持多跳转发、UDP/TCP 数据封装、图形界面与命令行管理，并提供 Linux 内核数据后端。

## UI 示例

以下为当前界面使用示例数据渲染的截图，展示连接状态、节点和流量统计。

![Tunnel UI：连接概览](docs/images/ui-overview.png)

查看 [完整 UI 使用示例](docs/ui-example.md)，包含配置、日志截图和两节点操作步骤。可导入 [节点 A](examples/ui-node-a.json) / [节点 B](examples/ui-node-b.json) 配置开始体验。

## 功能

- **虚拟网络**：IPv4/IPv6、单设备多地址、多个不重叠网段、按 peer 授权。
- **加密通信**：TLS 1.3 与每对 peer 的预共享密钥（PSK）认证；单播端到端 AES-256-GCM 加密，以及链路逐跳保护。
- **多跳与选路**：路径通告和撤回、按跳数 ECMP、单播按流选择下一跳、故障重连；广播/组播使用 RPF 检查和跳数限制。
- **传输选择**：默认 TCP，可按 peer 选择 UDP；TCP 数据复用已认证的 TLS 控制连接。
- **地址与内网**：可选独立地址分配服务、持久租约与离线回收；内网网段发布、主备出口及系统 SNAT。
- **管理**：配置、连接状态、日志界面；命令行编辑、运行状态查询与配置热加载。
- **远程桌面**：Tunnel 提供已认证的虚拟网络和路由，GUI 调用 RustDesk 提供屏幕采集、编码、键鼠和全屏；旧 RFB/noVNC 代码仅保留兼容回退。
- **Linux 内核后端**：自定义三层 `net_device`，UDP 数据封装、加解密与转发在内核完成；控制面及 TCP/TLS 通道保留用户态。

项目采用 C++11、libevent 和 OpenSSL 3.x。桌面界面使用 Python/pywebview，Android 宿主使用 WebView、VpnService 和 JNI。
## Layout and build

Directory layout is intentionally small: `src/` contains the cross-platform C++ core; `config/` contains the repository default configuration; `examples/` contains sample node profiles; `gui/`, `remote_desktop/`, `android/`, and `kernel/` contain platform or feature code; `tests/` contains automated tests; `tools/` contains development utilities; `third_party/` contains bundled runtime dependencies; `docs/` contains documentation; and `build/` contains generated files only.

On Windows, double-click `build.bat`. On Linux or macOS, run `./build.sh`. The script compiles and links everything with the system C++ compiler driver (`g++`/`clang++`) directly -- CMake and Ninja are not required -- and builds a Release core; add `--tests` to build and run the native test suite in the same invocation. Add `--build-type Debug` for a debug build and `--gui` on Windows to package the desktop application under `build/gui/TunnelUI-live/`.

On Windows, run `build.bat --gui` once, then double-click `run-gui.vbs` or `run-gui.bat` to start the packaged desktop UI without opening a console window. The first launch may show a standard UAC prompt because the TUN adapter requires administrator rights; approve it to open the GUI. On Linux and macOS, run `./build.sh` first, then use `./run-gui.sh`. If the Linux core has no TUN capability, run `sudo bash run-gui.sh` once; the launcher grants the capability and opens the WebView as the desktop user. The normal user path never starts a hidden sudo password prompt. Run the command-line manager with `run-cli.bat` or `./run-cli.sh`; arguments after the script are passed to the CLI, for example `./run-cli.sh status`.

The three GUI entry scripts are thin wrappers around `tools/launch_gui.py`, which owns package discovery, desktop-session setup, Linux capability handling, UAC elevation, and argument forwarding.

The same entry point is available everywhere:

```bash
python3 scripts/build.py
python3 scripts/build.py --clean
python3 scripts/build.py --tests --skip-gui-deps --skip-kernel-module
```

The default build compiles the core without test targets. Use `--tests` when
you want the native test executables built and executed as part of the same
command; `--skip-gui-deps` and `--skip-kernel-module` keep that check usable on
machines that only have the core toolchain installed.

Android continues to use Gradle from `android/`; the Linux kernel module continues to use `tools/build_kernel.py`. These platform builds keep their own outputs and do not reuse the compiler object cache.

## 平台与当前边界

| 平台 | 网络设备 | 验证状态 |
| --- | --- | --- |
| Linux / WSL | 默认 `kernel`，可显式选择 `/dev/net/tun` | 已完成真实网络、内核模块、TCP/UDP、路由与 SNAT 测试 |
| Windows | Wintun | 已完成与 Linux/WSL 的真实互通测试 |
| macOS | utun | 后端已编写，尚未在目标平台构建和实机验证 |
| Android | VpnService/TUN | 宿主及 JNI 工程已编写，尚未在目标平台构建和实机验证 |

远程桌面主路径由已安装的 RustDesk 客户端负责；Tunnel GUI 只向 RustDesk 传入同一虚拟网络内的对端虚拟 IP。旧 RFB 实现仍可供兼容测试使用。直接启动 C++ 核心只建立隧道，远控需通过桌面界面启动 RustDesk。

本项目面向互信节点组网：路径与公钥传播信任已接入节点如实转发。当前不提供 NAT 穿透、TAP/以太网桥接、重叠虚拟网段、动态 PMTU、隧道分片重组或默认路由接管。内网功能允许隧道节点发起连接及内网设备回包，暂不支持内网设备主动向隧道发起新连接。

## 从源码构建

需要 C++11 编译器命令行工具（`g++` 或 `clang++`）、OpenSSL 3.x 和 libevent core。构建脚本直接调用编译器，不依赖 CMake/Ninja。在仓库根目录执行。Ubuntu/Debian 示例：

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libevent-dev \
    python3 iproute2 iputils-ping nftables

./build.sh                 # 或 python3 scripts/build.py
./build.sh --tests         # 编译并运行原生测试
```

Windows 使用 MinGW-w64 的 `g++`（MSYS2）：

```powershell
winget install MSYS2.MSYS2
# 在 MSYS2 MINGW64 终端中：
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl mingw-w64-x86_64-libevent
build.bat
```

脚本会自动发现编译器（`TUNNEL_CXX` 优先，其次 `PATH`，再次 `C:\msys64\mingw64\bin` 等常见安装目录）和依赖前缀（编译器自身前缀、`TUNNEL_DEPS_ROOT`、`.deps/*`），并把 MinGW/OpenSSL/libevent 的运行库 DLL 复制到 `build/`。运行时需要管理员权限和 `wintun.dll`（已同时复制）。具体平台说明见 [开发说明](docs/development.md)；Android 构建入口见 [Android 文档](android/README.md)。

## 两节点快速开始

先生成一把 PSK，通过可信方式交给另一端；同一对 peer 使用相同密钥：

```bash
./build/tunnel --generate-key
```

以下地址为文档示例，必须替换成实际可达的绑定地址和端口。`networks` 填写本机的虚拟 IP/前缀，两端属于同一虚拟网段但使用不同 IP。

节点 A 保存为 `node-a.json`：

```json
{
  "device_backend": "tun",
  "listen": {"bind_address": "192.0.2.10:65535"},
  "networks": ["10.1.0.1/24"],
  "peers": [
    {
      "endpoint": "192.0.2.20:65535",
      "shared_key": "REPLACE_WITH_THE_GENERATED_SHARED_KEY"
    }
  ]
}
```

节点 B 保存为 `node-b.json`：

```json
{
  "device_backend": "tun",
  "listen": {"bind_address": "192.0.2.20:65535"},
  "networks": ["10.1.0.2/24"],
  "peers": [
    {
      "endpoint": "192.0.2.10:65535",
      "shared_key": "REPLACE_WITH_THE_GENERATED_SHARED_KEY"
    }
  ]
}
```

分别校验并启动，B 端将文件名替换为 `node-b.json`：

```bash
./build/tunnel --check node-a.json
sudo ./build/tunnel node-a.json --watch-config
```

在 A 端执行 `ping 10.1.0.2` 检查连通性。Windows 在管理员终端中使用 `.\build\tunnel.exe`，多配置构建器的程序通常位于 `build\Release\`。

开启监听时，`listen.bind_address` 是本机唯一的传输地址，同时用于 TCP/UDP 绑定和对端连接；可填写具体单播地址，也可填写 `0.0.0.0:端口` 或 `[::]:端口` 绑定所有网卡。关闭监听时 `bind_address` 和 `shared_key` 不参与出站连接，规范化时会被移除，核心自动使用通配绑定和实际出站端点；此模式需要对端通过 `listen.shared_key` 接收入站邻接。虚拟网络内的节点身份由该网络的 `tunnel_ip` 决定。数据封装默认使用 TCP；如需 UDP，在 peer 对象中添加 `"transport": "udp"`，两端版本均须支持；程序不自动在 TCP/UDP 间回退。多网络时还须明确填写每个 peer 允许使用的网段。需要免登记接收入站节点时，可在 `listen` 中配置 `shared_key`；持钥节点仍受 `listen.networks` 限制。

上述配置显式选择 `tun`，无需安装本项目的内核模块。省略 `device_backend` 时，**Linux 默认使用 `kernel`，其他平台（包括 Android）默认使用 `tun`**。

## Linux 内核设备

先安装与**正在运行的内核**匹配的开发头文件和构建工具，再使用项目构建脚本生成模块：

```bash
bash build.sh
bash run-gui.sh
```

Linux 默认使用 `kernel`。先执行 `build.sh` 构建核心和 GUI 环境；如果配置选择 `tun`，运行 `run-gui.sh` 前仍需为核心设置所需能力。使用 `device_backend=kernel` 时还需按当前发行版安装模块和设备权限；模块二进制不能跨内核版本通用。

WSL 也需要与其运行内核匹配的构建树，普通发行版头文件不能直接替代。已在 WSL `6.18.40.1-microsoft-standard-WSL2` 完成实际运行验证，其他版本以对应编译和测试结果为准。构建要求、ABI、WSL 和 BTF 处理见 [内核后端说明](kernel/README.md)。

## 图形界面、命令行与热加载

桌面管理工具需要 Python 3.10+ 及对应平台的 WebView 依赖。安装 Python 依赖后，显式指定刚构建的核心：

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -r gui/requirements.txt
.venv/bin/python gui/main.py --binary build/tunnel
```

Linux GTK/WebKit 后端通常需要系统 `gi` 包和 WebKit 运行库，安装步骤见 [GUI 文档](gui/README.md)。启动网络需要相应设备与路由管理权限；Linux/macOS 当前没有独立提权服务。

也可通过命令行后台管理同一配置：

```bash
.venv/bin/python -m tools.tunnel_cli --binary build/tunnel start --config node-a.json
.venv/bin/python -m tools.tunnel_cli --binary build/tunnel status
.venv/bin/python -m tools.tunnel_cli --binary build/tunnel config set /tun_mtu 1300
.venv/bin/python -m tools.tunnel_cli --binary build/tunnel stop
```

上述后台管理方式与直接运行核心二选一，避免重复启动同一节点。GUI/CLI 保存会校验并应用运行配置；直接运行核心使用 `--watch-config` 监视文件，Linux/macOS 也支持 `SIGHUP`。peer 变更只重连受影响邻接；地址、设备和网络等变更会重建资源及连接。详见 [命令行说明](docs/cli.md)。

## 示例与文档

| 内容 | 入口 |
| --- | --- |
| UI 使用示例 | [界面截图与操作步骤](docs/ui-example.md)、[节点 A](examples/ui-node-a.json)、[节点 B](examples/ui-node-b.json) |
| 基础配置 | [default.json](config/default.json) |
| TCP 数据封装 | [节点 A](examples/tcp-node-a.json)、[节点 B](examples/tcp-node-b.json) |
| 自动地址分配 | [服务端](examples/address-server.json)、[客户端](examples/address-client.json) |
| 内网路由与 SNAT | [出口节点](examples/subnet-gateway.json)、[访问节点](examples/subnet-client.json) |
| 远程桌面 | [被控端](examples/desktop-host.json)、[控制端](examples/desktop-client.json)、[使用说明](remote_desktop/README.md) |
| Design and implementation | [Design](docs/design.md), [Development](docs/development.md) |
| Verification | [Test results](docs/test-results.md), [Tests](tests/) |

示例中的地址和密钥均需替换。普通原生测试不要求创建真实隧道设备；真实网络、内核模块和 SNAT 集成测试需要 Linux 管理权限，运行方式及已验证范围见开发说明和测试记录。