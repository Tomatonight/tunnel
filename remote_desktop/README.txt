远程桌面

当前支持已登录桌面的单屏查看、鼠标/键盘、只读模式、首次设备配对、预授权无人值守、
仅已授权设备/同虚拟网络所有节点两种策略、实时撤销、后台运行和日志。
Windows、Linux X11 有实际截图/输入验证；macOS Quartz 后端已编写，尚无目标平台实测。
Wayland 明确返回不支持。登录界面、锁屏/UAC安全桌面、FileVault、音频、剪贴板和文件传输不在本版范围。
Android 当前只提供隧道配置/访问功能，不提供远程桌面控制或被控后端。

界面使用

1. 安装/打开桌面界面，导入 examples/desktop-host.json（被控端）和 desktop-client.json（控制端）。
   将公布地址、虚拟IP、网段和两端相同的peer PSK改成实际值，先确认隧道互通。
2. 被控端“远程桌面”页开启服务、选择开放网络，默认使用“仅已授权设备”。
   勾选无人值守表示已获准设备以后不必每次本机确认；首次未知设备仍需批准。
3. 控制端在该页输入被控端虚拟IP，例如10.1.0.1，选择共同tunnel，点击连接。
   首次连接显示被控端长期设备指纹，本机确认信任后继续；该确认不会给公网陌生设备开放权限。
4. 被控端批准请求，选择“仅查看”或“允许控制”，需要后续无人值守时勾选记住设备。
   查看模式在服务端强制禁止输入；同时仅允许一个控制端，后来的连接不会自动抢占。
5. 要让同网所有有效节点直接控制，改为“本虚拟网络内所有节点”，同时开启无人值守。
   此模式不要求把每个控制端写入名单；删除某项名单记录不会封禁仍在该网络中的设备。
   切回名单模式、关闭服务、缩小网络范围或撤销名单授权，会立即取消对应访问资格并关闭会话。

屏幕通过JPEG传输，最大1600×900、最多8帧/秒；只保留最新画面，不积压视频帧。
输入队列有界，移动合并；断开、撤权或队列溢出会释放按键。文字输入法组合、特殊快捷键与多屏不作跨平台保证。
依赖Python ssl/OpenSSL TLS1.3。桌面TCP端口默认47831，仅绑定选定网络的本机虚拟IP，不绑定0.0.0.0/::。
这是虚拟网络内应用端口，外层隧道仍是原有单UDP socket，公网仅需原有隧道TCP/UDP端点。

身份与成员验证

长期Ed25519设备密钥和自签TLS证书保存在desktop-identity.pem，首次生成，以后加载。
desktop-devices.json保存授权设备及控制端已信任的被控设备公钥；正常重启/地址变化不会改长期身份。
已有身份文件或授权库损坏时报错，不悄悄生成替代身份。换钥需要重新配对，不受普通路径更新覆盖。
两种访问模式均经核心验证当前同网节点和源虚拟IP；不会只因为连接来自某个IP段就放行。
握手绑定两端随机数、TLS服务证书、双方设备公钥、源/目的虚拟IP、网段和请求权限。
核心使用本次进程身份签署用途隔离的成员证明；任何源IP、公钥、网段或证明不匹配都拒绝。
每秒复核会话资格；核心已撤回路径/地址资格后关闭会话。物理断网仍遵守核心5秒保活、20秒失效规则。
信任边界沿用隧道“接入节点如实转发路径公钥”的约定；持久授权设备另需证明拥有其长期私钥。

后台与命令行

桌面界面通过独立Python后台进程管理核心与远控服务。开启远控且无人值守时，关闭界面会保留后台；
重新打开相同配置目录可接回。界面“断开”始终停止后台与隧道；控制端窗口关闭会断开其正在查看的远控。
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
命令行配置工具为python -m tunnel_cli，Windows成品为TunnelCtl.exe；与GUI使用同一配置目录即可管理同一个后台，详见../命令行说明.txt。

验证

    python tests/remote_runtime_test.py
    python tests/remote_platform_test.py
    python tests/remote_platform_test.py --live-capture
    python tests/remote_stdio_test.py --binary build/tunnel.exe
Linux隔离真实键鼠（需要Xvfb、libXtst；不会操作当前用户桌面）：
    python tests/remote_platform_test.py --xvfb
真实双节点TUN+TLS+Xvfb（root，需要iproute2、Xvfb、libXtst及Python依赖）：
    sudo python tests/remote_network_integration.py --binary build-wsl/tunnel
平台与测试结果以 ../测试结果.txt 为准，不将macOS源码检查记为实机通过。
