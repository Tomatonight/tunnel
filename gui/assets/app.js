(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const MAX_CONFIG_BYTES = 1024 * 1024;
  const pageInfo = {
    overview: ["OVERVIEW", "网络概览", "查看节点连接与虚拟网络的实时状态。"],
    config: ["CONFIGURATION", "连接配置", "管理节点、虚拟网络与认证信息。"],
    remote: ["REMOTE DESKTOP", "远程桌面", "查看与操作虚拟网络中的设备，管理本机远控授权。"],
    logs: ["ACTIVITY", "运行日志", "跟踪连接变化，定位运行问题。"]
  };
  const phaseLabels = { stopped: "已停止", starting: "正在启动", running: "运行中", stopping: "正在停止", error: "运行异常" };
  const peerLabels = ["未连接", "连接中", "认证中", "已连接"];
  const counterNames = {
    forwarded: "转发数据包", unicast_forwarded: "转发单播", multicast_forwarded: "转发组播", flood_forwarded: "转发广播 / 组播",
    tun_received: "TUN 收到", tun_sent: "TUN 写入", tun_delivered: "本机投递", delivered: "本机投递", udp_received: "UDP 收到", udp_sent: "UDP 发出",
    tcp_data_sent: "TCP 加密记录发出", tcp_data_received: "TCP 加密记录收到", tcp_data_rejected: "TCP 数据校验拒绝", tcp_data_send_drop: "TCP 数据排队丢弃",
    udp_data_sent: "UDP 加密记录发出", udp_data_received: "UDP 加密记录收到",
    udp_rejected: "UDP 校验拒绝", invalid_packet: "无效数据包", tun_rejected: "TUN 数据包拒绝", tun_oversize: "超过 MTU", mtu_drop: "超过 MTU",
    spoofed_source: "源地址拒绝", source_rejected: "源地址拒绝", rpf_drop: "RPF 拒绝", rpf_rejected: "RPF 拒绝", hop_limit_drop: "跳数耗尽",
    no_route: "无可用路径", pending_drop: "待握手数据包丢弃", handshake_timeout: "握手超时", peer_timeout: "邻接活动超时",
    e2e_rejected: "端到端校验拒绝", decrypt_failed: "解密失败", send_failed: "发送失败", tcp_failed: "TCP 连接失败",
    peer_up: "邻接建立", peer_down: "邻接断开", control_rejected: "控制消息拒绝", route_rejected: "路径通告拒绝",
    control_forwarded: "转发控制消息", e2e_established: "端到端会话建立", udp_send_drop: "UDP 发送丢弃",
    unicast_sent: "单播发出", flood_sent: "广播 / 组播发出", tun_read: "TUN 收到", tun_written: "TUN 写入",
    e2e_send_drop: "端到端发送丢弃", session_limit_drop: "会话数量限制丢弃", invalid_tun_packet: "无效 TUN 数据包",
    tun_packet_error: "TUN 数据包错误", tun_write_drop: "TUN 写入丢弃", invalid_forward: "无效转发信息",
    e2e_decrypt_drop: "端到端解密拒绝", invalid_inner: "无效内层数据包"
  };
  let bridgeReady = false;
  let initialized = false;
  let busy = false;
  let savedText = "";
  let savedRevision;
  let state = { phase: "stopped", status: null, logs: [] };
  let logs = [];
  let visibleLogs = [];
  let toastTimer;
  let pollTimer;
  let polling = false;
  let pollFailures = 0;
  let lastLogsSignature = "";
  let configRevision = 0;
  let formModel = null;
  let jsonPending = false;
  let appliedJSON = "";
  let networkSerial = 0;
  let remoteState = {};
  let remoteSession = null;
  let remoteFrameTimer;
  let remoteFrameBusy = false;
  let remoteFrameSequence = -1;
  let remoteInputQueue = [];
  let remoteInputBusy = false;
  let remoteSignature = "";

  function text(element, value) { element.textContent = String(value == null ? "—" : value); }
  function element(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value != null) text(node, value);
    return node;
  }
  function number(value) { return typeof value === "number" && Number.isFinite(value) ? value : 0; }
  function formatNumber(value) { return new Intl.NumberFormat("zh-CN").format(value); }
  function byteSize(value) { return new TextEncoder().encode(value).length; }
  function showToast(message, failed = false) {
    clearTimeout(toastTimer);
    text($("toast"), message);
    $("toast").classList.toggle("error", failed);
    $("toast").hidden = false;
    toastTimer = setTimeout(() => { $("toast").hidden = true; }, failed ? 6000 : 3500);
  }
  function feedback(message, kind = "") {
    text($("config-feedback"), message);
    $("config-feedback").className = kind;
    $("config-editor").classList.toggle("invalid", kind === "failure");
  }
  function hostAvailable() {
    return !!((window.TunnelHost && typeof window.TunnelHost.request === "function") ||
      (window.pywebview && window.pywebview.api && typeof window.pywebview.api.request === "function"));
  }
  function androidHost() { return !!(window.TunnelHost && typeof window.TunnelHost.request === "function") || state.platform === "Android"; }
  async function request(action, payload = {}) {
    if (!hostAvailable()) throw new Error("尚未连接本机宿主，请从 Tunnel 应用打开界面。");
    const android = window.TunnelHost && typeof window.TunnelHost.request === "function";
    const envelope = { action, payload };
    if (!android) envelope.token = window.__TUNNEL_UI_TOKEN__;
    const message = JSON.stringify(envelope);
    const raw = android
      ? await Promise.resolve(window.TunnelHost.request(message))
      : await window.pywebview.api.request(message);
    let result;
    try { result = typeof raw === "string" ? JSON.parse(raw) : raw; }
    catch (_) { throw new Error("本机宿主返回了无法解析的响应。"); }
    if (!result || result.ok !== true) throw new Error(result && result.error ? String(result.error) : "操作未完成。");
    return result.data;
  }
  function navigate(page) {
    if (!pageInfo[page]) page = "overview";
    Object.keys(pageInfo).forEach((name) => { $("page-" + name).hidden = name !== page; });
    document.querySelectorAll("[data-page]").forEach((button) => {
      const current = button.dataset.page === page;
      button.classList.toggle("active", current);
      if (current) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    const info = pageInfo[page];
    text($("page-eyebrow"), info[0]); text($("page-title"), info[1]); text($("page-description"), info[2]);
    if (page === "logs" && $("follow-logs").checked) $("log-output").scrollTop = $("log-output").scrollHeight;
  }
  function updateControls() {
    const active = state.phase === "running" || state.phase === "starting" || state.phase === "stopping";
    const retryStop = state.phase === "stopping" && !!state.error;
    const transitional = state.phase === "starting" || (state.phase === "stopping" && !retryStop);
    const validText = $("config-editor").value.trim().length > 0;
    const serviceOnly = active ? !!(state.status && !state.status.node && state.status.address_service && state.status.address_service.server && state.status.address_service.server.enabled) : !!(formModel && formModel.serverOnly);
    $("connection-button").disabled = !bridgeReady || busy || transitional || (!active && !validText);
    $("connection-button").classList.toggle("disconnect", active);
    text($("connection-label"), retryStop ? "重试断开" : state.phase === "starting" ? "正在启动" : state.phase === "stopping" ? "正在停止" : active ? serviceOnly ? "停止服务" : "断开网络" : serviceOnly ? "启动服务" : "连接网络");
    $("reload-config").disabled = !bridgeReady || busy;
    $("validate-config").disabled = !bridgeReady || busy || !validText;
    $("save-config").disabled = !bridgeReady || busy || transitional || !validText;
    text($("save-config"), active ? "保存并应用" : "保存配置");
    text($("config-apply-help"), active ? "运行中保存会立即应用；网络资源变更可能短暂重连。应用失败会显示原因并保留修改，供你继续编辑。" : "连接时会校验并保存当前配置。运行中也可以保存并应用修改，无需手动断开。");
    $("clear-logs").disabled = !bridgeReady || busy || logs.length === 0;
    $("copy-logs").disabled = visibleLogs.length === 0;
    $("import-config").disabled = busy;
    $("config-editor").readOnly = busy;
    $("basic-config-fields").disabled = busy || jsonPending || !formModel || formModel.serverOnly;
    $("advanced-config-fields").disabled = busy || jsonPending || !formModel || formModel.serverOnly;
    $("basic-config-fields").hidden = !!(formModel && formModel.serverOnly);
    $("advanced-config-fields").hidden = !!(formModel && formModel.serverOnly);
    $("address-service-fields").disabled = busy || jsonPending || !formModel;
    for (const id of ["merge-access", "replace-access", "copy-access-export"]) $(id).disabled = busy || !bridgeReady;
    $("apply-json").disabled = !bridgeReady || busy || !validText || !jsonPending;
    $("discard-json").disabled = busy || !jsonPending;
    $("json-pending-notice").hidden = !jsonPending;
    document.querySelectorAll(".generate-key,.export-access").forEach((button) => { button.disabled = !bridgeReady || busy; });
    $("access-import-text").readOnly = busy; $("choose-access-file").disabled = busy;
    $("add-subnet").disabled = busy || androidHost();
    $("subnet-android-notice").hidden = !androidHost();
    document.querySelectorAll(".subnet-network,.subnet-prefix,.subnet-snat").forEach((input) => { input.disabled = androidHost(); });
    $("remote-config-fields").disabled = busy || jsonPending || !formModel || formModel.serverOnly || androidHost();
    $("remote-platform-notice").hidden = !androidHost();
    $("remote-save").disabled = !bridgeReady || busy || transitional || jsonPending || !formModel || formModel.serverOnly || androidHost();
    text($("remote-save"), active ? "保存并应用" : "保存远控设置");
    $("remote-connect").disabled = !bridgeReady || busy || state.phase !== "running" || !!remoteSession || androidHost();
    if (androidHost()) text($("remote-message"), "本版远程桌面需要 Windows、Linux 或 macOS 桌面宿主。Android 可继续使用隧道网络。");
    $("remote-android-configuration").hidden = !(androidHost() && formModel && formModel.remote.enabled);
    $("remote-remove-unsupported").disabled = busy || jsonPending || !formModel;
    $("remote-refresh").disabled = !bridgeReady || busy;
  }
  function editorChanged(fromForm = false) {
    configRevision += 1;
    if (!fromForm) jsonPending = $("config-editor").value !== appliedJSON || !formModel;
    const value = $("config-editor").value;
    const dirty = value !== savedText;
    $("config-dirty").hidden = !dirty; $("edit-dot").hidden = !dirty;
    const bytes = byteSize(value);
    text($("editor-size"), bytes < 1024 ? bytes + " B" : (bytes / 1024).toFixed(1) + " KiB");
    if (bytes > MAX_CONFIG_BYTES) feedback("配置超过 1 MiB，请缩小配置文件。", "failure");
    else feedback(jsonPending ? "JSON 修改尚未应用，请先校验并应用到表单。" : dirty ? state.phase === "running" ? "配置尚未保存；保存并应用后立即生效，可能短暂重连。" : "配置尚未保存；连接时会校验并保存。" : "配置中的共享密钥仅用于对应节点的认证。");
    updateControls();
  }
  function configuration(allowRaw = false) {
    if (!allowRaw && jsonPending) throw new Error("请先将 JSON 修改应用到表单，再保存或连接。");
    const value = $("config-editor").value;
    if (!value.trim()) throw new Error("请先载入或填写配置。");
    if (byteSize(value) > MAX_CONFIG_BYTES) throw new Error("配置文件不能超过 1 MiB。");
    return value;
  }
  function publishSupported() {
    if (androidHost() && formModel && !formModel.serverOnly && formModel.published.length) throw new Error("Android 只能作为内网访问端。请移除发布内网配置后再保存或连接。");
    if (androidHost() && formModel && formModel.remote.enabled) throw new Error("Android 本版不支持本机远程桌面服务。请到远程桌面页面移除此设置，再保存或连接。");
  }
  function responseMessage(data, fallback) { return data && typeof data.message === "string" && data.message ? data.message : fallback; }
  async function saveConfiguration() {
    try {
      const value = configuration(); publishSupported();
      const active = state.phase === "running";
      const payload = { text: value };
      if (savedRevision !== undefined) payload.expected_sha256 = savedRevision;
      const data = await request("save_config", payload);
      const previous = formModel;
      acceptNormalized(data && typeof data.text === "string" ? data.text : value, true);
      // Preserve settings deliberately hidden by a disabled mode in this window.
      // They are still omitted from the saved configuration until re-enabled.
      if (previous.serverOnly && formModel.serverOnly) formModel = { ...previous, server: formModel.server, deviceBackend: formModel.deviceBackend };
      if (!previous.server.enabled && !formModel.server.enabled) formModel.server = previous.server;
      formModel.server.exportAddress = previous.server.exportAddress;
      if (formModel.server.enabled && formModel.server.mode === "individual") formModel.server.key = previous.server.key;
      if (formModel.server.enabled && formModel.server.mode === "shared") {
        formModel.server.clients = previous.server.clients.map((client) => ({ ...client, ids: new Set(formModel.server.pools.filter((pool) => previous.server.pools.some((old) => old.cidr === pool.cidr && client.ids.has(old.id))).map((pool) => pool.id)) }));
      }
      renderForm(); synchronizeForm(true);
      savedRevision = data ? data.revision : undefined;
      let message = responseMessage(data, active ? "配置已保存并应用。" : "配置已保存，连接时生效。");
      if (data && (data.mode === "rebuild" || data.interrupted) && !message.includes("重连")) message += " 配置变更涉及连接重建，相关连接正在重连。";
      feedback(message, "success"); showToast(message);
      await poll();
    } catch (error) { feedback(error.message || String(error), "failure"); throw error; }
  }
  async function action(task) {
    if (busy) return;
    busy = true; updateControls();
    try { await task(); }
    catch (error) { showToast(error.message || String(error), true); }
    finally { busy = false; updateControls(); }
  }
  async function loadConfig(manual = false) {
    if (manual && $("config-editor").value !== savedText && !window.confirm("重新载入将替换尚未保存的修改，是否继续？")) return;
    const revision = configRevision;
    const data = await request("load_config");
    if (!data || typeof data.text !== "string") throw new Error("宿主未返回有效配置文本。");
    if (byteSize(data.text) > MAX_CONFIG_BYTES) throw new Error("配置文件不能超过 1 MiB。");
    if (configRevision !== revision) return;
    savedRevision = data.revision;
    if (!data.text.trim()) { formModel = blankModel(); renderForm(); synchronizeForm(true); }
    else if (data.error) preserveRaw(data.text, data.error, true);
    else {
      try { acceptNormalized(data.text, true); }
      catch (error) { preserveRaw(data.text, error.message, true); }
    }
    if (manual) showToast("已重新载入保存的配置。");
  }
  // This helper only derives references for the form. The C++ parser remains
  // authoritative for host validity, overlap, ownership and authorization.
  function subnetReference(cidr) {
    if (typeof cidr !== "string") return null;
    const split = cidr.trim().split("/");
    if (split.length !== 2 || !/^\d+$/.test(split[1])) return null;
    const prefix = Number(split[1]); const ip = split[0];
    const ipv4 = (value) => {
      const parts = value.split(".");
      return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255) ? parts.map(Number) : null;
    };
    if (!ip.includes(":")) {
      const parts = ipv4(ip); if (!parts || prefix > 32) return null;
      return parts.map((part, index) => { const bits = Math.min(8, Math.max(0, prefix - index * 8)); return part & (bits ? (255 << (8 - bits)) : 0); }).join(".") + "/" + prefix;
    }
    if (prefix > 128 || /[^a-fA-F0-9:.]/.test(ip)) return null;
    let value = ip;
    if (value.includes(".")) {
      const position = value.lastIndexOf(":"); const tail = ipv4(value.slice(position + 1));
      if (!tail) return null;
      value = value.slice(0, position + 1) + ((tail[0] << 8) | tail[1]).toString(16) + ":" + ((tail[2] << 8) | tail[3]).toString(16);
    }
    const halves = value.split("::"); if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
    const count = left.length + right.length;
    if (!left.concat(right).every((word) => /^[a-fA-F0-9]{1,4}$/.test(word)) ||
        (halves.length === 1 ? count !== 8 : count >= 8)) return null;
    const words = left.map((word) => parseInt(word, 16)).concat(halves.length === 2 ? Array(8 - count).fill(0) : [], right.map((word) => parseInt(word, 16)));
    const masked = words.map((word, index) => { const bits = Math.min(16, Math.max(0, prefix - index * 16)); return word & (bits ? (65535 << (16 - bits)) : 0); });
    let best = -1, length = 1;
    for (let i = 0; i < 8;) {
      if (masked[i] !== 0) { i += 1; continue; }
      let end = i; while (end < 8 && masked[end] === 0) end += 1;
      if (end - i > length) { best = i; length = end - i; } i = end;
    }
    const strings = masked.map((word) => word.toString(16));
    return (best < 0 ? strings.join(":") : strings.slice(0, best).join(":") + "::" + strings.slice(best + length).join(":")) + "/" + prefix;
  }
  function blankModel() {
    return { address: "", networks: [{ id: ++networkSerial, cidr: "" }], peers: [], clients: [], published: [], serverOnly: false,
      server: { enabled: false, address: "", bind: "", mode: "shared", key: "", exportAddress: "", stateFile: "address-leases.json", reclaim: "86400", pools: [{ id: ++networkSerial, cidr: "" }], clients: [] },
      listenEnabled: true, bind: "", listenAll: true, listenIds: new Set(), tunMtu: "1280", transportMtu: "1500", deviceBackend: "auto",
      remote: { present: false, enabled: false, access: "authorized_devices", unattended: false, name: "", port: "47831", ids: new Set() } };
  }
  function localNetworks(model = formModel) {
    return model.networks.concat(model.clients.flatMap((client) => client.networks.map((network) => ({ ...network, managed: true }))));
  }
  function modelFromDocument(doc) {
    const object = (value, allowed, name) => {
      if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(name + " 包含表单无法表达的字段；已保留完整 JSON。");
    };
    object(doc, ["address", "networks", "peers", "listen", "tun_mtu", "transport_mtu", "address_server", "address_clients", "advertise_routes", "remote_desktop", "device_backend"], "配置");
    if (doc.address !== undefined && typeof doc.address !== "string") throw new Error("本机公布地址格式不正确。");
    const networkList = (value, name) => {
      if (!Array.isArray(value) || !value.every((cidr) => typeof cidr === "string" && subnetReference(cidr))) throw new Error(name + " 必须是有效的 CIDR 列表。");
      return value.map((cidr) => ({ id: ++networkSerial, cidr }));
    };
    const model = blankModel(); model.address = doc.address || "";
    if (doc.device_backend !== undefined && !["tun", "kernel"].includes(doc.device_backend)) throw new Error("隧道设备必须选择 tun 或 kernel。");
    model.deviceBackend = doc.device_backend || "auto";
    model.networks = networkList(doc.networks || [], "本机网络");
    if (doc.address_clients !== undefined && !Array.isArray(doc.address_clients)) throw new Error("地址分配客户端必须是列表。");
    model.clients = (doc.address_clients || []).map((client) => {
      object(client, ["address", "shared_key", "networks"], "地址分配客户端");
      if (typeof client.address !== "string" || typeof client.shared_key !== "string") throw new Error("分配服务地址或密钥格式不正确。");
      return { address: client.address, key: client.shared_key, networks: networkList(client.networks, "申请网段") };
    });
    if (doc.advertise_routes !== undefined && !Array.isArray(doc.advertise_routes)) throw new Error("发布内网必须是列表。");
    model.published = (doc.advertise_routes || []).map((route) => {
      object(route, ["tunnel", "prefix", "snat"], "发布内网");
      if (typeof route.tunnel !== "string" || typeof route.prefix !== "string" || (route.snat !== undefined && typeof route.snat !== "boolean")) throw new Error("发布内网的字段格式不正确。");
      const network = localNetworks(model).find((item) => subnetReference(item.cidr) === subnetReference(route.tunnel));
      if (!network) throw new Error("发布内网引用了未配置的虚拟网络；已保留完整 JSON。");
      return { networkId: network.id, tunnel: route.tunnel, prefix: route.prefix, snat: route.snat === true };
    });
    const ids = (references, available = localNetworks(model)) => {
      if (!Array.isArray(references)) throw new Error("网络授权必须是列表。");
      return new Set(references.map((reference) => {
        const normalized = subnetReference(reference);
        const item = available.find((network) => normalized && subnetReference(network.cidr) === normalized);
        if (!item) throw new Error("网络授权引用了未定义的网络；已保留完整 JSON。"); return item.id;
      }));
    };
    if (doc.remote_desktop !== undefined) {
      const remote = doc.remote_desktop;
      object(remote, ["enabled", "networks", "access", "unattended", "port", "device_name"], "远程桌面");
      if ((remote.enabled !== undefined && typeof remote.enabled !== "boolean") ||
          (remote.unattended !== undefined && typeof remote.unattended !== "boolean") ||
          (remote.access !== undefined && !["authorized_devices", "all_tunnel_nodes"].includes(remote.access)) ||
          (remote.port !== undefined && (!Number.isInteger(remote.port) || remote.port < 1 || remote.port > 65535)) ||
          (remote.device_name !== undefined && typeof remote.device_name !== "string")) throw new Error("远程桌面配置格式不正确。");
      if (remote.enabled && remote.networks === undefined && localNetworks(model).length !== 1) throw new Error("多个虚拟网络时，需要明确选择远控范围。");
      model.remote = { present: true, enabled: remote.enabled === true, access: remote.access || "authorized_devices", unattended: remote.unattended === true,
        name: remote.device_name || "", port: String(remote.port || 47831), ids: remote.networks === undefined ? new Set(localNetworks(model).length === 1 ? [localNetworks(model)[0].id] : []) : ids(remote.networks) };
    } else if (localNetworks(model).length === 1) model.remote.ids.add(localNetworks(model)[0].id);
    if (doc.address_server !== undefined) {
      const service = doc.address_server;
      object(service, ["address", "bind_address", "state_file", "reclaim_after", "networks", "clients", "shared_key"], "地址分配服务");
      const shared = Object.prototype.hasOwnProperty.call(service, "shared_key");
      if (typeof service.address !== "string" || (service.bind_address !== undefined && typeof service.bind_address !== "string") ||
          (service.state_file !== undefined && typeof service.state_file !== "string") || (service.reclaim_after !== undefined && !Number.isInteger(service.reclaim_after)) ||
          (shared ? typeof service.shared_key !== "string" || service.clients !== undefined : !Array.isArray(service.clients))) throw new Error("地址分配服务的字段格式不正确；共享密钥与逐节点授权不能同时配置。");
      model.server = { enabled: true, address: service.address, bind: service.bind_address || "", stateFile: service.state_file || "address-leases.json",
        mode: shared ? "shared" : "individual", key: shared ? service.shared_key : "", exportAddress: "",
        reclaim: String(service.reclaim_after === undefined ? 86400 : service.reclaim_after), pools: networkList(service.networks, "地址池"), clients: [] };
      model.server.clients = (service.clients || []).map((client) => {
        object(client, ["address", "shared_key", "networks"], "授权接入节点");
        if (typeof client.address !== "string" || typeof client.shared_key !== "string") throw new Error("授权节点地址或密钥格式不正确。");
        return { address: client.address, key: client.shared_key, ids: ids(client.networks, model.server.pools) };
      });
    }
    model.serverOnly = !model.address && model.server.enabled;
    if (!model.serverOnly && (!model.address || !localNetworks(model).length)) throw new Error("本机需要公布地址及手动或自动获取的虚拟网络。");
    if (doc.peers !== undefined && !Array.isArray(doc.peers)) throw new Error("连接节点必须是列表。");
    model.peers = (doc.peers || []).map((peer) => {
      object(peer, ["address", "shared_key", "networks", "transport"], "节点");
      if (typeof peer.address !== "string" || typeof peer.shared_key !== "string") throw new Error("节点地址或共享密钥格式不正确。");
      if (peer.transport !== undefined && !["udp", "tcp"].includes(peer.transport)) throw new Error("节点的数据封装必须为 udp 或 tcp。");
      if (peer.networks === undefined && localNetworks(model).length !== 1) throw new Error("多个虚拟网络时，节点必须明确列出允许的网络。");
      const selected = peer.networks === undefined ? new Set([localNetworks(model)[0].id]) : ids(peer.networks);
      if (!selected.size) throw new Error("节点至少需要一个获授权的虚拟网络。");
      return { address: peer.address, key: peer.shared_key, transport: peer.transport || "udp", ids: selected };
    });
    if (doc.listen !== undefined) {
      object(doc.listen, ["enabled", "bind_address", "networks"], "监听设置");
      if (doc.listen.enabled !== undefined && typeof doc.listen.enabled !== "boolean") throw new Error("监听开关必须为布尔值。");
      if (doc.listen.bind_address !== undefined && typeof doc.listen.bind_address !== "string") throw new Error("绑定地址必须是文本。");
      model.listenEnabled = doc.listen.enabled !== false; model.bind = doc.listen.bind_address || "";
      model.listenAll = doc.listen.networks === undefined;
      model.listenIds = model.listenAll ? new Set(localNetworks(model).map((network) => network.id)) : ids(doc.listen.networks);
    }
    for (const [field, target] of [["tun_mtu", "tunMtu"], ["transport_mtu", "transportMtu"]]) {
      if (doc[field] !== undefined) {
        if (!Number.isInteger(doc[field])) throw new Error("MTU 必须是整数。"); model[target] = String(doc[field]);
      }
    }
    return model;
  }
  function serializeForm() {
    const model = formModel;
    const available = localNetworks(model);
    const refs = (ids, list = available) => list.filter((network) => ids.has(network.id)).map((network) => subnetReference(network.cidr) || network.cidr.trim());
    const doc = {};
    if (model.deviceBackend !== "auto") doc.device_backend = model.deviceBackend;
    if (!model.serverOnly) {
      doc.address = model.address.trim();
      if (model.networks.length || !model.clients.length) doc.networks = model.networks.map((network) => network.cidr.trim());
      if (model.clients.length) doc.address_clients = model.clients.map((client) => ({ address: client.address.trim(), shared_key: client.key, networks: client.networks.map((network) => network.cidr.trim()) }));
      if (model.published.length) doc.advertise_routes = model.published.map((route) => {
        const network = available.find((item) => item.id === route.networkId);
        const result = { tunnel: network ? subnetReference(network.cidr) || network.cidr.trim() : route.tunnel, prefix: route.prefix.trim() };
        if (route.snat) result.snat = true;
        return result;
      });
      if (model.remote.present || model.remote.enabled) {
        const remote = { enabled: model.remote.enabled };
        if (available.length !== 1 || !model.remote.ids.has(available[0].id)) remote.networks = refs(model.remote.ids);
        if (model.remote.access !== "authorized_devices") remote.access = model.remote.access;
        if (model.remote.unattended) remote.unattended = true;
        if (model.remote.name.trim()) remote.device_name = model.remote.name.trim();
        if (model.remote.port !== "" && Number(model.remote.port) !== 47831) remote.port = Number(model.remote.port);
        doc.remote_desktop = remote;
      }
    if (model.peers.length) doc.peers = model.peers.map((peer) => {
      const result = { address: peer.address.trim(), shared_key: peer.key };
      if (peer.transport !== "udp") result.transport = peer.transport;
      if (available.length !== 1 || !peer.ids.has(available[0].id)) result.networks = refs(peer.ids);
      return result;
    });
    const listen = {};
    if (!model.listenEnabled) listen.enabled = false;
    if (model.bind.trim()) listen.bind_address = model.bind.trim();
    if (!model.listenAll) listen.networks = refs(model.listenIds);
    if (Object.keys(listen).length) doc.listen = listen;
    const tun = model.tunMtu === "" ? 1280 : Number(model.tunMtu);
    const transport = model.transportMtu === "" ? 1500 : Number(model.transportMtu);
    if (tun !== 1280) doc.tun_mtu = tun;
    if (transport !== 1500) doc.transport_mtu = transport;
    }
    if (model.server.enabled) {
      const service = { address: model.server.address.trim(), networks: model.server.pools.map((network) => network.cidr.trim()) };
      if (model.server.mode === "shared") service.shared_key = model.server.key;
      else service.clients = model.server.clients.map((client) => ({ address: client.address.trim(), shared_key: client.key, networks: refs(client.ids, model.server.pools) }));
      if (model.server.bind.trim()) service.bind_address = model.server.bind.trim();
      if (model.server.stateFile.trim() && model.server.stateFile.trim() !== "address-leases.json") service.state_file = model.server.stateFile.trim();
      const reclaim = model.server.reclaim === "" ? 86400 : Number(model.server.reclaim);
      if (reclaim !== 86400) service.reclaim_after = reclaim;
      doc.address_server = service;
    }
    return JSON.stringify(doc, null, 2) + "\n";
  }
  function synchronizeForm(saved = false) {
    if (!formModel) return;
    appliedJSON = serializeForm(); $("config-editor").value = appliedJSON; jsonPending = false;
    if (saved) savedText = appliedJSON;
    editorChanged(true);
  }
  function acceptNormalized(value, saved = false) {
    const model = modelFromDocument(JSON.parse(value));
    formModel = model; renderForm(); synchronizeForm(saved);
    if (model.clients.length) $("address-clients-settings").open = true;
    if (model.server.enabled) $("address-server-settings").open = true;
    if (model.published.length) $("subnet-settings").open = true;
  }
  function normalizedImport(value, original) {
    // Validation resolves a platform default to its effective backend. Preserve
    // the user's omitted selection while editing an import; a successful save
    // accepts the core's explicit backend for portable persisted configuration.
    if (Object.prototype.hasOwnProperty.call(JSON.parse(original), "device_backend")) return value;
    const doc = JSON.parse(value); delete doc.device_backend;
    return JSON.stringify(doc, null, 2) + "\n";
  }
  function preserveRaw(value, error, saved = false) {
    $("config-editor").value = value;
    if (saved) savedText = value;
    jsonPending = true; $("advanced-config").open = true; $("json-settings").open = true;
    editorChanged(); feedback((error || "此配置需要校验。") + " 原始 JSON 已保留，请修正后应用到表单。", "failure");
  }
  function inputControl(className, value, placeholder, label, type = "text") {
    const input = element("input", "form-input " + className); input.type = type; input.value = value;
    input.placeholder = placeholder; input.autocomplete = "off"; input.spellcheck = false; input.setAttribute("aria-label", label); return input;
  }
  function smallButton(label, className, callback) {
    const button = element("button", "button secondary small " + className, label); button.type = "button"; button.addEventListener("click", callback); return button;
  }
  function renderAuthorization() {
    const choices = (container, selected, changed) => {
      container.replaceChildren();
      localNetworks().forEach((network, index) => {
        const label = element("label", "network-choice"); const check = element("input"); check.type = "checkbox"; check.checked = selected.has(network.id);
        check.dataset.networkId = String(network.id); check.addEventListener("change", () => { if (check.checked) selected.add(network.id); else selected.delete(network.id); changed(); synchronizeForm(); });
        label.append(check, element("span", "", (network.managed ? "自动 · " : "") + (subnetReference(network.cidr) || "网络 " + (index + 1) + "（请填写 IP/前缀）"))); container.append(label);
      });
    };
    document.querySelectorAll(".peer-card").forEach((card, index) => {
      const peer = formModel.peers[index]; const warning = card.querySelector(".network-warning");
      const update = () => { warning.hidden = localNetworks().some((network) => peer.ids.has(network.id)); };
      choices(card.querySelector(".network-choices"), peer.ids, update); update();
    });
    $("listen-network-fields").hidden = formModel.listenAll;
    choices($("listen-network-fields"), formModel.listenIds, () => {});
    choices($("remote-network-fields"), formModel.remote.ids, () => { formModel.remote.present = true; });
    const oldTarget = $("remote-target-network").value;
    $("remote-target-network").replaceChildren();
    localNetworks().forEach((network) => {
      const reference = subnetReference(network.cidr); if (!reference) return;
      const option = element("option", "", reference); option.value = reference; $("remote-target-network").append(option);
    });
    if (Array.from($("remote-target-network").options).some((option) => option.value === oldTarget)) $("remote-target-network").value = oldTarget;
    renderPublishNetworks();
  }
  function renderForm() {
    if (!formModel) return;
    $("local-endpoint").value = formModel.address; $("bind-address").value = formModel.bind;
    $("listen-enabled").checked = formModel.listenEnabled; $("listen-all").checked = formModel.listenAll;
    $("tun-mtu").value = formModel.tunMtu; $("transport-mtu").value = formModel.transportMtu;
    $("device-backend").value = formModel.deviceBackend;
    $("remote-enabled").checked = formModel.remote.enabled; $("remote-unattended").checked = formModel.remote.unattended;
    $("remote-access").value = formModel.remote.access; $("remote-device-name").value = formModel.remote.name; $("remote-port").value = formModel.remote.port;
    renderRemoteAccess();
    $("network-fields").replaceChildren();
    formModel.networks.forEach((network, index) => {
      const row = element("div", "network-row"); const input = inputControl("network-cidr", network.cidr, "例如 10.1.0.1/24", "本机虚拟 IP 和前缀 " + (index + 1));
      input.addEventListener("input", () => { network.cidr = input.value; renderAuthorization(); synchronizeForm(); });
      const remove = smallButton("移除", "remove-network", () => {
        formModel.networks = formModel.networks.filter((entry) => entry !== network);
        formModel.peers.forEach((peer) => peer.ids.delete(network.id)); formModel.listenIds.delete(network.id); formModel.remote.ids.delete(network.id);
        renderForm(); synchronizeForm();
      });
      remove.setAttribute("aria-label", "移除虚拟网络 " + (index + 1)); row.append(input, remove); $("network-fields").append(row);
    });
    $("peer-fields").replaceChildren(); $("peer-form-empty").hidden = formModel.peers.length > 0;
    formModel.peers.forEach((peer, index) => {
      const card = element("section", "peer-card"); const heading = element("div", "peer-card-heading");
      heading.append(element("h4", "", "节点 " + (index + 1)), smallButton("移除节点", "remove-peer", () => {
        formModel.peers = formModel.peers.filter((entry) => entry !== peer); renderForm(); synchronizeForm();
      }));
      const addressLabel = element("label", "form-field"); const address = inputControl("peer-address", peer.address, "例如 100.0.0.2:65535", "对端公布地址 " + (index + 1));
      address.addEventListener("input", () => { peer.address = address.value; synchronizeForm(); });
      addressLabel.append(element("span", "", "对端公布地址"), address);
      const transportLabel = element("label", "form-field"); const transport = element("select", "form-input peer-transport");
      transport.setAttribute("aria-label", "数据封装 " + (index + 1));
      for (const [value, label] of [["udp", "UDP（默认）"], ["tcp", "TCP"]]) { const option = element("option", "", label); option.value = value; transport.append(option); }
      transport.value = peer.transport;
      transport.addEventListener("change", () => { peer.transport = transport.value; synchronizeForm(); });
      transportLabel.append(element("span", "", "数据封装"), transport, element("small", "", "任一端选择 TCP 时使用 TCP；双方均需支持。UDP 不通时不会自动切换。"));
      const keyLabel = element("div", "form-field"); keyLabel.append(element("span", "", "共享密钥（双方一致）"));
      const keyControl = element("div", "secret-control"); const key = inputControl("peer-key", peer.key, "填写双方约定的密钥，或生成新密钥", "共享密钥 " + (index + 1), "password");
      key.autocomplete = "new-password"; key.addEventListener("input", () => { peer.key = key.value; synchronizeForm(); });
      const show = smallButton("显示", "show-key", () => { key.type = key.type === "password" ? "text" : "password"; text(show, key.type === "password" ? "显示" : "隐藏"); show.setAttribute("aria-pressed", String(key.type === "text")); }); show.setAttribute("aria-pressed", "false");
      const generate = smallButton("生成", "generate-key", () => action(async () => {
        if (peer.key && !window.confirm("生成新密钥会替换当前节点的密钥。双方需使用同一新密钥，是否继续？")) return;
        const data = await request("generate_key"); if (!data || typeof data.key !== "string" || !/^[0-9a-f]{64}$/i.test(data.key)) throw new Error("宿主未返回有效的新密钥。");
        peer.key = data.key; key.value = data.key; synchronizeForm(); showToast("已生成新密钥，请复制给对应节点使用。");
      }));
      keyControl.append(key, show, generate, smallButton("复制", "copy-key", () => action(async () => { if (!peer.key) throw new Error("请先填写或生成密钥。"); await copyText(peer.key); showToast("已复制此节点的共享密钥。"); })));
      keyLabel.append(keyControl);
      const authorization = element("div", "peer-authorization");
      authorization.append(element("div", "authorization-label", "允许加入的网络"), element("div", "network-choices"), element("p", "network-warning", "请至少选择一个网络；新增网络不会自动授权。"));
      card.append(heading, addressLabel, keyLabel, transportLabel, authorization); $("peer-fields").append(card);
    });
    renderAddressForms(); renderPublished(); renderAuthorization(); updateControls();
  }
  function renderPublishNetworks() {
    if (!formModel) return;
    document.querySelectorAll(".subnet-card").forEach((card, index) => {
      const route = formModel.published[index]; const select = card.querySelector(".subnet-network");
      const available = localNetworks(); select.replaceChildren();
      const selected = available.find((network) => network.id === route.networkId);
      if (!selected) {
        const placeholder = element("option", "", route.tunnel ? "原虚拟网络已移除：" + route.tunnel : "请选择所属虚拟网络");
        placeholder.value = ""; placeholder.disabled = true; placeholder.selected = true; select.append(placeholder);
      }
      available.forEach((network) => {
        const reference = subnetReference(network.cidr); const option = element("option", "", (network.managed ? "自动 · " : "") + (reference || "请先填写虚拟网络"));
        option.value = String(network.id); option.selected = network.id === route.networkId; select.append(option);
        if (option.selected && reference) route.tunnel = reference;
      });
    });
  }
  function renderPublished() {
    $("subnet-fields").replaceChildren();
    formModel.published.forEach((route, index) => {
      const card = element("section", "service-card subnet-card"); const heading = element("div", "service-card-heading");
      heading.append(element("h4", "", "内网 " + (index + 1)), smallButton("移除发布", "remove-subnet", () => {
        formModel.published = formModel.published.filter((item) => item !== route); renderForm(); synchronizeForm();
      }));
      const networkLabel = element("label", "form-field"); const network = element("select", "form-input subnet-network"); network.setAttribute("aria-label", "所属虚拟网络 " + (index + 1));
      network.addEventListener("change", () => { route.networkId = Number(network.value); renderPublishNetworks(); synchronizeForm(); });
      networkLabel.append(element("span", "", "所属虚拟网络"), network);
      const prefixLabel = element("label", "form-field"); const prefix = inputControl("subnet-prefix", route.prefix, "例如 192.168.10.0/24", "发布的内网网段 " + (index + 1));
      prefix.addEventListener("input", () => { route.prefix = prefix.value; synchronizeForm(); }); prefixLabel.append(element("span", "", "内网网段"), prefix);
      const snatLabel = element("label", "check-label"); const snat = element("input", "subnet-snat"); snat.type = "checkbox"; snat.checked = route.snat;
      snat.addEventListener("change", () => { route.snat = snat.checked; synchronizeForm(); }); snatLabel.append(snat, element("span", "", "源地址转换（SNAT）"));
      card.append(heading, networkLabel, prefixLabel, snatLabel, element("p", "field-hint", "开启后，内网设备看到发布节点的地址；关闭时，内网需有返回虚拟网络的路由。系统不支持时会显示错误。"));
      $("subnet-fields").append(card);
    });
    renderPublishNetworks();
  }
  async function normalizeIntoForm(value, saved = false) {
    try {
      const data = await request("normalize_config", { text: value });
      if (!data || typeof data.text !== "string" || byteSize(data.text) > MAX_CONFIG_BYTES) throw new Error("宿主未返回有效的规范化配置。");
      acceptNormalized(normalizedImport(data.text, value), saved); feedback("配置已校验并应用到表单。", "success");
    } catch (error) { preserveRaw(value, error.message || String(error), saved); throw error; }
  }
  async function copyText(value) {
    let copied = false;
    try { if (navigator.clipboard && navigator.clipboard.writeText) { await navigator.clipboard.writeText(value); copied = true; } } catch (_) { /* Use the native clipboard below. */ }
    if (!copied) await request("copy_text", { text: value });
  }
  function serviceKeyField(owner, className, title = "专用共享密钥（双方一致）") {
    const label = element("div", "form-field"); label.append(element("span", "", title));
    const controls = element("div", "secret-control"); const input = inputControl(className, owner.key, "填写密钥，或生成后交给对应节点", "服务认证共享密钥", "password"); input.autocomplete = "new-password";
    input.addEventListener("input", () => { owner.key = input.value; synchronizeForm(); });
    const show = smallButton("显示", "show-service-key", () => { input.type = input.type === "password" ? "text" : "password"; text(show, input.type === "password" ? "显示" : "隐藏"); show.setAttribute("aria-pressed", String(input.type === "text")); }); show.setAttribute("aria-pressed", "false");
    const generate = smallButton("生成", "generate-key generate-service-key", () => action(async () => {
      if (owner.key && !window.confirm("生成会替换当前密钥，使用它的服务端和客户端都需更新。是否继续？")) return;
      const data = await request("generate_key"); if (!data || typeof data.key !== "string" || !/^[0-9a-f]{64}$/i.test(data.key)) throw new Error("宿主未返回有效的新密钥。");
      owner.key = data.key; input.value = data.key; synchronizeForm(); showToast("已生成新密钥，请更新对应节点。");
    }));
    controls.append(input, show, generate, smallButton("复制", "copy-service-key", () => action(async () => { if (!owner.key) throw new Error("请先填写或生成密钥。"); await copyText(owner.key); showToast("已复制共享密钥。"); })));
    label.append(controls); return label;
  }
  function removeLocalAuthorization(id) {
    formModel.peers.forEach((peer) => peer.ids.delete(id)); formModel.listenIds.delete(id);
  }
  function addressNetworkRows(container, list, className, removed, changed) {
    container.replaceChildren();
    list.forEach((network, index) => {
      const row = element("div", "network-row"); const input = inputControl(className, network.cidr, "例如 10.1.0.0/24", "服务网段 " + (index + 1));
      input.addEventListener("input", () => { network.cidr = input.value; changed(); synchronizeForm(); });
      row.append(input, smallButton("移除", "remove-service-network", () => {
        list.splice(list.indexOf(network), 1); removed(network.id); renderForm(); synchronizeForm();
      })); container.append(row);
    });
  }
  function renderServerAuthorization() {
    document.querySelectorAll(".authorized-client-card").forEach((card, index) => {
      const client = formModel.server.clients[index]; const choices = card.querySelector(".network-choices"); choices.replaceChildren();
      formModel.server.pools.forEach((pool, position) => {
        const label = element("label", "network-choice"); const check = element("input"); check.type = "checkbox"; check.checked = client.ids.has(pool.id);
        check.addEventListener("change", () => { if (check.checked) client.ids.add(pool.id); else client.ids.delete(pool.id); synchronizeForm(); });
        label.append(check, element("span", "", subnetReference(pool.cidr) || "地址池 " + (position + 1) + "（请填写网段）")); choices.append(label);
      });
    });
  }
  function renderAddressForms() {
    $("address-client-fields").replaceChildren();
    formModel.clients.forEach((client, index) => {
      const card = element("section", "service-card address-client-card"); const heading = element("div", "service-card-heading");
      heading.append(element("h4", "", "分配服务 " + (index + 1)), smallButton("移除服务", "remove-address-client", () => {
        client.networks.forEach((network) => removeLocalAuthorization(network.id)); formModel.clients = formModel.clients.filter((item) => item !== client); renderForm(); synchronizeForm();
      }));
      const label = element("label", "form-field"); const input = inputControl("address-client-address", client.address, "例如 100.0.0.1:65534", "分配服务公布地址");
      input.addEventListener("input", () => { client.address = input.value; synchronizeForm(); }); label.append(element("span", "", "分配服务地址"), input);
      const networkTitle = element("div", "service-heading"); networkTitle.append(element("h3", "", "申请网段"), smallButton("＋ 添加网段", "add-requested-network", () => {
        client.networks.push({ id: ++networkSerial, cidr: "" }); renderForm(); synchronizeForm();
      }));
      const networks = element("div", "network-fields"); addressNetworkRows(networks, client.networks, "requested-network", removeLocalAuthorization, renderAuthorization);
      card.append(heading, label, serviceKeyField(client, "address-client-key"), networkTitle, networks); $("address-client-fields").append(card);
    });
    const server = formModel.server;
    $("address-server-enabled").checked = server.enabled; $("address-server-options").hidden = !server.enabled;
    $("address-server-only").checked = formModel.serverOnly; $("server-only-note").hidden = !formModel.serverOnly;
    $("address-server-address").value = server.address; $("address-server-bind").value = server.bind;
    $("address-reclaim").value = server.reclaim; $("address-state-file").value = server.stateFile;
    $("address-auth-mode").value = server.mode;
    $("shared-service-auth").hidden = server.mode !== "shared";
    $("shared-access-export").hidden = server.mode !== "shared";
    $("individual-service-auth").hidden = server.mode !== "individual";
    $("shared-client-address").value = server.exportAddress;
    $("address-shared-key").replaceChildren(serviceKeyField(server, "address-server-key", "接入密钥（所有客户端使用同一把）"));
    addressNetworkRows($("address-pool-fields"), server.pools, "address-pool", (id) => server.clients.forEach((client) => client.ids.delete(id)), renderServerAuthorization);
    $("authorized-client-fields").replaceChildren();
    server.clients.forEach((client, index) => {
      const card = element("section", "service-card authorized-client-card"); const heading = element("div", "service-card-heading");
      heading.append(element("h4", "", "授权节点 " + (index + 1)), smallButton("移除授权", "remove-authorized-client", () => {
        server.clients = server.clients.filter((item) => item !== client); renderForm(); synchronizeForm();
      }));
      const label = element("label", "form-field"); const address = inputControl("authorized-client-address", client.address, "例如 100.0.0.2:65535", "授权节点公布地址");
      address.addEventListener("input", () => { client.address = address.value; synchronizeForm(); }); label.append(element("span", "", "节点公布地址（必须与客户端一致）"), address);
      card.append(heading, label, serviceKeyField(client, "authorized-client-key"), element("p", "field-hint", "允许申请的地址池（新增池不会自动授权）"), element("div", "network-choices"),
        smallButton("导出接入配置", "service-export export-access", () => action(() => exportAccess(client))));
      $("authorized-client-fields").append(card);
    });
    renderServerAuthorization();
  }
  async function exportAccess(client = null) {
    await request("normalize_config", { text: configuration() });
    const server = formModel.server;
    const networkRefs = server.pools.filter((pool) => !client || client.ids.has(pool.id)).map((pool) => subnetReference(pool.cidr) || pool.cidr.trim());
    const value = JSON.stringify({ address: (client ? client.address : server.exportAddress).trim(), address_clients: [{ address: server.address.trim(), shared_key: client ? client.key : server.key, networks: networkRefs }] }, null, 2) + "\n";
    await request("normalize_config", { text: value });
    $("access-export-text").value = value; $("access-export-dialog").showModal();
  }
  async function importAccess(merge) {
    try {
      const raw = $("access-import-text").value;
      if (!raw.trim() || byteSize(raw) > MAX_CONFIG_BYTES) throw new Error("接入配置必须为不超过 1 MiB 的 JSON 文本。");
      const normalized = await request("normalize_config", { text: raw }); const incoming = JSON.parse(normalized.text);
      if (!Array.isArray(incoming.address_clients) || !incoming.address_clients.length) throw new Error("此配置没有地址分配客户端设置，请使用常规 JSON 导入。");
      if (merge) {
        const supplied = JSON.parse(raw);
        const extra = Object.keys(supplied).filter((key) => !["address", "address_clients", "networks", "peers"].includes(key));
        if (extra.length || (supplied.networks && supplied.networks.length) || (supplied.peers && supplied.peers.length)) throw new Error("合并只接受服务端导出的接入配置。完整配置请使用替换操作，原文不会丢失。");
        const current = JSON.parse(configuration());
        if (current.address && current.address !== incoming.address) throw new Error("接入配置的节点公布地址与当前地址不同。请核对地址，或明确选择替换当前配置。");
        current.address = incoming.address;
        if (current.networks) current.networks = current.networks.filter((cidr) => cidr.trim());
        // Freeze old single-network shorthand before adding a managed network.
        (current.peers || []).forEach((peer, index) => {
          if (peer.networks === undefined) peer.networks = localNetworks().filter((network) => formModel.peers[index].ids.has(network.id) && network.cidr.trim()).map((network) => subnetReference(network.cidr) || network.cidr.trim());
        });
        current.address_clients = current.address_clients || [];
        for (const client of incoming.address_clients) {
          const existing = current.address_clients.find((entry) => entry.address === client.address);
          if (existing) {
            if (existing.shared_key !== client.shared_key || JSON.stringify([...existing.networks].sort()) !== JSON.stringify([...client.networks].sort())) throw new Error("此分配服务已有不同的密钥或网段设置；请先手动调整，合并不会覆盖原有授权。");
          } else current.address_clients.push(client);
        }
        const source = JSON.stringify(current);
        const result = await request("normalize_config", { text: source }); acceptNormalized(normalizedImport(result.text, source));
      } else {
        if (!window.confirm("替换会移除当前表单中的 peer、静态网络和服务设置。是否使用这份接入配置？")) return;
        acceptNormalized(normalizedImport(normalized.text, raw));
      }
      $("access-import-dialog").close(); location.hash = "config"; feedback(merge ? "已合并接入配置，原有 peer 和网络授权保持不变；请保存后连接。" : "已替换为接入配置，请确认后保存或连接。", "success");
      showToast("接入配置已载入，尚未连接。");
    } catch (error) {
      text($("access-import-feedback"), error.message || String(error)); $("access-import-feedback").className = "dialog-feedback failure"; throw error;
    }
  }
  function renderAddressStatus(status) {
    const service = status && status.address_service;
    const server = service && service.server; const clients = service && Array.isArray(service.clients) ? service.clients : [];
    $("address-service-panel").hidden = !service || (!(server && server.enabled) && !clients.length);
    const output = $("address-service-status"); output.replaceChildren(); if (!service) return;
    const group = (title, endpoint, label, kind) => {
      const block = element("section", "service-status-group"); const heading = element("div", "service-status-heading");
      const name = element("div"); name.append(element("strong", "", title + " "), element("code", "", endpoint || "—"));
      heading.append(name, element("span", "service-status-tag " + kind, label)); block.append(heading); output.append(block); return block;
    };
    if (server && server.enabled) {
      const block = group("本机分配服务", server.address, server.error ? "服务异常" : server.running ? "服务运行中" : "尚未运行", server.error ? "failed" : server.running ? "ready" : "pending");
      if (server.error) block.append(element("p", "service-status-error", server.error));
      const leases = Array.isArray(server.leases) ? server.leases : [];
      if (!leases.length) block.append(element("p", "field-hint", "尚无地址绑定记录。"));
      leases.forEach((lease) => {
        const row = element("div", "service-assignment");
        row.append(element("code", "", lease.node || "—"), element("span", "", lease.network || "—"), element("code", "", lease.ip || "—"), element("span", "subtle", lease.online ? "在线" : "离线保留"));
        if (!lease.online && typeof lease.reclaim_at === "number" && lease.reclaim_at > 0) row.append(element("span", "subtle", "回收时间 " + new Date(lease.reclaim_at).toLocaleString("zh-CN", { hour12: false })));
        block.append(row);
      });
    }
    const labels = { waiting: "等待分配", connecting: "正在连接服务", connected: "已取得地址", error: "分配失败，等待重试" };
    clients.forEach((client) => {
      const grants = Array.isArray(client.grants) ? client.grants : [];
      const errors = Array.isArray(client.errors) ? client.errors : [];
      const label = errors.length ? (grants.length ? "部分地址已分配" : "地址分配失败") : client.state === "connected" && !grants.length ? "等待分配地址" : labels[client.state] || "等待服务状态";
      const block = group("地址客户端", client.server, label, errors.length ? "failed" : client.state === "connected" && grants.length ? "ready" : client.state === "error" ? "failed" : "pending");
      if (client.error) block.append(element("p", "service-status-error", client.error));
      errors.forEach((error) => block.append(element("p", "service-status-error", (error.network || "未知网段") + "：" + (error.error || "分配失败"))));
      grants.forEach((grant) => { const row = element("div", "service-assignment"); row.append(element("span", "", grant.network || "—"), element("code", "", grant.ip || "—")); block.append(row); });
      if (!grants.length) block.append(element("p", "field-hint", "尚未取得该服务的分配地址；此状态不表示虚拟网络已就绪。"));
    });
  }
  function renderSubnetStatus(status) {
    const local = status && Array.isArray(status.local_exports) ? status.local_exports : [];
    const remote = status && Array.isArray(status.subnet_routes) ? status.subnet_routes : [];
    $("subnet-status-panel").hidden = !local.length && !remote.length;
    const output = $("subnet-status"); output.replaceChildren();
    const row = (entry, localEntry) => {
      const block = element("section", "service-status-group"); const heading = element("div", "service-status-heading");
      const ready = localEntry ? entry.active === true : entry.state === "active";
      const labels = { active: "可访问", standby: "备用入口", pending: "等待入口", error: "访问异常" };
      const label = entry.error ? (localEntry ? "发布失败" : "访问异常") : localEntry ? ready ? "已发布" : "等待发布" : labels[entry.state] || "等待状态";
      const name = element("div"); name.append(element("strong", "", localEntry ? "本机发布 " : "可访问内网 "), element("code", "", entry.prefix || "—"));
      heading.append(name, element("span", "service-status-tag " + (entry.error || entry.state === "error" ? "failed" : ready ? "ready" : "pending"), label)); block.append(heading);
      const detail = element("div", "service-assignment subnet-assignment"); detail.append(element("span", "subtle", "虚拟网络"), element("code", "", entry.network || "—"));
      if (localEntry) detail.append(element("span", "subtle", entry.snat ? "SNAT 已配置" : "保留源地址"));
      else detail.append(element("span", "subtle", "入口节点"), element("code", "", entry.gateway || "—"));
      block.append(detail); if (entry.error) block.append(element("p", "service-status-error", entry.error)); output.append(block);
    };
    local.forEach((entry) => row(entry, true)); remote.forEach((entry) => row(entry, false));
  }
  function renderPeers(peers, hasStatus) {
    text($("peer-count"), peers.length);
    $("peers-empty").hidden = peers.length > 0;
    $("peers-table-wrap").hidden = peers.length === 0;
    const fragment = document.createDocumentFragment();
    peers.forEach((peer) => {
      const row = element("tr");
      const address = element("td");
      const wrap = element("div", "peer-endpoint");
      wrap.append(element("span", "peer-mark", "◇"), element("span", "", peer.node || "未知节点"));
      address.append(wrap);
      const statusCell = element("td");
      const peerState = Number.isInteger(peer.state) && peer.state >= 0 && peer.state < peerLabels.length ? peer.state : 0;
      statusCell.append(element("span", "state-badge state-" + peerState, peerLabels[peerState]));
      const transportCell = element("td", "peer-data-transport", ["udp", "tcp"].includes(peer.transport) ? peer.transport.toUpperCase() : "—");
      row.append(address, statusCell, transportCell); fragment.append(row);
    });
    $("peers-body").replaceChildren(fragment);
    text($("metric-peers"), hasStatus ? peers.filter((peer) => peer.state === 3).length : "—");
    text($("metric-peer-total"), hasStatus ? "/ " + peers.length : "");
    const pending = number(state.status && state.status.pending_connections);
    text($("metric-peer-note"), !hasStatus ? "等待运行状态" : pending ? pending + " 个连接正在握手" : "邻接需通过控制与数据通道验证");
  }
  function renderRoutes(routes, hasStatus) {
    text($("metric-routes"), hasStatus ? routes.length : "—");
    text($("route-count"), routes.length);
    $("routes-empty").hidden = routes.length > 0;
    $("routes-table-wrap").hidden = routes.length === 0;
    const fragment = document.createDocumentFragment();
    let ecmp = 0;
    routes.forEach((route) => {
      const row = element("tr");
      row.append(element("td", "", route.network || "—"), element("td", "", route.node || "—"));
      const hops = Array.isArray(route.next_hops) ? route.next_hops : [];
      const hopCell = element("td"); const hopList = element("div", "route-hops");
      hops.forEach((hop) => hopList.append(element("span", "hop-pill", hop)));
      if (!hops.length) hopList.append(element("span", "subtle", "无可用下一跳"));
      hopCell.append(hopList); row.append(hopCell);
      if (hops.length > 1) ecmp += 1;
      row.append(element("td", "route-mode" + (hops.length > 1 ? " ecmp" : ""), hops.length > 1 ? "ECMP × " + hops.length : hops.length ? "单路径" : "—"));
      fragment.append(row);
    });
    $("routes-body").replaceChildren(fragment);
    text($("metric-route-note"), ecmp ? ecmp + " 个目的地具有等价下一跳" : "按虚拟网络区分目的节点");
  }
  function renderCounters(counters, hasStatus) {
    const entries = Object.entries(counters).filter(([, value]) => typeof value === "number" && Number.isFinite(value)).sort(([a], [b]) => a.localeCompare(b));
    $("counters-empty").hidden = entries.length > 0;
    $("counters-list").hidden = entries.length === 0;
    const fragment = document.createDocumentFragment();
    entries.forEach(([key, value]) => {
      const row = element("div", "counter-row"); const label = element("dt", "", counterNames[key] || key);
      label.title = key; row.append(label, element("dd", "", formatNumber(value))); fragment.append(row);
    });
    $("counters-list").replaceChildren(fragment);
    // A missing runtime counter means no such event occurred; do not invent traffic data.
    const forwarded = Object.prototype.hasOwnProperty.call(counters, "forwarded") ? number(counters.forwarded)
      : number(counters.unicast_forwarded) + number(counters.multicast_forwarded) + number(counters.flood_forwarded);
    text($("metric-forwarded"), hasStatus ? formatNumber(forwarded) : "—");
    const dropped = entries.filter(([key]) => /drop|reject|invalid|oversize/.test(key)).reduce((total, [, value]) => total + value, 0);
    text($("metric-forward-note"), dropped ? "拒绝 / 丢弃事件 " + formatNumber(dropped) : "协议核心累计计数");
  }
  function logLevel(value) {
    const level = String(value || "info").toLowerCase();
    if (level === "warn") return "warning";
    return ["debug", "info", "warning", "error"].includes(level) ? level : "info";
  }
  function logTime(value) {
    if (value == null || value === "") return "—";
    // Hosts may send an already formatted local time, an ISO string, or a Unix timestamp.
    if (typeof value === "string" && /^\d{2}:\d{2}:\d{2}/.test(value)) return value;
    const date = new Date(typeof value === "number" && value < 100000000000 ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleTimeString("zh-CN", { hour12: false });
  }
  function renderLogs(force = false) {
    const search = $("log-search").value.trim().toLowerCase();
    const level = $("log-level").value;
    visibleLogs = logs.filter((line) => (level === "all" || logLevel(line.level) === level) &&
      (!search || (String(line.message || "") + " " + String(line.time || "") + " " + logLevel(line.level)).toLowerCase().includes(search)));
    text($("logs-count"), visibleLogs.length === logs.length ? logs.length : visibleLogs.length + " / " + logs.length);
    $("logs-empty").hidden = visibleLogs.length > 0;
    $("log-output").hidden = visibleLogs.length === 0;
    text($("logs-empty-title"), logs.length ? "没有匹配的日志" : "暂无日志");
    text($("logs-empty-detail"), logs.length ? "调整关键字或级别后重试。" : "启动网络后，运行记录会显示在这里。");
    // Preserve selection and scroll position when the host returns the same log snapshot.
    const signature = JSON.stringify(visibleLogs);
    if (!force && signature === lastLogsSignature) { updateControls(); return; }
    lastLogsSignature = signature;
    const output = $("log-output"); const oldScroll = output.scrollTop;
    const fragment = document.createDocumentFragment();
    visibleLogs.forEach((line) => {
      const row = element("div", "log-line"); const normalized = logLevel(line.level);
      const time = element("time", "log-time", logTime(line.time)); time.title = String(line.time || "");
      row.append(time, element("span", "log-level " + normalized, normalized === "warning" ? "WARN" : normalized.toUpperCase()), element("span", "log-message", line.message || ""));
      fragment.append(row);
    });
    output.replaceChildren(fragment);
    output.scrollTop = $("follow-logs").checked ? output.scrollHeight : oldScroll;
    updateControls();
  }
  function renderState(next) {
    if (!next || typeof next !== "object") throw new Error("宿主未返回有效运行状态。");
    state = next;
    if (!Object.prototype.hasOwnProperty.call(phaseLabels, state.phase)) state.phase = "error";
    const status = state.status && typeof state.status === "object" && typeof state.status.running === "boolean" ? state.status : null;
    const stale = state.status_stale === true && !!status;
    const peers = status && Array.isArray(status.peers) ? status.peers : [];
    const routes = status && Array.isArray(status.routes) ? status.routes : [];
    const sessions = status && Array.isArray(status.end_sessions) ? status.end_sessions : [];
    const counters = status && status.counters && typeof status.counters === "object" ? status.counters : {};
    const overlayErrors = [];
    if (status && typeof status.device_error === "string" && status.device_error) overlayErrors.push("隧道设备：" + status.device_error);
    if (status && status.address_errors && typeof status.address_errors === "object") {
      Object.entries(status.address_errors).forEach(([network, error]) => {
        if (typeof error === "string" && error) overlayErrors.push(network + "：" + error);
      });
    }
    $("phase-pill").dataset.phase = state.phase;
    $("phase-pill").classList.toggle("stale", stale);
    $("phase-pill").classList.toggle("degraded", !!overlayErrors.length);
    text($("phase-label"), stale ? "状态更新延迟" : overlayErrors.length ? "隧道异常" : phaseLabels[state.phase]);
    text($("local-address"), status && status.node || "—"); text($("local-device"), status && status.device || "—");
    text($("local-platform"), state.platform || "—"); text($("host-label"), state.platform ? state.platform + " 本机宿主" : "本机宿主已连接");
    text($("config-path"), state.config_path || "应用私有配置");
    text($("metric-sessions"), status ? sessions.filter((session) => session.ready === true).length : "—");
    const pendingSessions = sessions.filter((session) => session.ready !== true).length;
    text($("metric-session-note"), pendingSessions ? pendingSessions + " 个端到端会话正在协商" : "端到端会话按需建立");
    text($("refresh-status"), stale ? "核心状态未更新 · 最后快照" : status ? "最近更新 " + new Date().toLocaleTimeString("zh-CN", { hour12: false }) : "尚无运行状态");
    text($("footer-status"), stale ? "核心状态待更新 · 显示最后快照" : phaseLabels[state.phase] + " · 每秒更新");
    const error = [(typeof state.error === "string" ? state.error : ""), ...overlayErrors,
      stale ? "核心状态已超过 3 秒未更新，以下连接和计数为最后一次快照。" : ""].filter(Boolean).join("\n");
    $("error-notice").hidden = !error; text($("runtime-error"), error);
    renderPeers(peers, !!status); renderRoutes(routes, !!status); renderCounters(counters, !!status); renderAddressStatus(status); renderSubnetStatus(status);
    if (stale) text($("metric-peer-note"), "上次快照，等待核心更新");
    logs = Array.isArray(state.logs) ? state.logs.filter((line) => line && typeof line === "object") : [];
    if (state.remote_desktop) renderRemoteState(state.remote_desktop);
    renderLogs(); updateControls();
  }
  function renderRemoteAccess() {
    text($("remote-access-notice"), formModel.remote.access === "all_tunnel_nodes"
      ? "所选虚拟网络的有效成员均可控制本机；开启无人值守后无需逐次确认。公网访客与其他网络不在此范围内。"
      : "仅已授权设备可无人值守连接；新设备的请求在下方确认。关闭无人值守时每次仍需本机批准。");
  }
  function renderRemoteState(value) {
    remoteState = value && typeof value === "object" ? value : {};
    const signature = JSON.stringify(remoteState);
    if (signature === remoteSignature) return;
    remoteSignature = signature;
    const identity = remoteState.identity || {};
    text($("remote-identity"), identity.fingerprint ? (identity.name || "本机设备") + " · " + identity.fingerprint : "启动网络后显示本机设备指纹。");
    const enabled = remoteState.enabled === true || !!(remoteState.config && remoteState.config.enabled);
    text($("remote-service-state"), remoteState.error ? "服务异常" : enabled ? "允许连接本机" : "本机被控已关闭");
    $("remote-service-state").className = "service-status-tag " + (remoteState.error ? "failed" : enabled ? "ready" : "");
    if (remoteState.error) text($("remote-message"), remoteState.error);
    const rows = (id, entries, empty, build) => {
      const container = $(id); container.replaceChildren();
      if (!Array.isArray(entries) || !entries.length) { container.append(element("p", "field-hint", empty)); return; }
      entries.forEach((entry) => {
        const row = element("div", "remote-device-row");
        const description = element("div", "remote-device-description");
        description.append(element("strong", "", entry.name || entry.device_name || entry.address || "远程设备"), element("code", "remote-fingerprint", entry.fingerprint || ""));
        if (entry.tunnel || entry.network || entry.permission) description.append(element("span", "field-hint", [entry.tunnel || entry.network, entry.permission === "view" ? "仅查看" : entry.permission === "control" ? "键鼠控制" : ""].filter(Boolean).join(" · ")));
        row.append(description); build(row, entry); container.append(row);
      });
    };
    rows("remote-pending", remoteState.pending, "暂无连接请求。", (row, entry) => {
      const actions = element("div", "remote-row-actions"); const permission = element("select", "form-input remote-permission"); permission.setAttribute("aria-label", "授予设备权限");
      for (const [value, label] of [["view", "只查看"], ["control", "查看并控制"]]) { const option = element("option", "", label); option.value = value; permission.append(option); }
      permission.value = (entry.permission || entry.requested) === "view" ? "view" : "control";
      const rememberLabel = element("label", "check-label"); const remember = element("input"); remember.type = "checkbox"; remember.checked = true; rememberLabel.append(remember, element("span", "", "记住此设备"));
      const authorize = smallButton("允许连接", "remote-approve", () => action(async () => { await request("remote_authorize", { request_id: entry.request_id || entry.id, permission: permission.value, remember: remember.checked }); await refreshRemote(); }));
      const deny = smallButton("拒绝", "remote-deny", () => action(async () => { await request("remote_reject", { request_id: entry.request_id || entry.id }); await refreshRemote(); }));
      actions.append(permission, rememberLabel, authorize, deny); row.append(actions);
    });
    rows("remote-devices", remoteState.devices, "暂无已授权设备。", (row, entry) => {
      const allNodes = remoteState.config && remoteState.config.access === "all_tunnel_nodes";
      row.append(smallButton(allNodes ? "移出设备名单" : "撤销授权", "remote-revoke", () => action(async () => { await request("remote_revoke", { fingerprint: entry.fingerprint }); await refreshRemote(); showToast(allNodes ? "已移出名单；当前全网络模式仍允许此节点连接。" : "已撤销授权并终止对应会话。"); })));
    });
    rows("remote-sessions", remoteState.sessions, "暂无会话。", (row, entry) => {
      row.append(smallButton("终止会话", "remote-terminate", () => action(async () => { await request("remote_terminate", { session_id: entry.session_id || entry.id }); await refreshRemote(); })));
    });
  }
  async function refreshRemote() {
    if (androidHost()) { text($("remote-message"), "本版远程桌面需要 Windows、Linux 或 macOS 桌面宿主。"); return; }
    renderRemoteState(await request("remote_state"));
  }
  function sessionId(value) { return value && (value.session_id || value.id); }
  async function connectRemote() {
    const payload = { address: $("remote-target").value.trim(), tunnel: $("remote-target-network").value,
      port: Number($("remote-target-port").value || 47831), permission: $("remote-view-only").checked ? "view" : "control" };
    if (!payload.address || !payload.tunnel) throw new Error("请填写对端虚拟 IP 并选择虚拟网络。");
    text($("remote-message"), "正在验证对端身份…");
    let connected = await request("remote_connect", payload);
    if (connected && connected.trust_required) {
      const identity = connected.identity || {};
      if (!identity.fingerprint) throw new Error("对端未提供有效设备指纹。");
      if (!window.confirm("首次连接此设备，请与对端显示的指纹核对：\n\n" + (identity.name || payload.address) + "\n" + identity.fingerprint + "\n\n确认后记住此设备身份。")) { text($("remote-message"), "已取消身份确认。"); return; }
      await request("remote_trust", { fingerprint: identity.fingerprint });
      connected = await request("remote_connect", payload);
    }
    if (!sessionId(connected)) throw new Error(connected && connected.message || "未能建立桌面会话。");
    remoteSession = { ...connected, address: payload.address, permission: connected.permission || payload.permission, payload };
    remoteFrameSequence = -1; $("remote-image").hidden = true; $("remote-frame-wait").hidden = false; $("remote-image").removeAttribute("src");
    $("remote-viewer").hidden = false; text($("remote-viewer-title"), payload.address + (remoteSession.permission === "view" ? " · 仅查看" : " · 远程控制"));
    text($("remote-message"), connected.pending ? "等待对端批准连接…" : "连接已建立，正在获取画面…");
    remoteFrame(); updateControls();
  }
  async function disconnectRemote() {
    const previous = remoteSession;
    if (!previous) return;
    await sendRemoteInput({ type: "release_all" });
    await request("remote_disconnect", { session_id: sessionId(previous) });
    resetRemoteViewer("远程桌面已断开。");
  }
  function resetRemoteViewer(message) {
    remoteSession = null; remoteInputQueue = []; clearTimeout(remoteFrameTimer);
    $("remote-viewer").hidden = true; $("remote-image").removeAttribute("src"); text($("remote-message"), message); updateControls();
  }
  async function remoteFrame() {
    clearTimeout(remoteFrameTimer);
    if (!remoteSession || remoteFrameBusy) return;
    const current = sessionId(remoteSession); remoteFrameBusy = true;
    try {
      const frame = await request("remote_frame", { session_id: current, after: remoteFrameSequence });
      if (!remoteSession || sessionId(remoteSession) !== current) return;
      if (frame.error || ["closed", "error", "disconnected"].includes(frame.status)) throw new Error(frame.error || "远程连接已结束。");
      if (frame.status === "trust_required") {
        const identity = frame.identity || {};
        if (!identity.fingerprint) throw new Error("对端未提供有效设备指纹。");
        if (!window.confirm("首次连接此设备，请与对端显示的指纹核对：\n\n" + (identity.name || remoteSession.address) + "\n" + identity.fingerprint + "\n\n确认后记住此设备身份。")) { await disconnectRemote(); return; }
        await request("remote_trust", { fingerprint: identity.fingerprint });
        const payload = remoteSession.payload;
        const connected = await request("remote_connect", payload);
        if (!sessionId(connected)) throw new Error("未能建立桌面会话。");
        remoteSession = { ...connected, address: payload.address, payload, permission: connected.permission || payload.permission }; remoteFrameSequence = -1;
        return;
      }
      if (frame.permission) remoteSession.permission = frame.permission;
      text($("remote-viewer-title"), remoteSession.address + (remoteSession.permission === "view" ? " · 仅查看" : " · 远程控制"));
      if (frame.jpeg) {
        if (typeof frame.jpeg !== "string" || frame.jpeg.length > 16 * 1024 * 1024 || !/^[A-Za-z0-9+/=]+$/.test(frame.jpeg)) throw new Error("收到无效的画面数据。");
        remoteFrameSequence = frame.sequence; $("remote-image").src = "data:image/jpeg;base64," + frame.jpeg;
        $("remote-image").hidden = false; $("remote-frame-wait").hidden = true;
        text($("remote-message"), remoteSession.permission === "view" ? "正在查看屏幕，无键鼠控制权限。" : "已连接。点击画面以操作远程键盘与鼠标。");
      } else if (frame.status === "pending") text($("remote-frame-wait"), "等待对端批准连接…");
    } catch (error) { if (remoteSession && sessionId(remoteSession) === current) resetRemoteViewer(error.message || String(error)); }
    finally { remoteFrameBusy = false; if (remoteSession) remoteFrameTimer = setTimeout(remoteFrame, document.hidden ? 500 : 100); }
  }
  async function sendRemoteInput(event) {
    if (!remoteSession || remoteSession.permission === "view") return;
    const current = sessionId(remoteSession);
    // Coalesce pointer movement; preserve key/button transitions in order.
    if (event.type === "mouse_move" && remoteInputQueue.length && remoteInputQueue[remoteInputQueue.length - 1].type === "mouse_move") remoteInputQueue[remoteInputQueue.length - 1] = event;
    else if (event.type === "release_all") remoteInputQueue = [event];
    else if (remoteInputQueue.length < 128) remoteInputQueue.push(event);
    else { remoteInputQueue = [{ type: "release_all" }]; }
    if (remoteInputBusy) return;
    remoteInputBusy = true;
    try {
      while (remoteInputQueue.length && remoteSession && sessionId(remoteSession) === current) await request("remote_input", { session_id: current, event: remoteInputQueue.shift() });
    } catch (error) { remoteInputQueue = []; text($("remote-message"), error.message || String(error)); }
    finally { remoteInputBusy = false; }
  }
  function remotePosition(event) {
    const image = $("remote-image"); if (image.hidden || !image.naturalWidth) return null;
    const bounds = image.getBoundingClientRect();
    return { x: Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width)), y: Math.max(0, Math.min(1, (event.clientY - bounds.top) / bounds.height)) };
  }
  async function poll() {
    clearTimeout(pollTimer);
    if (!bridgeReady || polling) return;
    polling = true;
    try {
      renderState(await request("get_state")); pollFailures = 0;
      $("host-notice").hidden = true;
    } catch (error) {
      pollFailures += 1;
      text($("footer-status"), "状态更新失败，正在重试");
      if (pollFailures >= 2) {
        $("host-notice").hidden = false;
        text($("host-notice-title"), "暂时无法获取本机状态");
        text($("host-notice-detail"), error.message || String(error));
      }
    } finally { polling = false; pollTimer = setTimeout(poll, 1000); }
  }
  async function initializeBridge() {
    if (initialized || !hostAvailable()) return;
    initialized = true; bridgeReady = true; document.body.classList.add("bridge-ready"); updateControls();
    try { await loadConfig(); }
    catch (error) { feedback(error.message || String(error), "failure"); showToast(error.message || String(error), true); }
    await poll();
  }
  document.querySelectorAll("[data-page]").forEach((button) => button.addEventListener("click", () => { location.hash = button.dataset.page; }));
  document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => { location.hash = button.dataset.go; }));
  window.addEventListener("hashchange", () => navigate(location.hash.slice(1)));
  $("config-editor").addEventListener("input", () => editorChanged());
  $("config-editor").addEventListener("keydown", (event) => {
    // Keep Tab's native focus navigation. Ctrl/Cmd+S saves the editor.
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") { event.preventDefault(); if (!$("save-config").disabled) $("save-config").click(); }
  });
  $("reload-config").addEventListener("click", () => action(() => loadConfig(true)));
  for (const [id, property] of [["local-endpoint", "address"], ["bind-address", "bind"], ["tun-mtu", "tunMtu"], ["transport-mtu", "transportMtu"], ["device-backend", "deviceBackend"]]) {
    $(id).addEventListener(id === "device-backend" ? "change" : "input", () => { if (formModel) { formModel[property] = $(id).value; synchronizeForm(); } });
  }
  $("listen-enabled").addEventListener("change", () => { formModel.listenEnabled = $("listen-enabled").checked; synchronizeForm(); });
  for (const [id, property] of [["remote-enabled", "enabled"], ["remote-unattended", "unattended"]]) {
    $(id).addEventListener("change", () => { formModel.remote.present = true; formModel.remote[property] = $(id).checked; if (property === "enabled" && $(id).checked && localNetworks().length === 1 && !formModel.remote.ids.size) { formModel.remote.ids.add(localNetworks()[0].id); renderAuthorization(); } synchronizeForm(); });
  }
  for (const [id, property] of [["remote-access", "access"], ["remote-device-name", "name"], ["remote-port", "port"]]) {
    $(id).addEventListener(id === "remote-access" ? "change" : "input", () => { formModel.remote.present = true; formModel.remote[property] = $(id).value; renderRemoteAccess(); synchronizeForm(); });
  }
  $("remote-save").addEventListener("click", () => action(saveConfiguration));
  $("remote-refresh").addEventListener("click", () => action(refreshRemote));
  $("remote-remove-unsupported").addEventListener("click", () => { formModel.remote = { ...formModel.remote, present: false, enabled: false }; renderForm(); synchronizeForm(); });
  $("remote-connect").addEventListener("click", () => action(connectRemote));
  $("remote-disconnect").addEventListener("click", () => action(disconnectRemote));
  $("remote-fullscreen").addEventListener("click", () => { const expanded = $("remote-viewer").classList.toggle("expanded"); text($("remote-fullscreen"), expanded ? "恢复窗口" : "放大画面"); });
  $("remote-screen").addEventListener("pointermove", (event) => { const position = remotePosition(event); if (position) sendRemoteInput({ type: "mouse_move", ...position }); });
  for (const [name, down] of [["pointerdown", true], ["pointerup", false]]) $("remote-screen").addEventListener(name, (event) => {
    const position = remotePosition(event); if (!position || ![0, 1, 2].includes(event.button) || !remoteSession || remoteSession.permission === "view") return;
    event.preventDefault(); $("remote-screen").focus({ preventScroll: true });
    if (down) $("remote-screen").setPointerCapture(event.pointerId);
    sendRemoteInput({ type: "mouse_move", ...position }); sendRemoteInput({ type: "mouse_button", button: ["left", "middle", "right"][event.button], down });
    if (!down && $("remote-screen").hasPointerCapture(event.pointerId)) $("remote-screen").releasePointerCapture(event.pointerId);
  });
  $("remote-screen").addEventListener("contextmenu", (event) => event.preventDefault());
  $("remote-screen").addEventListener("wheel", (event) => { if (remoteSession && remoteSession.permission !== "view") { event.preventDefault(); sendRemoteInput({ type: "wheel", dx: Math.sign(event.deltaX), dy: -Math.sign(event.deltaY) }); } }, { passive: false });
  for (const [name, down] of [["keydown", true], ["keyup", false]]) $("remote-screen").addEventListener(name, (event) => {
    if (!remoteSession || remoteSession.permission === "view" || !event.code) return;
    event.preventDefault(); event.stopPropagation(); sendRemoteInput({ type: "key", key: event.code, down });
  });
  for (const name of ["blur", "pointercancel"]) $("remote-screen").addEventListener(name, () => sendRemoteInput({ type: "release_all" }));
  window.addEventListener("blur", () => sendRemoteInput({ type: "release_all" }));
  document.addEventListener("visibilitychange", () => { if (document.hidden) sendRemoteInput({ type: "release_all" }); });
  $("listen-all").addEventListener("change", () => {
    formModel.listenAll = $("listen-all").checked;
    if (!formModel.listenAll) formModel.listenIds = new Set(localNetworks().map((network) => network.id));
    renderAuthorization(); synchronizeForm();
  });
  $("add-network").addEventListener("click", () => {
    if (formModel.networks.length >= 64) { showToast("最多支持 64 个虚拟网络。", true); return; }
    formModel.networks.push({ id: ++networkSerial, cidr: "" });
    renderForm(); synchronizeForm(); $("network-fields").lastElementChild.querySelector("input").focus();
  });
  $("add-peer").addEventListener("click", () => {
    if (formModel.peers.length >= 256) { showToast("最多支持 256 个连接节点。", true); return; }
    const networks = localNetworks();
    formModel.peers.push({ address: "", key: "", transport: "udp", ids: new Set(networks.length === 1 ? [networks[0].id] : []) });
    renderForm(); synchronizeForm(); $("peer-fields").lastElementChild.querySelector("input").focus();
  });
  $("apply-json").addEventListener("click", () => action(async () => { await normalizeIntoForm(configuration(true)); showToast("JSON 配置已应用到表单。"); }));
  $("discard-json").addEventListener("click", () => {
    if (!window.confirm("放弃尚未应用的 JSON 修改，恢复表单内容？")) return;
    if (!formModel) formModel = blankModel(); renderForm(); synchronizeForm();
  });
  $("add-address-client").addEventListener("click", () => {
    if (formModel.clients.length >= 256) { showToast("地址分配服务配置数量已达上限。", true); return; }
    // Empty placeholder rows are not static addresses and need not block DHCP-like setup.
    formModel.networks.filter((network) => !network.cidr.trim()).forEach((network) => removeLocalAuthorization(network.id));
    formModel.networks = formModel.networks.filter((network) => network.cidr.trim());
    formModel.clients.push({ address: "", key: "", networks: [{ id: ++networkSerial, cidr: "" }] }); renderForm(); synchronizeForm();
  });
  $("add-subnet").addEventListener("click", () => {
    if (androidHost()) { showToast("Android 只能访问内网，不支持发布本机内网。", true); return; }
    const networks = localNetworks(); const selected = networks.length === 1 ? networks[0] : null;
    formModel.published.push({ networkId: selected ? selected.id : null, tunnel: selected ? subnetReference(selected.cidr) || selected.cidr.trim() : "", prefix: "", snat: false });
    renderForm(); synchronizeForm(); $("subnet-fields").lastElementChild.querySelector(".subnet-prefix").focus();
  });
  $("address-server-enabled").addEventListener("change", () => {
    formModel.server.enabled = $("address-server-enabled").checked;
    if (!formModel.server.enabled) formModel.serverOnly = false;
    renderForm(); synchronizeForm();
  });
  $("address-server-only").addEventListener("change", () => {
    const selected = $("address-server-only").checked;
    if (selected && (formModel.address || formModel.peers.length || formModel.clients.length || formModel.published.length || formModel.networks.some((network) => network.cidr.trim())) &&
        !window.confirm("仅服务模式保存后不再包含本机隧道地址、peer、内网发布和自动申请配置；当前窗口可切回恢复这些编辑内容。是否继续？")) { $("address-server-only").checked = false; return; }
    formModel.serverOnly = selected; renderForm(); synchronizeForm();
  });
  $("address-auth-mode").addEventListener("change", () => {
    const selected = $("address-auth-mode").value;
    if (selected === formModel.server.mode) return;
    const message = selected === "shared" ? "共享模式允许持钥节点申请全部地址池，现有逐节点限制将不再生效。切换授权方式？" : "逐节点模式只允许已列出的节点接入，需为每个节点设置密钥和地址池。切换授权方式？";
    if (!window.confirm(message)) { $("address-auth-mode").value = formModel.server.mode; return; }
    formModel.server.mode = selected; renderForm(); synchronizeForm();
  });
  $("shared-client-address").addEventListener("input", () => { formModel.server.exportAddress = $("shared-client-address").value; });
  $("export-shared-access").addEventListener("click", () => action(() => exportAccess()));
  for (const [id, property] of [["address-server-address", "address"], ["address-server-bind", "bind"], ["address-reclaim", "reclaim"], ["address-state-file", "stateFile"]]) {
    $(id).addEventListener("input", () => { formModel.server[property] = $(id).value; synchronizeForm(); });
  }
  $("add-address-pool").addEventListener("click", () => { formModel.server.pools.push({ id: ++networkSerial, cidr: "" }); renderForm(); synchronizeForm(); });
  $("add-authorized-client").addEventListener("click", () => {
    formModel.server.clients.push({ address: "", key: "", ids: new Set(formModel.server.pools.length === 1 ? [formModel.server.pools[0].id] : []) }); renderForm(); synchronizeForm();
  });
  $("open-access-import").addEventListener("click", () => {
    $("access-import-feedback").className = "dialog-feedback";
    text($("access-import-feedback"), "合并会保留已有静态网络、peer 和监听设置；不会静默覆盖密钥。"); $("access-import-dialog").showModal();
  });
  $("close-access-import").addEventListener("click", () => $("access-import-dialog").close());
  $("close-access-export").addEventListener("click", () => $("access-export-dialog").close());
  $("copy-access-export").addEventListener("click", () => action(async () => { await copyText($("access-export-text").value); showToast("已复制节点接入配置。"); }));
  $("merge-access").addEventListener("click", () => action(() => importAccess(true)));
  $("replace-access").addEventListener("click", () => action(() => importAccess(false)));
  $("choose-access-file").addEventListener("click", () => $("access-file").click());
  $("access-file").addEventListener("change", () => {
    const file = $("access-file").files && $("access-file").files[0]; $("access-file").value = ""; if (!file) return;
    if (file.size > MAX_CONFIG_BYTES) { text($("access-import-feedback"), "配置文件不能超过 1 MiB。"); return; }
    const reader = new FileReader(); reader.onerror = () => { text($("access-import-feedback"), "无法读取选择的接入配置。"); };
    reader.onload = () => { if (busy) { text($("access-import-feedback"), "其他操作正在进行，请稍后重新选择文件。"); return; } $("access-import-text").value = String(reader.result || "").replace(/^\uFEFF/, ""); };
    reader.readAsText(file, "UTF-8");
  });
  $("import-config").addEventListener("click", () => $("config-file").click());
  $("config-file").addEventListener("change", () => {
    const file = $("config-file").files && $("config-file").files[0]; $("config-file").value = "";
    if (!file) return;
    if (file.size > MAX_CONFIG_BYTES) { showToast("配置文件不能超过 1 MiB。", true); return; }
    if ((formModel.address || formModel.server.enabled || $("config-editor").value !== savedText) && !window.confirm("导入将替换当前配置，包括已有 peer 和网络授权。是否继续？")) return;
    const revision = configRevision;
    const reader = new FileReader();
    reader.onerror = () => showToast("无法读取选择的配置文件。", true);
    reader.onload = () => {
      if (configRevision !== revision) { showToast("读取期间配置已被编辑，未覆盖当前内容。", true); return; }
      const value = String(reader.result || "").replace(/^\uFEFF/, "");
      if (byteSize(value) > MAX_CONFIG_BYTES) { showToast("配置文件不能超过 1 MiB。", true); return; }
      action(async () => {
        await normalizeIntoForm(value);
        feedback("已导入 " + file.name + "，请确认表单并保存。", "success"); showToast("已导入配置。");
      });
    };
    reader.readAsText(file, "UTF-8");
  });
  $("validate-config").addEventListener("click", () => action(async () => {
    try { const data = await request("validate_config", { text: configuration(true) }); feedback(responseMessage(data, jsonPending ? "JSON 校验通过，请应用到表单。" : "配置校验通过。"), "success"); showToast("配置校验通过。"); }
    catch (error) { feedback(error.message || String(error), "failure"); throw error; }
  }));
  $("save-config").addEventListener("click", () => action(saveConfiguration));
  $("connection-button").addEventListener("click", () => action(async () => {
    if (state.phase === "running" || state.phase === "stopping") {
      const data = await request("stop"); showToast(responseMessage(data, "已提交停止请求。"));
    } else {
      try {
        const value = configuration(); publishSupported(); const data = await request("start", { text: value });
        savedText = value; savedRevision = data ? data.revision : undefined; editorChanged(); feedback("配置已保存，启动结果请查看网络概览。", "success");
        showToast(responseMessage(data, "已提交启动请求。")); location.hash = "overview";
      } catch (error) { feedback(error.message || String(error), "failure"); throw error; }
    }
    await poll();
  }));
  $("clear-logs").addEventListener("click", () => action(async () => { await request("clear_logs"); await poll(); showToast("已清空日志。"); }));
  $("copy-logs").addEventListener("click", () => action(async () => {
    const value = visibleLogs.map((line) => "[" + logTime(line.time) + "] [" + logLevel(line.level).toUpperCase() + "] " + String(line.message || "")).join("\n");
    if (!value) return;
    await copyText(value);
    showToast("已复制当前筛选结果。");
  }));
  $("log-search").addEventListener("input", () => renderLogs(true));
  $("log-level").addEventListener("change", () => renderLogs(true));
  $("follow-logs").addEventListener("change", () => { if ($("follow-logs").checked) $("log-output").scrollTop = $("log-output").scrollHeight; });
  window.addEventListener("pywebviewready", initializeBridge);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && bridgeReady) poll(); });
  formModel = blankModel(); renderForm(); synchronizeForm(true);
  navigate(location.hash.slice(1)); initializeBridge();
  setTimeout(() => {
    if (initialized) return;
    if (hostAvailable()) { initializeBridge(); return; }
    text($("phase-label"), "开发预览");
    text($("host-notice-title"), "界面预览 · 未连接本机宿主");
    text($("host-notice-detail"), "此页面未运行隧道。请通过 Tunnel 桌面应用或 Android 应用打开；预览中可查看界面和编辑配置。");
    text($("footer-status"), "开发预览 · 无运行数据");
  }, 1500);
})();
