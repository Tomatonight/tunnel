#!/usr/bin/env node
"use strict";

// Offline browser regression. Uses fixture bridge responses; never starts a VPN.
// Install Playwright separately or point --playwright at an existing package.
// node tests/gui_frontend_test.js --browser /path/to/chrome
// Optional: --playwright /path/to/node_modules/playwright --output build/gui-tests/frontend
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const root = path.resolve(__dirname, "..");
const options = { output: path.join(root, "build", "gui-tests", "frontend"), browser: process.env.CHROME_PATH, playwright: process.env.PLAYWRIGHT_MODULE };
for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (arg === "--help") {
    console.log("Usage: node tests/gui_frontend_test.js [--browser CHROME_PATH] [--playwright MODULE_PATH] [--output DIRECTORY]\n" +
      "Uses installed system Chrome/Edge or Playwright Chromium; no downloads.\n" +
      "CHROME_PATH and PLAYWRIGHT_MODULE are also supported. No TUN privileges are required.");
    process.exit(0);
  }
  if (!["--browser", "--playwright", "--output"].includes(arg) || !process.argv[i + 1]) throw new Error("Unknown or incomplete option: " + arg);
  options[arg.slice(2)] = process.argv[++i];
}
options.output = path.resolve(options.output);

function browserExecutable() {
  if (options.browser) return path.resolve(options.browser);
  const candidates = process.platform === "win32" ? [
    path.join(process.env.PROGRAMFILES || "C:/Program Files", "Google/Chrome/Application/chrome.exe"),
    path.join(process.env["PROGRAMFILES(X86)"] || "C:/Program Files (x86)", "Microsoft/Edge/Application/msedge.exe"),
    path.join(process.env.LOCALAPPDATA || "", "Google/Chrome/Application/chrome.exe")
  ] : process.platform === "darwin" ? [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
  ] : ["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser"];
  return candidates.find((candidate) => fs.existsSync(candidate));
}

async function main() {
  fs.mkdirSync(options.output, { recursive: true });
  const report = { ok: false, kind: "offline frontend contract tests; fixture data only", checks: [], page_errors: [], screenshots: [], browser: browserExecutable() || "Playwright Chromium" };
  let browser;
  try {
    let playwright;
    try { playwright = require(options.playwright ? path.resolve(options.playwright) : "playwright"); }
    catch (_) { throw new Error("Playwright package is unavailable. Install it or set --playwright /path/to/node_modules/playwright."); }
    browser = await playwright.chromium.launch({ executablePath: browserExecutable(), headless: true });
    const page = await browser.newPage({ viewport: { width: 1360, height: 1000 } });
    page.setDefaultTimeout(10000);
    const observe = (target) => target.on("pageerror", (error) => report.page_errors.push(error.message));
    observe(page);
    page.on("dialog", (dialog) => dialog.accept());
    await page.addInitScript(() => {
      window.__calls = [];
      window.__TUNNEL_UI_TOKEN__ = "frontend-test-page-token";
      window.__config = JSON.stringify({ address: "192.0.2.1:65535", networks: ["10.1.0.1/24"], peers: [{ address: "192.0.2.2:65535", shared_key: "a".repeat(64) }] });
      window.__revision = "0".repeat(64);
      // Minimal host-contract fixture. C++ parser correctness is covered separately.
      const normalized = (text) => {
        let doc; try { doc = JSON.parse(text); } catch (_) { throw new Error("invalid JSON"); }
        if (doc.listen && doc.listen.address) {
          const local = new Map();
          const networks = (items) => items.map((item) => {
            local.set(item.tunnel, item.tunnel_ip + "/" + item.tunnel.split("/")[1]); return item.tunnel;
          });
          const inbound = networks(doc.listen.networks);
          const peers = doc.peers.map((peer) => ({ address: peer.address, shared_key: peer.shared_key, networks: networks(peer.networks) }));
          return { address: doc.listen.address, networks: Array.from(local.values()), peers, listen: { enabled: doc.listen.enabled, networks: inbound }, device_backend: doc.device_backend || "tun" };
        }
        if (!doc || typeof doc !== "object" || Object.keys(doc).some((key) => !["address", "networks", "peers", "listen", "tun_mtu", "transport_mtu", "address_server", "address_clients", "advertise_routes", "remote_desktop", "device_backend"].includes(key))) throw new Error("unknown configuration field");
        if (doc.device_backend !== undefined && !["tun", "kernel"].includes(doc.device_backend)) throw new Error("device_backend must be tun or kernel");
        // This fixture represents a Windows core. Normalized output freezes
        // the effective platform default instead of erasing explicit TUN.
        if (doc.device_backend === undefined) doc.device_backend = "tun";
        const local = (doc.networks || []).concat((doc.address_clients || []).flatMap((client) => client.networks));
        const serverOnly = doc.address_server && !Object.prototype.hasOwnProperty.call(doc, "address");
        if (!serverOnly && (!doc.address || !local.length || local.some((value) => !value))) throw new Error("address and networks required");
        for (const client of doc.address_clients || []) {
          if (!client.address || !client.shared_key || !Array.isArray(client.networks) || !client.networks.length) throw new Error("address client requires endpoint, key and networks");
        }
        if (doc.address_server) {
          const service = doc.address_server;
          if (!service.address || !Array.isArray(service.networks) || !service.networks.length || service.networks.some((network) => !network)) throw new Error("server requires endpoint and pools");
          const shared = Object.prototype.hasOwnProperty.call(service, "shared_key");
          if (shared && (typeof service.shared_key !== "string" || !service.shared_key || service.clients !== undefined)) throw new Error("shared_key and clients are mutually exclusive and shared_key cannot be empty");
          for (const client of service.clients || []) {
            if (!client.address || !client.shared_key || !Array.isArray(client.networks) || !client.networks.length || client.networks.some((network) => !service.networks.includes(network))) throw new Error("server client requires endpoint, key and authorized pool");
          }
          if (!shared) service.clients = service.clients || [];
        }
        for (const peer of doc.peers || []) {
          if (peer.transport !== undefined && !["udp", "tcp"].includes(peer.transport)) throw new Error("peer transport must be udp or tcp");
          if (peer.transport === "udp") delete peer.transport;
          if (peer.networks && !peer.networks.length) throw new Error("peer needs at least one network");
          if (!peer.networks && local.length > 1) throw new Error("multi-network authorization required");
        }
        const ref = (cidr) => {
          if (!cidr.includes(":")) {
            const [address, prefix] = cidr.split("/"); const words = address.split(".").map(Number);
            let bits = Number(prefix); return words.map((word) => { const keep = Math.min(8, Math.max(0, bits)); bits -= 8; return word & (keep ? 255 << (8 - keep) : 0); }).join(".") + "/" + prefix;
          }
          return cidr;
        };
        for (const route of doc.advertise_routes || []) {
          if (Object.keys(route).some((key) => !["tunnel", "prefix", "snat"].includes(key))) throw new Error("unknown advertised route field");
          if (!local.map(ref).includes(route.tunnel)) throw new Error("advertised route tunnel is not configured");
          if (!route.prefix || !route.prefix.includes("/") || ref(route.prefix) !== route.prefix) throw new Error("advertised prefix must be canonical");
          if (local.map(ref).includes(route.prefix)) throw new Error("advertised prefix overlaps tunnel");
          if (route.snat !== undefined && typeof route.snat !== "boolean") throw new Error("snat must be boolean");
        }
        return doc;
      };
      window.__state = {
        phase: "running", platform: "Windows", config_path: "/fixture/configure.json", error: "",
        status: { running: true, node: "192.0.2.1:65535", device: "Tunnel-Test", pending_connections: 0,
          peers: [{ node: "192.0.2.2:65535", state: 3, transport: "tcp" }, { node: "192.0.2.3:65535", state: 2, transport: "udp" }],
          routes: [{ network: "10.1.0.0/24", node: "192.0.2.4:65535", next_hops: ["192.0.2.2:65535", "192.0.2.3:65535"] }],
          end_sessions: [{ ready: true }], counters: { unicast_forwarded: 1234, flood_forwarded: 10, udp_rejected: 2, tcp_data_sent: 8, tcp_data_received: 7, tcp_data_rejected: 1, tcp_data_send_drop: 2, udp_data_sent: 6, udp_data_received: 5 } },
        logs: [{ id: 1, time: "12:30:01", level: "info", message: "peer up 192.0.2.2:65535" },
          { id: 2, time: "12:30:02", level: "warning", message: '<img src=x onerror="window.__xss=true">' }]
      };
      window.pywebview = { api: { request: async (raw) => {
        const request = JSON.parse(raw); window.__calls.push(request);
        if (request.token !== "frontend-test-page-token") return JSON.stringify({ ok: false, error: "invalid page token" });
        if (request.action === "get_state") return JSON.stringify({ ok: true, data: window.__state });
        if (request.action === "load_config") return JSON.stringify({ ok: true, data: { text: window.__config, revision: window.__revision } });
        if (request.action === "remote_state") return JSON.stringify({ ok: true, data: window.__state.remote_desktop || {} });
        if (request.action === "remote_connect") {
          window.__remoteViewer = {session_id: "viewer-" + (window.__calls.filter((call) => call.action === "remote_connect").length), status: "connecting", permission: request.payload.permission};
          return JSON.stringify({ok: true, data: window.__remoteViewer});
        }
        if (request.action === "remote_frame") {
          if (!window.__remoteTrusted) return JSON.stringify({ok:true, data:{...window.__remoteViewer,status:"trust_required",identity:{name:"Test desktop", fingerprint:"ab".repeat(32)}}});
          const canvas = document.createElement("canvas"); canvas.width = 160; canvas.height = 90;
          const context = canvas.getContext("2d"); context.fillStyle = "#25477c"; context.fillRect(0,0,160,90);
          return JSON.stringify({ok:true,data:{...window.__remoteViewer,status:"connected",sequence:Date.now(),jpeg:canvas.toDataURL("image/jpeg").split(",")[1],width:160,height:90}});
        }
        if (request.action === "remote_trust") window.__remoteTrusted = true;
        if (request.action === "remote_authorize") { const pending=window.__state.remote_desktop.pending.pop(); window.__state.remote_desktop.devices.push({...pending,permission:request.payload.permission}); }
        if (request.action === "remote_revoke") window.__state.remote_desktop.devices=[];
        if (request.action === "remote_terminate") window.__state.remote_desktop.sessions=[];
        if (request.action === "remote_reject") window.__state.remote_desktop.pending=[];
        if (request.action === "generate_key") return JSON.stringify({ ok: true, data: { key: "c".repeat(64) } });
        if (["normalize_config", "validate_config", "save_config", "start"].includes(request.action)) {
          try {
            const text = JSON.stringify(normalized(request.payload.text), null, 2) + "\n";
            if (request.action === "normalize_config") return JSON.stringify({ ok: true, data: { text } });
            if (request.action === "save_config" && request.payload.expected_sha256 !== undefined && request.payload.expected_sha256 !== window.__revision) throw new Error("configuration changed; reload before saving");
            if (request.action === "save_config" && window.__saveError) throw new Error(window.__saveError);
            if (request.action === "save_config" || request.action === "start") window.__config = text;
            if (request.action === "save_config") {
              window.__revision = window.__revision === "0".repeat(64) ? "1".repeat(64) : "0".repeat(64);
              return JSON.stringify({ ok: true, data: { text, revision: window.__revision, mode: "peers", message: "配置已保存并应用", ...window.__saveResult } });
            }
          } catch (error) { return JSON.stringify({ ok: false, error: error.message }); }
        }
        if (request.action === "stop") { window.__state.phase = "stopped"; window.__state.error = ""; }
        if (request.action === "start") window.__state.phase = "running";
        if (request.action === "clear_logs") window.__state.logs = [];
        return JSON.stringify({ ok: true, data: {} });
      } } };
    });
    const url = pathToFileURL(path.join(root, "gui", "assets", "index.html")).href;
    const check = (name) => { report.checks.push(name); console.log("PASS " + name); };
    const screenshot = async (target, name) => {
      await target.evaluate(() => window.scrollTo(0, 0));
      await target.waitForTimeout(100);
      const file = path.join(options.output, name + ".png"); await target.screenshot({ path: file, fullPage: true }); report.screenshots.push(file);
    };
    await page.goto(url);
    await page.waitForFunction(() => document.getElementById("metric-peers").textContent === "1");
    assert(await page.evaluate(() => window.__calls.every((request) => request.token === "frontend-test-page-token")));
    check("desktop_bridge_capability_token");
    assert.equal(await page.locator("#metric-forwarded").textContent(), "1,244");
    assert.equal(await page.locator(".route-mode").textContent(), "ECMP × 2");
    assert.equal(await page.locator("#metric-sessions").textContent(), "1");
    assert.equal(await page.locator('#counters-list dt[title="tcp_data_sent"]').textContent(), "TCP 加密记录发出");
    assert.equal(await page.locator('#counters-list dt[title="tcp_data_rejected"]').textContent(), "TCP 数据校验拒绝");
    assert.equal(await page.locator('#counters-list dt[title="tcp_data_send_drop"]').textContent(), "TCP 数据排队丢弃");
    assert.equal(await page.locator("#metric-forward-note").textContent(), "拒绝 / 丢弃事件 5");
    check("live_status_ecmp_counters");
    assert.deepEqual(await page.locator(".peer-data-transport").allTextContents(), ["TCP", "UDP"]);
    check("status_shows_negotiated_peer_transport");
    await screenshot(page, "frontend-desktop");

    await page.click('[data-page="config"]');
    const documentValue = () => page.locator("#config-editor").inputValue().then(JSON.parse);
    assert.equal(await page.inputValue("#local-endpoint"), "192.0.2.1:65535");
    assert.equal(await page.locator(".network-cidr").inputValue(), "10.1.0.1/24");
    assert.equal((await documentValue()).peers[0].networks, undefined);
    assert.equal((await documentValue()).listen, undefined);
    assert.equal((await documentValue()).tun_mtu, undefined); check("minimal_form_and_omitted_defaults");
    assert.equal(await page.locator(".peer-transport").inputValue(), "udp");
    assert.equal((await documentValue()).peers[0].transport, undefined);
    await page.selectOption(".peer-transport", "tcp");
    assert.equal((await documentValue()).peers[0].transport, "tcp");
    await page.selectOption(".peer-transport", "udp");
    assert.equal((await documentValue()).peers[0].transport, undefined);
    check("peer_transport_selector_preserves_minimal_udp_and_explicit_tcp");
    assert.equal(await page.locator("#advanced-config").evaluate((details) => details.open), false);
    assert.equal(await page.locator("#json-settings").evaluate((details) => details.open), false); check("advanced_settings_collapsed_by_default");
    await screenshot(page, "frontend-config-simple");
    await page.locator("#advanced-config > summary").click();
    assert.equal(await page.inputValue("#device-backend"), "auto");
    assert.equal((await documentValue()).device_backend, undefined);
    await page.selectOption("#device-backend", "kernel");
    assert.equal((await documentValue()).device_backend, "kernel");
    await page.selectOption("#device-backend", "tun");
    assert.equal((await documentValue()).device_backend, "tun");
    await page.selectOption("#device-backend", "auto");
    assert.equal((await documentValue()).device_backend, undefined);
    check("device_backend_selector_distinguishes_platform_default_and_explicit_backends");
    await page.locator("#advanced-config > summary").click();
    await page.fill("#local-endpoint", "192.0.2.11:65535");
    await page.waitForTimeout(1200);
    assert.equal(await page.inputValue("#local-endpoint"), "192.0.2.11:65535");
    assert.equal((await documentValue()).address, "192.0.2.11:65535");
    assert(await page.locator("#config-dirty").isVisible()); check("poll_preserves_unsaved_edits");
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true }));
    await page.click(".generate-key"); await page.waitForFunction(() => document.querySelector(".peer-key").value === "c".repeat(64));
    assert.equal(await page.locator(".peer-key").getAttribute("type"), "password");
    await page.click(".show-key"); assert.equal(await page.locator(".peer-key").getAttribute("type"), "text");
    await page.click(".copy-key"); await page.waitForFunction(() => window.__calls.some((request) => request.action === "copy_text" && request.payload.text === "c".repeat(64)));
    check("per_peer_generate_show_and_copy_key");
    await page.click("#add-network"); await page.locator(".network-cidr").nth(1).fill("10.2.0.1/24");
    assert.deepEqual((await documentValue()).peers[0].networks, ["10.1.0.0/24"]);
    assert.equal(await page.locator(".peer-card .network-choice input").nth(1).isChecked(), false); check("adding_network_does_not_expand_peer_authorization");
    await page.locator(".peer-card .network-choice input").nth(1).check();
    assert.deepEqual((await documentValue()).peers[0].networks, ["10.1.0.0/24", "10.2.0.0/24"]); check("explicit_multi_network_authorization");
    const ipv6Cases = [
      ["fd53:42:7ef0::2/64", "fd53:42:7ef0::/64"],
      ["fd53:42:7ef0:abcd:abcd:1234:5678:9/73", "fd53:42:7ef0:abcd:ab80::/73"],
      ["::ffff:192.0.2.2/120", "::ffff:c000:200/120"],
      ["2001:db8::1/0", "::/0"],
      ["2001:db8::1/128", "2001:db8::1/128"]
    ];
    for (const [host, subnet] of ipv6Cases) {
      await page.locator(".network-cidr").nth(1).fill(host);
      assert.equal((await documentValue()).peers[0].networks[1], subnet, host);
    }
    await page.locator(".network-cidr").nth(1).fill("fd53:42:7ef0::2/64"); check("ipv6_subnet_reference_derivation");
    await page.locator(".peer-card .network-choice input").nth(1).uncheck();
    await page.locator(".remove-network").nth(0).click();
    assert.deepEqual((await documentValue()).peers[0].networks, []);
    await page.click("#save-config"); await page.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("peer needs at least one network"));
    check("removing_authorized_network_never_falls_back_to_all");
    await page.locator(".peer-card .network-choice input").nth(0).check();
    await page.click("#add-network"); await page.locator(".network-cidr").nth(1).fill("10.1.0.1/24");
    await page.locator(".peer-card .network-choice input").nth(1).check();
    await page.locator("#advanced-config > summary").click();
    await page.uncheck("#listen-enabled"); await page.fill("#bind-address", "0.0.0.0:65000");
    await page.uncheck("#listen-all"); await page.locator("#listen-network-fields input").nth(0).uncheck();
    assert.deepEqual((await documentValue()).listen, { enabled: false, bind_address: "0.0.0.0:65000", networks: ["10.1.0.0/24"] });
    check("advanced_inbound_authorization_and_binding");
    await page.click("#save-config");
    await page.waitForFunction(() => document.getElementById("config-dirty").hidden); check("save_clears_dirty");
    assert.equal(await page.locator("#save-config").textContent(), "保存并应用");
    assert.equal(await page.evaluate(() => window.__calls.filter(call => call.action === "save_config").at(-1).payload.expected_sha256), "0".repeat(64));
    assert((await page.locator("#config-feedback").textContent()).includes("配置已保存并应用"));
    assert((await page.locator("#config-apply-help").textContent()).includes("重连"));
    const beforeRejectedApply = await page.evaluate(() => window.__config);
    await page.fill("#local-endpoint", "192.0.2.77:65535");
    const pendingApply = await page.inputValue("#config-editor");
    const loadedRevision = await page.evaluate(() => window.__revision);
    await page.evaluate(() => { window.__revision = "f".repeat(64); });
    await page.click("#save-config");
    await page.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("configuration changed"));
    assert.equal(await page.evaluate(() => window.__config), beforeRejectedApply);
    assert.equal(await page.inputValue("#config-editor"), pendingApply);
    assert(await page.locator("#config-dirty").isVisible());
    await page.evaluate(revision => { window.__revision = revision; }, loadedRevision);
    check("stale_configuration_revision_does_not_overwrite_saved_file");
    await page.evaluate(() => { window.__saveError = "reload rejected: listener busy; previous configuration restored"; });
    await page.click("#save-config");
    await page.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("reload rejected"));
    assert.equal(await page.evaluate(() => window.__config), beforeRejectedApply);
    assert.equal(await page.inputValue("#config-editor"), pendingApply);
    assert(await page.locator("#config-dirty").isVisible());
    check("failed_reload_preserves_pending_edits_and_saved_configuration");
    await page.evaluate(() => { delete window.__saveError; window.__saveResult = {mode: "rebuild", interrupted: true}; });
    await page.click("#save-config");
    await page.waitForFunction(() => document.getElementById("config-dirty").hidden && document.getElementById("config-feedback").textContent.includes("重连"));
    assert.equal(await page.inputValue("#config-editor"), await page.evaluate(() => window.__config));
    await page.evaluate(() => { delete window.__saveResult; });
    check("runtime_save_accepts_normalized_text_and_reports_reconnection");
    await screenshot(page, "frontend-config-desktop");
    const validJSON = await page.inputValue("#config-editor");
    await page.locator("#json-settings > summary").click();
    await page.fill("#config-editor", "broken"); await page.click("#validate-config");
    await page.waitForFunction(() => document.getElementById("config-feedback").textContent === "invalid JSON"); check("validation_error_feedback");
    assert(await page.locator("#local-endpoint").isDisabled());
    const beforeSave = await page.evaluate(() => window.__calls.filter((request) => request.action === "save_config").length);
    await page.click("#save-config");
    assert.equal(await page.evaluate(() => window.__calls.filter((request) => request.action === "save_config").length), beforeSave);
    assert.equal(await page.inputValue("#config-editor"), "broken"); check("unapplied_json_blocks_save_without_data_loss");
    const unknown = JSON.stringify({ ...JSON.parse(validJSON), unsupported_security: true });
    await page.fill("#config-editor", unknown); await page.click("#apply-json");
    await page.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("unknown configuration field"));
    assert.equal(await page.inputValue("#config-editor"), unknown); check("unknown_json_fields_preserved_on_rejection");
    await page.fill("#config-editor", validJSON + "\n"); await page.click("#apply-json");
    await page.waitForFunction(() => !document.getElementById("basic-config-fields").disabled);
    assert.equal(await page.locator("#listen-enabled").isChecked(), false);
    assert.equal((await documentValue()).peers[0].shared_key, "c".repeat(64)); check("json_apply_preserves_keys_and_inbound_limits");
    const tcpJSON = JSON.parse(validJSON); tcpJSON.peers[0].transport = "tcp"; tcpJSON.device_backend = "kernel";
    await page.fill("#config-editor", JSON.stringify(tcpJSON)); await page.click("#apply-json");
    await page.waitForFunction(() => document.querySelector(".peer-transport").value === "tcp");
    assert.equal(await page.inputValue("#device-backend"), "kernel");
    await page.fill(".peer-address", "192.0.2.22:65535");
    assert.equal((await documentValue()).peers[0].transport, "tcp");
    await page.click("#save-config");
    await page.waitForFunction(() => JSON.parse(window.__config).peers[0].transport === "tcp");
    assert.equal(JSON.parse(await page.evaluate(() => window.__config)).device_backend, "kernel");
    check("kernel_backend_json_import_edit_and_runtime_save_preserve_selection");
    check("tcp_peer_json_import_form_edit_and_runtime_save_preserve_transport");
    const tunJSON = { ...tcpJSON, device_backend: "tun" };
    await page.setInputFiles("#config-file", { name: "explicit-tun.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(tunJSON)) });
    await page.waitForFunction(() => document.getElementById("device-backend").value === "tun");
    assert.equal((await documentValue()).device_backend, "tun");
    await page.click("#save-config");
    await page.waitForFunction(() => JSON.parse(window.__config).device_backend === "tun");
    check("explicit_tun_import_and_save_preserve_cross_platform_selection");
    const automaticJSON = { ...tunJSON }; delete automaticJSON.device_backend;
    await page.setInputFiles("#config-file", { name: "platform-default.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(automaticJSON)) });
    await page.waitForFunction(() => document.getElementById("device-backend").value === "auto");
    assert.equal((await documentValue()).device_backend, undefined);
    check("missing_backend_import_keeps_platform_default_despite_core_normalization");
    await page.click("#save-config");
    await page.waitForFunction(() => document.getElementById("device-backend").value === "tun");
    assert.equal((await documentValue()).device_backend, "tun");
    check("platform_default_save_materializes_effective_backend");
    const invalidTransport = JSON.stringify({ ...tcpJSON, peers: [{ ...tcpJSON.peers[0], transport: "quic" }] });
    await page.fill("#config-editor", invalidTransport); await page.click("#apply-json");
    await page.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("peer transport must be udp or tcp"));
    assert.equal(await page.inputValue("#config-editor"), invalidTransport);
    check("invalid_peer_transport_preserves_import_for_repair");
    const legacy = { peers: [{ address: "192.0.2.3:65535", shared_key: "legacy-secret", networks: [{ tunnel: "10.1.0.0/24", tunnel_ip: "10.1.0.9" }, { tunnel: "10.2.0.0/24", tunnel_ip: "10.2.0.9" }] }], listen: { enabled: false, address: "192.0.2.9:65535", networks: [{ tunnel: "10.1.0.0/24", tunnel_ip: "10.1.0.9" }] } };
    await page.setInputFiles("#config-file", { name: "legacy.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(legacy)) });
    await page.waitForFunction(() => document.getElementById("local-endpoint").value === "192.0.2.9:65535");
    assert.equal(await page.inputValue("#device-backend"), "auto");
    assert.deepEqual((await documentValue()).networks, ["10.1.0.9/24", "10.2.0.9/24"]);
    assert.deepEqual((await documentValue()).listen, { enabled: false, networks: ["10.1.0.0/24"] }); check("legacy_file_import_via_host_normalization");
    const imported = await page.inputValue("#config-editor");
    await page.setInputFiles("#config-file", { name: "oversize.json", mimeType: "application/json", buffer: Buffer.alloc(1024 * 1024 + 1, 32) });
    assert.equal(await page.inputValue("#config-editor"), imported);
    await page.waitForFunction(() => document.getElementById("toast").classList.contains("error")); check("oversized_import_preserves_editor");
    await page.setInputFiles("#config-file", { name: "broken.json", mimeType: "application/json", buffer: Buffer.from('{"unfinished"') });
    await page.waitForFunction(() => document.getElementById("config-editor").value === '{"unfinished"');
    assert(await page.locator("#config-editor").isVisible());
    await page.waitForTimeout(1100); assert.equal(await page.inputValue("#config-editor"), '{"unfinished"'); check("invalid_import_survives_poll_for_manual_repair");
    const emptyNetworks = JSON.stringify({ address: "192.0.2.30:65535", networks: [] });
    await page.setInputFiles("#config-file", { name: "empty-networks.json", mimeType: "application/json", buffer: Buffer.from(emptyNetworks) });
    await page.waitForFunction((value) => document.getElementById("config-editor").value === value, emptyNetworks);
    assert(await page.locator("#local-endpoint").isDisabled()); check("empty_network_import_is_preserved_and_rejected");
    await page.fill("#config-editor", imported + "\n"); await page.click("#apply-json");
    await page.waitForFunction(() => !document.getElementById("basic-config-fields").disabled);
    await page.fill("#local-endpoint", "192.0.2.19:65535"); await page.click("#save-config");
    await page.waitForFunction(() => JSON.parse(window.__config).address === "192.0.2.19:65535"); check("save_serializes_latest_form_edits");

    const beforeServices = await page.inputValue("#config-editor");
    const loadFixture = async (document) => {
      await page.evaluate((value) => { window.__config = value; }, JSON.stringify(document));
      await page.click("#reload-config");
      await page.waitForFunction(() => !document.getElementById("reload-config").disabled);
    };
    await page.locator("#address-server-settings > summary").click();
    await page.check("#address-server-enabled"); await page.check("#address-server-only");
    await page.fill("#address-server-address", "192.0.2.10:65534");
    await page.locator(".address-pool").fill("10.90.0.0/24");
    assert.equal(await page.inputValue("#address-auth-mode"), "shared");
    assert.equal(await page.locator("#address-auth-settings").evaluate((details) => details.open), false);
    await page.locator("#address-shared-key .generate-service-key").click();
    await page.waitForFunction(() => document.querySelector(".address-server-key").value === "c".repeat(64));
    assert.equal(await page.locator(".address-server-key").getAttribute("type"), "password");
    assert.equal((await documentValue()).address_server.shared_key, "c".repeat(64));
    assert.equal((await documentValue()).address_server.clients, undefined);
    await page.locator("#address-shared-key .show-service-key").click(); assert.equal(await page.locator(".address-server-key").getAttribute("type"), "text");
    await page.locator("#address-shared-key .show-service-key").click();
    await page.locator("#address-shared-key .copy-service-key").click();
    check("new_server_defaults_to_one_shared_key_without_client_list");
    await page.click("#save-config"); await page.waitForFunction(() => document.getElementById("config-dirty").hidden);
    const sharedServer = await documentValue();
    await page.uncheck("#address-server-only");
    assert.equal((await documentValue()).address, JSON.parse(beforeServices).address);
    assert.deepEqual((await documentValue()).networks, JSON.parse(beforeServices).networks);
    await page.check("#address-server-only");
    assert.deepEqual(await documentValue(), sharedServer);
    check("saving_service_only_preserves_hidden_tunnel_form_for_explicit_restore");
    await page.fill("#shared-client-address", "192.0.2.19:65535");
    assert.deepEqual(await documentValue(), sharedServer); assert(await page.locator("#config-dirty").isHidden());
    await page.click("#export-shared-access"); await page.waitForFunction(() => document.getElementById("access-export-dialog").open);
    assert.deepEqual(JSON.parse(await page.inputValue("#access-export-text")), { address: "192.0.2.19:65535", address_clients: [{ address: "192.0.2.10:65534", shared_key: "c".repeat(64), networks: ["10.90.0.0/24"] }] });
    await page.click("#close-access-export"); check("shared_export_address_is_ephemeral_and_config_is_complete");
    await page.click("#add-address-pool"); await page.locator(".address-pool").nth(1).fill("fd90::/64");
    await page.click("#export-shared-access"); await page.waitForFunction(() => document.getElementById("access-export-dialog").open);
    assert.deepEqual(JSON.parse(await page.inputValue("#access-export-text")).address_clients[0].networks, ["10.90.0.0/24", "fd90::/64"]);
    await page.click("#close-access-export"); check("shared_export_authorizes_all_pools");
    await page.evaluate(() => { document.getElementById("advanced-config").open = false; });
    await screenshot(page, "frontend-shared-address-server");
    await page.setViewportSize({ width: 390, height: 844 }); assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await screenshot(page, "frontend-shared-address-server-mobile"); await page.setViewportSize({ width: 1360, height: 1000 });
    const mixedAuth = JSON.stringify({ address_server: { ...sharedServer.address_server, clients: [] } });
    await page.setInputFiles("#config-file", { name: "mixed-auth.json", mimeType: "application/json", buffer: Buffer.from(mixedAuth) });
    await page.waitForFunction((value) => document.getElementById("config-editor").value === value, mixedAuth);
    assert((await page.locator("#config-feedback").textContent()).includes("mutually exclusive"));
    assert(await page.locator("#address-server-enabled").isDisabled()); check("mixed_auth_import_rejected_without_dropping_either_field");
    await loadFixture({ address_server: { address: "192.0.2.10:65534", networks: ["10.90.0.0/24"], clients: [{ address: "192.0.2.18:65535", shared_key: "legacy-only-key", networks: ["10.90.0.0/24"] }] } });
    assert.equal(await page.inputValue("#address-auth-mode"), "individual"); assert.equal((await documentValue()).address_server.shared_key, undefined);
    assert.equal((await documentValue()).address_server.clients[0].shared_key, "legacy-only-key");
    assert(await page.locator("#shared-service-auth").isHidden()); check("legacy_authorization_load_never_switches_to_shared");
    await page.locator("#address-auth-settings > summary").click();
    const restricted = await documentValue(); page.removeAllListeners("dialog"); page.once("dialog", (dialog) => dialog.dismiss());
    await page.selectOption("#address-auth-mode", "shared");
    assert.deepEqual(await documentValue(), restricted); assert.equal(await page.inputValue("#address-auth-mode"), "individual");
    page.on("dialog", (dialog) => dialog.accept()); check("cancel_shared_mode_switch_preserves_restricted_configuration");
    const savedRestricted = await page.evaluate(() => window.__config);
    await page.selectOption("#address-auth-mode", "shared");
    assert.equal((await documentValue()).address_server.clients, undefined); assert.equal((await documentValue()).address_server.shared_key, "");
    assert.equal(await page.evaluate(() => window.__config), savedRestricted);
    await page.selectOption("#address-auth-mode", "individual"); assert.deepEqual(await documentValue(), restricted);
    check("explicit_auth_switch_is_mutually_exclusive_and_never_autosaves");
    await page.locator(".remove-authorized-client").click();
    await page.click("#add-authorized-client");
    await page.locator(".authorized-client-address").fill("192.0.2.19:65535");
    await page.locator(".authorized-client-card .generate-service-key").click();
    await page.waitForFunction(() => document.querySelector(".authorized-client-key").value === "c".repeat(64));
    assert.equal(await page.locator(".authorized-client-key").getAttribute("type"), "password");
    assert.deepEqual(Object.keys(await documentValue()), ["address_server"]);
    assert.equal((await documentValue()).address_server.reclaim_after, undefined);
    assert.equal((await documentValue()).address_server.state_file, undefined);
    assert(await page.locator("#local-endpoint").isDisabled()); check("server_only_form_and_omitted_defaults");
    await page.click("#add-address-pool"); await page.locator(".address-pool").nth(1).fill("fd90::/64");
    assert.deepEqual((await documentValue()).address_server.clients[0].networks, ["10.90.0.0/24"]);
    assert.equal(await page.locator(".authorized-client-card .network-choice input").nth(1).isChecked(), false);
    await page.fill("#address-reclaim", "3600"); await page.fill("#address-state-file", "leases.json");
    assert.equal((await documentValue()).address_server.reclaim_after, 3600); check("adding_pool_never_broadens_client_authorization");
    await page.locator(".authorized-client-card .export-access").click(); await page.waitForFunction(() => document.getElementById("access-export-dialog").open);
    const accessText = await page.inputValue("#access-export-text"); const access = JSON.parse(accessText);
    assert.deepEqual(access, { address: "192.0.2.19:65535", address_clients: [{ address: "192.0.2.10:65534", shared_key: "c".repeat(64), networks: ["10.90.0.0/24"] }] });
    await page.click("#copy-access-export"); await page.waitForFunction((value) => window.__calls.some((call) => call.action === "copy_text" && call.payload.text === value), accessText);
    await page.click("#close-access-export"); check("export_per_node_access_config_and_copy");
    await page.click("#save-config"); await page.waitForFunction(() => JSON.parse(window.__config).address_server && document.getElementById("config-dirty").hidden);
    assert.deepEqual(JSON.parse(await page.evaluate(() => window.__config)), await documentValue());
    await screenshot(page, "frontend-address-server");
    await page.setViewportSize({ width: 390, height: 844 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await screenshot(page, "frontend-address-server-mobile"); check("server_form_saves_and_fits_mobile");
    await page.setViewportSize({ width: 1360, height: 1000 });
    await loadFixture({ address: "192.0.2.19:65535", networks: ["10.1.0.19/24"], peers: [{ address: "192.0.2.20:65535", shared_key: "original-peer-key" }] });
    await page.evaluate(() => { document.getElementById("address-clients-settings").open = true; });
    await page.click("#open-access-import");
    await page.setInputFiles("#access-file", { name: "access.json", mimeType: "application/json", buffer: Buffer.from(accessText) });
    await page.waitForFunction((value) => document.getElementById("access-import-text").value === value, accessText);
    await page.click("#merge-access"); await page.waitForFunction(() => !document.getElementById("access-import-dialog").open);
    const merged = await documentValue();
    assert.deepEqual(merged.networks, ["10.1.0.19/24"]);
    assert.equal(merged.peers[0].shared_key, "original-peer-key");
    assert.deepEqual(merged.peers[0].networks, ["10.1.0.0/24"]);
    assert.deepEqual(merged.address_clients, access.address_clients);
    assert.equal(await page.locator(".peer-card .network-choice input").nth(1).isChecked(), false);
    check("access_import_merge_preserves_peer_key_and_network_authorization");
    await page.waitForTimeout(1100); assert.deepEqual(await documentValue(), merged); check("service_poll_preserves_unsaved_edits");
    await page.click("#open-access-import");
    await page.fill("#access-import-text", JSON.stringify({ ...access, address: "192.0.2.99:65535" }));
    await page.click("#merge-access"); await page.waitForFunction(() => document.getElementById("access-import-feedback").classList.contains("failure"));
    assert.deepEqual(await documentValue(), merged);
    await page.fill("#access-import-text", JSON.stringify({ ...access, address_clients: [{ ...access.address_clients[0], shared_key: "do-not-overwrite" }] }));
    await page.click("#merge-access"); await page.waitForFunction(() => document.getElementById("access-import-feedback").textContent.includes("密钥"));
    assert.deepEqual(await documentValue(), merged); check("access_merge_rejects_address_and_key_conflicts_without_changes");
    await page.fill("#access-import-text", accessText); await page.click("#replace-access");
    await page.waitForFunction(() => !document.getElementById("access-import-dialog").open);
    assert.deepEqual(await documentValue(), access);
    assert.equal(await page.locator(".network-cidr").count(), 0);
    assert.equal(await page.locator(".peer-card").count(), 0);
    assert.equal(await page.locator(".address-client-key").getAttribute("type"), "password");
    await page.click("#save-config"); await page.waitForFunction(() => document.getElementById("config-dirty").hidden);
    check("access_explicit_replace_creates_client_without_static_ip");
    await page.click("#add-peer"); await page.locator(".peer-address").fill("192.0.2.20:65535"); await page.locator(".peer-key").fill("managed-peer-key");
    assert.equal((await documentValue()).peers[0].networks, undefined);
    await page.click(".add-requested-network"); await page.locator(".requested-network").nth(1).fill("fd90::/64");
    assert.deepEqual((await documentValue()).peers[0].networks, ["10.90.0.0/24"]);
    await page.locator(".requested-network").nth(1).fill("fd91::/64");
    assert.deepEqual((await documentValue()).address_clients[0].networks, ["10.90.0.0/24", "fd91::/64"]);
    check("managed_network_forms_preserve_existing_peer_limits");
    await page.click("#connection-button"); await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "stopped");
    await page.locator(".address-client-address").fill("192.0.2.10:65533");
    const latestManaged = await documentValue();
    await page.click("#connection-button"); await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "running");
    assert.deepEqual(await page.evaluate(() => JSON.parse(window.__calls.filter((call) => call.action === "start").at(-1).payload.text)), latestManaged);
    check("start_serializes_latest_managed_client_form");
    await page.setViewportSize({ width: 390, height: 844 });
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)); await screenshot(page, "frontend-address-client-mobile");
    await page.setViewportSize({ width: 1360, height: 1000 });
    await page.evaluate(() => { window.__state.status.address_service = { running: true, server: { enabled: true, running: true, address: "192.0.2.10:65534", error: "", leases: [{ node: "192.0.2.19:65535", network: "10.90.0.0/24", ip: "10.90.0.1", online: false, reclaim_at: 2000000000000 }] }, clients: [{ server: "192.0.2.10:65534", state: "waiting", grants: [], errors: [], error: "" }] }; });
    await page.click('[data-page="overview"]');
    await page.waitForFunction(() => document.getElementById("address-service-status").textContent.includes("等待分配"));
    assert((await page.locator("#address-service-status").textContent()).includes("离线保留")); check("service_status_displays_waiting_and_persistent_lease");
    await page.evaluate(() => { window.__state.status.address_service.clients[0] = { server: "192.0.2.10:65534", state: "connected", grants: [{ network: "10.90.0.0/24", ip: "10.90.0.1", expires_at: 2000000000000 }], errors: [{ network: "fd91::/64", error: '<img src=x onerror="window.__xss=true"> pool exhausted' }], error: "" }; });
    await page.waitForFunction(() => document.getElementById("address-service-status").textContent.includes("部分地址已分配"));
    assert((await page.locator("#address-service-status").textContent()).includes("pool exhausted"));
    assert.equal(await page.locator("#address-service-status img").count(), 0);
    assert.equal(await page.evaluate(() => !!window.__xss), false); check("partial_grants_show_pool_errors_as_safe_text");
    await page.evaluate(() => { window.__state.status.device_error = "virtual interface unavailable"; window.__state.status.address_errors = { "10.90.0.0/24": "failed to install address" }; });
    await page.waitForFunction(() => document.getElementById("phase-label").textContent === "隧道异常");
    assert(await page.locator("#error-notice").isVisible());
    assert((await page.locator("#runtime-error").textContent()).includes("failed to install address"));
    assert((await page.locator("#address-service-status").textContent()).includes("服务运行中"));
    check("device_failure_is_visible_while_service_stays_running");
    await screenshot(page, "frontend-address-status");
    await page.click('[data-page="config"]'); await loadFixture(JSON.parse(beforeServices));
    await page.evaluate(() => { delete window.__state.status.address_service; delete window.__state.status.device_error; delete window.__state.status.address_errors; });

    await loadFixture({ address: "192.0.2.19:65535", networks: ["10.1.0.19/24"], peers: [{ address: "192.0.2.20:65535", shared_key: "published-peer-key" }] });
    await page.locator("#subnet-settings > summary").click(); await page.click("#add-subnet");
    await page.locator(".subnet-prefix").fill("203.0.113.0/24");
    assert.deepEqual((await documentValue()).advertise_routes, [{ tunnel: "10.1.0.0/24", prefix: "203.0.113.0/24" }]);
    await page.locator(".subnet-snat").check();
    assert.equal((await documentValue()).advertise_routes[0].snat, true);
    await page.waitForTimeout(1100); assert.equal(await page.locator(".subnet-snat").isChecked(), true);
    await page.click("#save-config"); await page.waitForFunction(() => document.getElementById("config-dirty").hidden);
    assert.equal(JSON.parse(await page.evaluate(() => window.__config)).advertise_routes[0].snat, true);
    check("published_subnet_form_defaults_and_snat_save");
    await page.click("#add-network"); await page.locator(".network-cidr").nth(1).fill("10.2.0.19/24");
    assert.deepEqual((await documentValue()).peers[0].networks, ["10.1.0.0/24"]);
    assert.equal((await documentValue()).advertise_routes[0].tunnel, "10.1.0.0/24");
    check("publishing_never_expands_peer_authorization");
    await page.locator(".remove-peer").click(); await page.locator(".remove-network").nth(0).click();
    assert.equal((await documentValue()).advertise_routes[0].tunnel, "10.1.0.0/24");
    await page.click("#save-config"); await page.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("tunnel is not configured"));
    assert.equal(await page.locator(".subnet-prefix").inputValue(), "203.0.113.0/24");
    await page.locator(".subnet-network").selectOption({ index: 1 });
    assert.equal((await documentValue()).advertise_routes[0].tunnel, "10.2.0.0/24");
    check("removing_publish_network_preserves_route_until_explicit_repair");
    await page.locator(".subnet-prefix").fill("203.0.113.1/24"); await page.click("#save-config");
    await page.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("canonical"));
    assert.equal(await page.locator(".subnet-prefix").inputValue(), "203.0.113.1/24");
    await page.locator(".subnet-prefix").fill("203.0.114.0/24"); await page.locator(".subnet-snat").uncheck();
    await page.click("#connection-button"); await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "stopped");
    const publishedLatest = await documentValue(); await page.click("#connection-button");
    await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "running");
    assert.deepEqual(await page.evaluate(() => JSON.parse(window.__calls.filter((call) => call.action === "start").at(-1).payload.text)), publishedLatest);
    check("published_prefix_validation_and_start_use_latest_edits");
    await page.click('[data-page="config"]');
    await loadFixture({ address: "192.0.2.19:65535", address_clients: [{ address: "192.0.2.10:65534", shared_key: "managed-publish-key", networks: ["10.90.0.0/24"] }], advertise_routes: [{ tunnel: "10.90.0.0/24", prefix: "203.0.114.0/24", snat: true }] });
    assert((await page.locator(".subnet-network option:checked").textContent()).includes("自动"));
    assert.deepEqual((await documentValue()).advertise_routes, [{ tunnel: "10.90.0.0/24", prefix: "203.0.114.0/24", snat: true }]);
    check("managed_tunnel_publication_round_trip");
    await page.setViewportSize({ width: 390, height: 844 }); assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await screenshot(page, "frontend-subnet-mobile"); await page.setViewportSize({ width: 1360, height: 1000 });
    await page.evaluate(() => { window.__state.status.local_exports = [{ network: "10.90.0.0/24", prefix: "203.0.114.0/24", snat: true, active: false, error: "SNAT unavailable on this platform" }]; window.__state.status.subnet_routes = [{ network: "10.90.0.0/24", prefix: "192.168.70.0/24", gateway: "192.0.2.70:65535", state: "active", error: "" }]; });
    await page.click('[data-page="overview"]'); await page.waitForFunction(() => document.getElementById("subnet-status").textContent.includes("SNAT unavailable"));
    assert((await page.locator("#subnet-status").textContent()).includes("发布失败"));
    assert((await page.locator("#subnet-status").textContent()).includes("192.0.2.70:65535"));
    assert((await page.locator("#subnet-status").textContent()).includes("可访问"));
    await page.evaluate(() => { window.__state.status.subnet_routes[0].gateway = "192.0.2.71:65535"; window.__state.status.local_exports[0].error = '<img src=x onerror="window.__subnet_xss=true">'; });
    await page.waitForFunction(() => document.getElementById("subnet-status").textContent.includes("192.0.2.71:65535"));
    assert.equal(await page.locator("#subnet-status img").count(), 0); assert.equal(await page.evaluate(() => !!window.__subnet_xss), false);
    check("subnet_status_shows_selected_gateway_failures_and_safe_text");
    await screenshot(page, "frontend-subnet-status");
    await page.click('[data-page="config"]'); await loadFixture(JSON.parse(beforeServices));
    await page.evaluate(() => { delete window.__state.status.local_exports; delete window.__state.status.subnet_routes; });

    await page.click('[data-page="logs"]'); await page.selectOption("#log-level", "warning");
    assert.equal(await page.locator(".log-line").count(), 1);
    await page.fill("#log-search", "not present"); assert(await page.locator("#logs-empty").isVisible());
    await page.fill("#log-search", ""); check("log_level_and_text_filter");
    assert.equal(await page.locator(".log-message").textContent(), '<img src=x onerror="window.__xss=true">');
    assert.equal(await page.locator("#log-output img").count(), 0);
    assert.equal(await page.evaluate(() => !!window.__xss), false); check("untrusted_log_text_is_not_html");
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true }));
    await page.click("#copy-logs");
    await page.waitForFunction(() => window.__calls.some((request) => request.action === "copy_text" && request.payload.text.includes("<img"))); check("clipboard_host_fallback");
    await page.click("#clear-logs");
    await page.waitForFunction(() => document.getElementById("logs-count").textContent === "0"); check("clear_logs");
    await page.click("#connection-button");
    await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "stopped");
    await page.click('[data-page="config"]'); await page.fill("#local-endpoint", "192.0.2.29:65535");
    await page.click("#connection-button");
    await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "running");
    assert.equal(await page.evaluate(() => JSON.parse(window.__calls.filter((request) => request.action === "start").at(-1).payload.text).address), "192.0.2.29:65535"); check("stop_and_start_latest_form_edits");

    const beforeRemote = await page.inputValue("#config-editor");
    await page.click('[data-page="config"]');
    await loadFixture({address:"192.0.2.29:65535",networks:["10.1.0.1/24"],remote_desktop:{enabled:true,unattended:true}});
    await page.click('[data-page="remote"]');
    assert(await page.locator("#remote-enabled").isChecked()); assert(await page.locator("#remote-unattended").isChecked());
    assert.equal(await page.inputValue("#remote-access"),"authorized_devices"); assert.equal((await documentValue()).remote_desktop.networks,undefined);
    await page.selectOption("#remote-access","all_tunnel_nodes"); await page.fill("#remote-device-name","My workstation");
    assert.equal((await documentValue()).remote_desktop.access,"all_tunnel_nodes");
    assert((await page.textContent("#remote-access-notice")).includes("公网访客"));
    await page.click("#remote-save"); await page.waitForFunction(()=>JSON.parse(window.__config).remote_desktop.access==="all_tunnel_nodes");
    check("remote_config_defaults_and_all_tunnel_members_mode");
    await page.click('[data-page="config"]'); await page.click("#add-network"); await page.locator(".network-cidr").nth(1).fill("10.2.0.1/24");
    assert.deepEqual((await documentValue()).remote_desktop.networks,["10.1.0.0/24"]);
    await page.click('[data-page="remote"]'); assert.equal(await page.locator("#remote-network-fields input").nth(1).isChecked(),false);
    check("remote_new_network_never_expands_authorization");
    await page.evaluate(()=>{window.__state.phase="running";window.__state.remote_desktop={config:{enabled:true},identity:{name:"Local test",fingerprint:"aa".repeat(32)},pending:[{request_id:"pending1",name:'<img src=x onerror="window.__remoteXss=true">',fingerprint:"bb".repeat(32),network:"10.1.0.0/24",requested:"control"}],devices:[],sessions:[{session_id:"incoming1",name:"Active controller",fingerprint:"cc".repeat(32),permission:"control"}]};});
    await page.click("#remote-refresh"); await page.waitForSelector(".remote-approve");
    assert.equal(await page.locator("#remote-pending img").count(),0); assert.equal(await page.evaluate(()=>window.__remoteXss),undefined);
    await page.selectOption(".remote-permission","view"); await page.click(".remote-approve"); await page.waitForSelector(".remote-revoke");
    assert(await page.evaluate(()=>window.__calls.some(call=>call.action==="remote_authorize"&&call.payload.permission==="view"&&call.payload.remember===true)));
    await page.click(".remote-revoke"); await page.waitForFunction(()=>!document.querySelector(".remote-revoke"));
    await page.click(".remote-terminate"); await page.waitForFunction(()=>!document.querySelector(".remote-terminate"));
    check("remote_approve_revoke_terminate_and_safe_identity_rendering");
    await page.fill("#remote-target","10.1.0.2"); await page.selectOption("#remote-target-network","10.1.0.0/24");
    await page.click("#remote-connect"); await page.waitForFunction(()=>!document.getElementById("remote-image").hidden&&document.getElementById("remote-image").naturalWidth>0);
    assert(await page.evaluate(()=>window.__calls.some(call=>call.action==="remote_trust")));
    await page.locator("#remote-image").click(); await page.locator("#remote-screen").press("KeyA");
    await page.waitForFunction(()=>window.__calls.some(call=>call.action==="remote_input"&&call.payload.event.type==="key"&&call.payload.event.key==="KeyA"&&call.payload.event.down===false));
    await page.click("#remote-fullscreen"); assert(await page.locator("#remote-viewer").evaluate(node=>node.classList.contains("expanded"))); await page.click("#remote-fullscreen");
    await screenshot(page,"frontend-remote-desktop");
    await page.click("#remote-disconnect"); await page.waitForFunction(()=>document.getElementById("remote-viewer").hidden);
    assert(await page.evaluate(()=>window.__calls.some(call=>call.action==="remote_input"&&call.payload.event.type==="release_all")));
    check("remote_async_fingerprint_pairing_frame_keyboard_and_release");
    await page.check("#remote-view-only"); await page.click("#remote-connect"); await page.waitForFunction(()=>!document.getElementById("remote-image").hidden);
    const inputsBeforeView = await page.evaluate(()=>window.__calls.filter(call=>call.action==="remote_input").length);
    await page.locator("#remote-screen").focus(); await page.locator("#remote-screen").press("KeyB");
    assert.equal(await page.evaluate(()=>window.__calls.filter(call=>call.action==="remote_input").length),inputsBeforeView);
    await page.click("#remote-disconnect"); check("remote_view_only_sends_no_keyboard_or_mouse");
    await page.click('[data-page="config"]'); await loadFixture(JSON.parse(beforeRemote));

    await page.setViewportSize({ width: 390, height: 844 });
    for (const name of ["overview", "config", "logs", "remote"]) {
      await page.click('[data-page="' + name + '"]');
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), "Mobile page overflow: " + name);
      if (name === "config") {
        await page.evaluate(() => { document.getElementById("advanced-config").open = false; });
        await screenshot(page, "frontend-config-mobile");
      }
    }
    await page.click('[data-page="overview"]'); await page.waitForFunction(() => document.getElementById("toast").hidden);
    await screenshot(page, "frontend-mobile"); check("mobile_390_all_pages_no_document_overflow");
    await page.evaluate(() => { window.__state.status_stale = true; });
    await page.waitForFunction(() => document.getElementById("phase-pill").classList.contains("stale"));
    assert(await page.locator("#error-notice").isVisible()); check("stale_core_snapshot_is_marked");
    await page.evaluate(() => { window.__state.status_stale = false; window.__state.phase = "stopping"; window.__state.error = "stop timeout; retry"; });
    await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "stopping" && !document.getElementById("connection-button").disabled);
    await page.click("#connection-button");
    await page.waitForFunction(() => document.getElementById("phase-pill").dataset.phase === "stopped"); check("stop_timeout_allows_retry");

    const preview = await browser.newPage({ viewport: { width: 390, height: 844 } }); observe(preview);
    await preview.goto(url);
    await preview.waitForFunction(() => document.getElementById("phase-label").textContent === "开发预览");
    assert(await preview.locator("#connection-button").isDisabled());
    assert.equal(await preview.locator("#metric-peers").textContent(), "—");
    assert(await preview.locator("#host-notice").isVisible()); check("preview_has_no_fake_runtime_data");

    const android = await browser.newPage(); observe(android); android.on("dialog", (dialog) => dialog.accept());
    await android.addInitScript(() => {
      window.__androidCalls = [];
      window.TunnelHost = { request: (raw) => {
        const request = JSON.parse(raw); window.__androidCalls.push(request); if (request.token) throw new Error("Android must omit desktop token");
        if (request.action === "normalize_config") return JSON.stringify({ ok: true, data: { text: request.payload.text } });
        return JSON.stringify({ ok: true, data: request.action === "load_config" ? { text: "" } : { phase: "stopped", status: {}, platform: "Android", logs: [] } });
      } };
    });
    await android.goto(url); await android.waitForFunction(() => document.getElementById("local-platform").textContent === "Android");
    assert.equal(await android.locator("#metric-peers").textContent(), "—");
    await android.click('[data-page="config"]'); await android.fill("#local-endpoint", "192.0.2.51:65535");
    await android.locator(".network-cidr").fill("10.51.0.1/24");
    await android.click("#add-peer"); await android.locator(".peer-address").fill("192.0.2.52:65535");
    assert.equal(JSON.parse(await android.inputValue("#config-editor")).peers[0].networks, undefined); check("android_sync_bridge_and_blank_form_entry");
    await android.click(".remove-peer");
    assert.equal(JSON.parse(await android.inputValue("#config-editor")).peers, undefined);
    await android.click(".remove-network");
    assert.deepEqual(JSON.parse(await android.inputValue("#config-editor")).networks, []);
    await android.click("#add-network"); await android.locator(".network-cidr").fill("10.51.0.1/24");
    check("form_remove_peer_and_recreate_network");
    await android.locator(".network-cidr").fill("");
    await android.locator("#address-clients-settings > summary").click(); await android.click("#add-address-client");
    await android.locator(".address-client-address").fill("192.0.2.50:65534");
    await android.locator(".address-client-key").fill("blank-form-service-key"); await android.locator(".requested-network").fill("10.51.0.0/24");
    const blankManaged = JSON.parse(await android.inputValue("#config-editor"));
    assert.equal(blankManaged.networks, undefined);
    assert.deepEqual(blankManaged.address_clients[0], { address: "192.0.2.50:65534", shared_key: "blank-form-service-key", networks: ["10.51.0.0/24"] });
    check("blank_form_can_enter_automatic_client_without_static_placeholder");
    await android.locator("#subnet-settings > summary").click();
    assert(await android.locator("#add-subnet").isDisabled()); assert(await android.locator("#subnet-android-notice").isVisible());
    await android.setInputFiles("#config-file", { name: "publish.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify({ ...blankManaged, advertise_routes: [{ tunnel: "10.51.0.0/24", prefix: "192.168.70.0/24", snat: true }] })) });
    await android.waitForFunction(() => document.querySelector(".subnet-prefix"));
    assert(await android.locator(".subnet-prefix").isDisabled()); assert(await android.locator(".subnet-snat").isDisabled());
    await android.click("#save-config"); await android.waitForFunction(() => document.getElementById("config-feedback").textContent.includes("Android"));
    assert.equal(await android.evaluate(() => window.__androidCalls.filter((call) => call.action === "save_config").length), 0);
    assert.equal(JSON.parse(await android.inputValue("#config-editor")).advertise_routes[0].prefix, "192.168.70.0/24");
    check("android_access_only_preserves_but_blocks_imported_publication");
    await android.click(".remove-subnet"); assert.equal(JSON.parse(await android.inputValue("#config-editor")).advertise_routes, undefined);
    await android.click("#save-config"); await android.waitForFunction(() => window.__androidCalls.some((call) => call.action === "save_config"));
    check("android_can_explicitly_remove_publication_and_save_access_config");
    const androidSavedBeforeRemote = await android.evaluate(() => window.__androidCalls.filter(call => call.action === "save_config").length);
    await android.setInputFiles("#config-file", {name:"desktop.json",mimeType:"application/json",buffer:Buffer.from(JSON.stringify({...blankManaged,remote_desktop:{enabled:true,unattended:true}}))});
    await android.waitForFunction(()=>document.getElementById("remote-enabled").checked);
    await android.click("#save-config"); await android.waitForFunction(()=>document.getElementById("config-feedback").textContent.includes("远程桌面"));
    assert.equal(await android.evaluate(() => window.__androidCalls.filter(call => call.action === "save_config").length),androidSavedBeforeRemote);
    await android.click('[data-page="remote"]'); await android.locator("#remote-platform-notice").waitFor({state: "visible"});
    assert(await android.locator("#remote-connect").isDisabled()); assert(await android.locator("#remote-enabled").isDisabled());
    await android.click("#remote-remove-unsupported"); assert.equal(JSON.parse(await android.inputValue("#config-editor")).remote_desktop,undefined);
    await android.click('[data-page="config"]'); await android.click("#save-config");
    await android.waitForFunction((before)=>window.__androidCalls.filter(call=>call.action==="save_config").length>before,androidSavedBeforeRemote);
    check("android_desktop_import_is_visible_blocked_and_explicitly_removable");

    const delayed = await browser.newPage(); observe(delayed);
    await delayed.goto(url);
    await delayed.evaluate(() => {
      window.pywebview = { api: { request: async (raw) => JSON.stringify({ ok: true, data: JSON.parse(raw).action === "load_config" ? { text: "" } : { phase: "stopped", platform: "Delayed", logs: [] } }) } };
      window.dispatchEvent(new Event("pywebviewready"));
    });
    await delayed.waitForFunction(() => document.getElementById("local-platform").textContent === "Delayed"); check("delayed_pywebviewready_initializes_bridge");
    assert.deepEqual(report.page_errors, []);
    report.ok = true;
  } catch (error) {
    report.error = error.stack || String(error); process.exitCode = 1; console.error(report.error);
  } finally {
    if (browser) await browser.close();
    const output = path.join(options.output, "results.json");
    fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n", "utf8");
    console.log((report.ok ? "PASS" : "FAIL") + " " + report.checks.length + " frontend checks; " + output);
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
