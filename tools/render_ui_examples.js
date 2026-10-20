#!/usr/bin/env node
"use strict";

// Render the real frontend with fictional, offline bridge responses.
// Reads only examples/ui-node-a.json; never launches the core or creates a tunnel.
// node tools/render_ui_examples.js --playwright /path/to/playwright --browser /path/to/chrome
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const root = path.resolve(__dirname, "..");
const options = {
  output: path.join(root, "docs", "images"),
  playwright: process.env.PLAYWRIGHT_MODULE,
  browser: process.env.CHROME_PATH
};
for (let i = 2; i < process.argv.length; i += 1) {
  const option = process.argv[i];
  if (option === "--help") {
    console.log("Usage: node tools/render_ui_examples.js [--playwright MODULE_PATH] [--browser CHROME_PATH] [--output DIRECTORY]\n" +
      "Renders overview, configuration and log screenshots using fictional offline data.\n" +
      "Uses an installed Chrome/Edge or Playwright Chromium; does not download a browser.");
    process.exit(0);
  }
  if (!["--playwright", "--browser", "--output"].includes(option) || !process.argv[i + 1]) {
    throw new Error("Unknown or incomplete option: " + option);
  }
  options[option.slice(2)] = process.argv[++i];
}
options.output = path.resolve(options.output);

function browserExecutable() {
  if (options.browser) return path.resolve(options.browser);
  const candidates = process.platform === "win32" ? [
    path.join(process.env.PROGRAMFILES || "C:/Program Files", "Google/Chrome/Application/chrome.exe"),
    path.join(process.env["PROGRAMFILES(X86)"] || "C:/Program Files (x86)", "Microsoft/Edge/Application/msedge.exe")
  ] : process.platform === "darwin" ? [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
  ] : ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];
  return candidates.find((candidate) => fs.existsSync(candidate));
}

async function main() {
  const config = JSON.parse(fs.readFileSync(path.join(root, "examples", "ui-node-a.json"), "utf8"));
  assert.equal(config.address, "192.0.2.10:65535");
  assert.deepEqual(config.networks, ["10.1.0.1/24"]);
  assert.equal(config.peers.length, 1);
  assert.equal(config.peers[0].address, "192.0.2.20:65535");
  assert.equal(config.peers[0].shared_key, "replace-with-the-same-random-secret-on-both-nodes");
  let playwright;
  try { playwright = require(options.playwright ? path.resolve(options.playwright) : "playwright"); }
  catch (_) { throw new Error("Install Playwright separately, or pass --playwright /path/to/playwright."); }
  const browser = await playwright.chromium.launch({ executablePath: browserExecutable(), headless: true });
  const errors = [];
  const blockedRequests = [];
  const screenshots = [];
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1000 },
      deviceScaleFactor: 1,
      locale: "zh-CN",
      timezoneId: "Asia/Shanghai",
      reducedMotion: "reduce",
      serviceWorkers: "block"
    });
    await context.route(/^https?:\/\//, (route) => {
      blockedRequests.push(route.request().url());
      return route.abort();
    });
    const page = await context.newPage();
    page.on("pageerror", (error) => errors.push(error.message));
    page.setDefaultTimeout(10000);
    await page.addInitScript((config) => {
      const NativeDate = Date;
      const timestamp = new NativeDate("2026-10-20T10:15:00+08:00").getTime();
      window.Date = class extends NativeDate {
        constructor(...args) { super(...(args.length ? args : [timestamp])); }
        static now() { return timestamp; }
      };
      const token = "offline-documentation-preview";
      window.__TUNNEL_UI_TOKEN__ = token;
      window.__documentationCalls = [];
      const logs = [
        ["10:14:48", "info", "示例会话：以下状态和日志使用虚构数据，不连接真实节点。"],
        ["10:14:48", "info", "已载入节点配置，本机公布地址 192.0.2.10:65535"],
        ["10:14:48", "info", "虚拟网卡 Tunnel 已就绪，本机 IP 10.1.0.1/24，MTU 1280"],
        ["10:14:49", "info", "正在连接节点 192.0.2.20:65535"],
        ["10:14:49", "info", "TCP 控制通道认证通过：192.0.2.20:65535"],
        ["10:14:50", "info", "UDP 数据通道验证通过，邻接已建立"],
        ["10:14:50", "info", "收到网络 10.1.0.0/24 的路径更新，目的节点 192.0.2.20:65535"],
        ["10:14:51", "info", "端到端加密会话已建立：10.1.0.1 → 10.1.0.2"],
        ["10:14:55", "debug", "控制与数据通道保活验证成功"],
        ["10:14:56", "info", "配置校验通过，运行中的设置已应用"],
        ["10:14:59", "debug", "路径状态稳定，当前可用下一跳 192.0.2.20:65535"],
        ["10:15:00", "info", "示例传输正常：已转发 12,480 个数据包"]
      ].map(([time, level, message], index) => ({ id: index + 1, time, level, message }));
      const state = {
        phase: "running", platform: "Windows",
        config_path: "examples/ui-node-a.json", error: "",
        status: {
          running: true, node: config.address, device: "Tunnel", pending_connections: 0,
          peers: [{ node: config.peers[0].address, state: 3, transport: "udp" }],
          routes: [{ network: "10.1.0.0/24", node: config.peers[0].address, next_hops: [config.peers[0].address] }],
          end_sessions: [{ ready: true }],
          counters: { unicast_forwarded: 12480, udp_data_sent: 13206, udp_data_received: 12844, e2e_established: 1 }
        },
        logs
      };
      window.pywebview = { api: { request: async (raw) => {
        const request = JSON.parse(raw);
        window.__documentationCalls.push(request.action);
        if (request.token !== token) throw new Error("Invalid documentation token");
        let data;
        if (request.action === "get_state") data = state;
        else if (request.action === "load_config") data = { text: JSON.stringify(config, null, 2) + "\n", revision: "0".repeat(64) };
        else if (request.action === "remote_state") data = {};
        else throw new Error("Documentation fixture is read-only: " + request.action);
        return JSON.stringify({ ok: true, data });
      } } };
    }, config);
    await page.goto(pathToFileURL(path.join(root, "gui", "assets", "index.html")).href);
    await page.waitForFunction(() => document.getElementById("metric-peers").textContent === "1");
    assert.equal(await page.locator("#local-address").textContent(), "192.0.2.10:65535");
    fs.mkdirSync(options.output, { recursive: true });
    for (const section of ["overview", "config", "logs"]) {
      await page.click('[data-page="' + section + '"]');
      await page.locator("#page-" + section).waitFor({ state: "visible" });
      await page.evaluate(async () => {
        window.scrollTo(0, 0);
        await document.fonts.ready;
        await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      });
      const dimensions = await page.evaluate(() => ({
        width: document.documentElement.scrollWidth,
        height: Math.max(document.documentElement.scrollHeight, window.innerHeight),
        viewport: window.innerWidth
      }));
      assert(dimensions.width <= dimensions.viewport, section + " has horizontal page overflow");
      if (section === "config") {
        assert.equal(await page.locator(".peer-key").getAttribute("type"), "password");
        assert.equal(await page.locator("#json-settings").evaluate((element) => element.open), false);
        assert.equal(await page.locator("#config-editor").isVisible(), false);
      }
      assert(!(await page.locator("body").innerText()).includes(config.peers[0].shared_key));
      assert.deepEqual(errors, []);
      assert.deepEqual(blockedRequests, []);
      const name = "ui-" + section + ".png";
      const file = path.join(options.output, name);
      await page.screenshot({ path: file, fullPage: true, animations: "disabled" });
      screenshots.push({ file: path.relative(root, file).replaceAll("\\", "/"), width: dimensions.width, height: dimensions.height, bytes: fs.statSync(file).size });
    }
    assert.deepEqual(errors, []);
    assert.deepEqual(blockedRequests, []);
    assert(await page.evaluate(() => window.__documentationCalls.every((action) => ["get_state", "load_config", "remote_state"].includes(action))));
    console.log(JSON.stringify({ ok: true, fixture: "fictional offline data", page_errors: errors, external_requests: blockedRequests, screenshots }, null, 2));
  } finally {
    await browser.close();
  }
}
main().catch((error) => { console.error(error.stack || String(error)); process.exitCode = 1; });
