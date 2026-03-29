"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const child_process_1 = require("child_process");
const license_1 = require("./license");
const viewType = "my.cursorMyUi";
/** MCP 在 mcp.json 中最多注册数量（与 my-mcp-1 … my-mcp-N 一致） */
const MAX_WUKONG_SESSIONS = 32;
const DEFAULT_SESSION_ORDER = ["1", "2", "3"];
/** 在线购买支付页（与 wukong.payStoreUrl 默认一致；设置留空时用此值） */
const DEFAULT_PAY_STORE_URL = "http://5245.fun/pay.html";
const GLOBAL_STATE_SESSION_KEY = "wukong.sessionMessages.v1";
const GLOBAL_STATE_SESSION_ORDER_KEY = "wukong.sessionOrder.v1";
const GLOBAL_STATE_SESSION_MEMOS_KEY = "wukong.sessionMemos.v1";
const MAX_SESSION_MEMO_CHARS = 200;
function isValidSessionId(id) {
    const n = parseInt(id, 10);
    return Number.isInteger(n) && n >= 1 && n <= MAX_WUKONG_SESSIONS && String(n) === id;
}
/** 去重、校验、按编号排序 */
function normalizeSessionOrder(raw) {
    const arr = Array.isArray(raw) ? raw : [];
    const ids = arr.map((x) => String(x)).filter(isValidSessionId);
    const unique = [...new Set(ids)];
    unique.sort((a, b) => parseInt(a, 10) - parseInt(b, 10));
    return unique;
}
function readSessionOrder(context) {
    const stored = normalizeSessionOrder(context.globalState.get(GLOBAL_STATE_SESSION_ORDER_KEY));
    if (stored.length > 0)
        return stored;
    return [...DEFAULT_SESSION_ORDER];
}
function readSessionMemos(context) {
    const raw = context.globalState.get(GLOBAL_STATE_SESSION_MEMOS_KEY);
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
        return {};
    const out = {};
    for (const [k, v] of Object.entries(raw)) {
        if (!isValidSessionId(k))
            continue;
        const s = String(v ?? "")
            .trim()
            .slice(0, MAX_SESSION_MEMO_CHARS);
        if (s)
            out[k] = s;
    }
    return out;
}
const MANAGED_MCP_KEY = /^my-mcp-\d+$/;
/** 单条消息里所有附件 Base64 字符总长度上限（约 2MB 量级） */
const MAX_ATTACH_BASE64_CHARS = Math.floor(2.5 * 1024 * 1024);
function parseSendAttachments(message) {
    const images = [];
    const files = [];
    let total = 0;
    const rawImg = message.images;
    if (Array.isArray(rawImg)) {
        for (const x of rawImg) {
            if (!x || typeof x !== "object")
                continue;
            const o = x;
            const mimeType = String(o.mimeType ?? "");
            const data = String(o.data ?? "").replace(/\s/g, "");
            if (!mimeType || !data)
                continue;
            if (!mimeType.startsWith("image/"))
                continue;
            total += data.length;
            if (total > MAX_ATTACH_BASE64_CHARS) {
                return { images: [], files: [], error: "附件总体积过大（单条约 2MB 上限）" };
            }
            images.push({ mimeType, data });
        }
    }
    const rawFiles = message.files;
    if (Array.isArray(rawFiles)) {
        for (const x of rawFiles) {
            if (!x || typeof x !== "object")
                continue;
            const o = x;
            const name = String(o.name ?? "file")
                .replace(/[/\\]/g, "_")
                .slice(0, 240);
            const mimeType = String(o.mimeType ?? "application/octet-stream");
            const data = String(o.data ?? "").replace(/\s/g, "");
            if (!data)
                continue;
            total += data.length;
            if (total > MAX_ATTACH_BASE64_CHARS) {
                return { images: [], files: [], error: "附件总体积过大（单条约 2MB 上限）" };
            }
            files.push({ name, mimeType, data });
        }
    }
    return { images, files };
}
console.log(`[${viewType}] module loaded`);
/** Windows：侧栏 Webview 内无法使用浏览器 Speech API 的麦克风，改用系统语音识别（PowerShell + System.Speech） */
const WIN_VOICE_PS_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
  Add-Type -AssemblyName System.Speech | Out-Null
  $zh = [System.Globalization.CultureInfo]::new('zh-CN')
  $e = $null
  try { $e = New-Object System.Speech.Recognition.SpeechRecognitionEngine($zh) } catch { $e = New-Object System.Speech.Recognition.SpeechRecognitionEngine }
  $e.LoadGrammar((New-Object System.Speech.Recognition.DictationGrammar))
  $e.SetInputToDefaultAudioDevice()
  $res = $e.Recognize()
  if (-not $res -or -not $res.Text) { exit 2 }
  $b = [System.Text.Encoding]::UTF8.GetBytes($res.Text)
  [Console]::Out.Write([Convert]::ToBase64String($b))
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
`.trim();
function encodePowerShellCommandBody(body) {
    return Buffer.from(body, "utf16le").toString("base64");
}
function recognizeSpeechWindows(timeoutMs) {
    return new Promise((resolve) => {
        const sysRoot = process.env.SystemRoot || "C:\\Windows";
        const psExe = path.join(sysRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        const encoded = encodePowerShellCommandBody(WIN_VOICE_PS_SCRIPT);
        const ps = (0, child_process_1.spawn)(psExe, ["-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], {
            windowsHide: true,
        });
        const outChunks = [];
        let stderr = "";
        ps.stdout.on("data", (d) => {
            outChunks.push(Buffer.from(d));
        });
        ps.stderr.on("data", (d) => {
            stderr += d.toString("utf8");
        });
        const timer = setTimeout(() => {
            try {
                ps.kill();
            }
            catch {
                // ignore
            }
        }, timeoutMs);
        ps.on("close", (code) => {
            clearTimeout(timer);
            const stdout = Buffer.concat(outChunks).toString("utf8");
            const b64 = stdout.replace(/\s+/g, "").trim();
            if (code === 0 && b64.length > 0) {
                try {
                    const text = Buffer.from(b64, "base64").toString("utf8");
                    resolve({ ok: true, text });
                }
                catch {
                    resolve({ ok: false, err: "无法解析识别结果" });
                }
                return;
            }
            if (code === 2) {
                resolve({ ok: false, err: "未识别到有效语句，请重试并靠近麦克风说话" });
                return;
            }
            const errLine = stderr.trim() || (code != null ? `识别进程退出码 ${code}` : "识别失败");
            resolve({ ok: false, err: errLine });
        });
        ps.on("error", (e) => {
            clearTimeout(timer);
            resolve({ ok: false, err: String(e) });
        });
    });
}
function activate(context) {
    console.log(`[${viewType}] activate() called`);
    // 配置工作区命令：接收目标路径参数
    context.subscriptions.push(vscode.commands.registerCommand("my.cursorMyUi.configureWorkspace", async (targetPath, sessionOrderOverride) => {
        // 如果没有传入路径，使用当前工作区
        let workspacePath = targetPath;
        if (!workspacePath) {
            const folder = vscode.workspace.workspaceFolders?.[0];
            if (!folder) {
                throw new Error("请先选择或打开一个工作区文件夹");
            }
            workspacePath = folder.uri.fsPath;
        }
        // 验证路径存在
        if (!fs.existsSync(workspacePath)) {
            throw new Error(`路径不存在：${workspacePath}`);
        }
        const srcDir = path.join(context.extensionPath, "mcp-server");
        const destDir = path.join(os.homedir(), ".cursor", "my-mcp-server");
        const copyDir = (src, dest) => {
            if (!fs.existsSync(dest))
                fs.mkdirSync(dest, { recursive: true });
            for (const name of fs.readdirSync(src)) {
                if (name === "node_modules")
                    continue; // 跳过 node_modules
                const s = path.join(src, name);
                const d = path.join(dest, name);
                if (fs.statSync(s).isDirectory())
                    copyDir(s, d);
                else
                    fs.copyFileSync(s, d);
            }
        };
        copyDir(srcDir, destDir);
        const nodeModules = path.join(destDir, "node_modules");
        if (!fs.existsSync(nodeModules)) {
            (0, child_process_1.execSync)("npm install", { cwd: destDir, stdio: "inherit" });
        }
        const cursorDir = path.join(workspacePath, ".cursor");
        const mcpPath = path.join(cursorDir, "mcp.json");
        const mcpServerPath = path.join(destDir, "index.mjs");
        let mcpServers = {};
        if (fs.existsSync(mcpPath)) {
            try {
                const raw = fs.readFileSync(mcpPath, "utf-8");
                const existing = JSON.parse(raw);
                mcpServers = existing.mcpServers ?? {};
            }
            catch {
                mcpServers = {};
            }
        }
        const mcpServerPathNorm = mcpServerPath.replace(/\\/g, "/");
        delete mcpServers["my-mcp"];
        for (const key of Object.keys(mcpServers)) {
            if (MANAGED_MCP_KEY.test(key)) {
                delete mcpServers[key];
            }
        }
        let order;
        if (Array.isArray(sessionOrderOverride) && sessionOrderOverride.length > 0) {
            order = normalizeSessionOrder(sessionOrderOverride);
            if (order.length === 0) {
                order = readSessionOrder(context);
            }
        }
        else {
            order = readSessionOrder(context);
        }
        if (order.length === 0) {
            throw new Error("会话列表为空，请先在侧栏至少保留一路会话");
        }
        void context.globalState.update(GLOBAL_STATE_SESSION_ORDER_KEY, order);
        for (const id of order) {
            mcpServers[`my-mcp-${id}`] = {
                command: "node",
                args: [mcpServerPathNorm],
                env: { WUKONG_SESSION: id },
            };
        }
        if (!fs.existsSync(cursorDir)) {
            fs.mkdirSync(cursorDir, { recursive: true });
        }
        fs.writeFileSync(mcpPath, JSON.stringify({ mcpServers }, null, 2), "utf-8");
        // 写入规则文件，让 Cursor 持续调用 check_messages
        const rulesDir = path.join(cursorDir, "rules");
        if (!fs.existsSync(rulesDir)) {
            fs.mkdirSync(rulesDir, { recursive: true });
        }
        const rulePath = path.join(rulesDir, "my-mcp.mdc");
        const ruleContent = `---
description: 助手正文只在 Cursor 显示；用 check_messages 保持循环，不向插件镜像长回复
globs:
alwaysApply: true
---

# 悟空mcp 多会话规则

侧栏可「添加/删除会话」管理通道（最多 **${MAX_WUKONG_SESSIONS}** 路）。点击 **「开始配置」** 时，仅按**当前侧栏会话列表**在本工作区 \`mcp.json\` 写入对应的 **my-mcp-N**；**增删会话后必须再次配置**，否则 Cursor 里 MCP 列表与插件不一致。每个 Cursor 对话窗口只绑定其中一个 **my-mcp-N**。

## 核心规则

1. **先正常对话**：用户寒暄、提问、下任务时，要像普通聊天一样直接回应；**禁止**用「工具正常」「通道已验证」等套话代替回答（例如用户说「你好」就要正常回问候）。
2. **用户要看的内容**：写在 **Cursor 对话窗口**；**默认不传 \`reply\`**。
3. **循环**：每轮回应后**必须立刻**再调用当前 MCP 的 \`check_messages()\`，否则用户会感觉对话被中断。
4. 插件可能**每次只推一条消息**；连发多条会分多次送达，请逐次回复并继续 \`check_messages\`。

## 禁止

- ❌ 长篇解释 MCP/插件原理来代替对用户消息的回复
- ❌ 不调用 \`check_messages\` 就结束（等于中断用户）
- ❌ 等待用户在 Cursor 里打字（用户从插件发消息）

## 流程

\`\`\`
check_messages → 收到插件消息 → 【Cursor 完整回复】→ check_messages() → 等待…
\`\`\`
`;
        fs.writeFileSync(rulePath, ruleContent, "utf-8");
        return { mcpPath, rulePath, destDir, workspacePath, sessionIds: order };
    }));
    context.subscriptions.push(vscode.commands.registerCommand("wukong.generateLicenseKey", async () => {
        const adminPwd = vscode.workspace.getConfiguration("wukong").get("adminPassword") ?? "";
        if (typeof adminPwd === "string" && adminPwd.trim().length > 0) {
            const pw = await vscode.window.showInputBox({
                password: true,
                title: "悟空mcp 管理员",
                prompt: "请输入管理员密码",
            });
            if (pw !== adminPwd) {
                void vscode.window.showErrorMessage("密码错误");
                return;
            }
        }
        const pick = await vscode.window.showQuickPick([
            { label: "$(infinity) 永久卡", description: "长期有效", dur: "perm" },
            { label: "$(calendar) 天卡", description: "激活后 24 小时", dur: "1d" },
            { label: "$(clock) 小时卡", description: "激活后 1 小时", dur: "1h" },
            { label: "$(watch) 自定义时长", description: "指定分钟数（激活后起算）", dur: "timed" },
        ], { placeHolder: "选择卡密类型", title: "生成悟空mcp 卡密" });
        if (!pick)
            return;
        const secret = (0, license_1.getLicenseSecret)();
        let key;
        if (pick.dur === "timed") {
            const rawMin = await vscode.window.showInputBox({
                title: "自定义时长（分钟）",
                prompt: "激活后有效时长，整数分钟",
                placeHolder: "例如 4320 表示 3 天",
                validateInput: (v) => {
                    const n = parseInt(String(v).trim(), 10);
                    if (!Number.isFinite(n) || n < 1 || n > 5256000) {
                        return "请输入 1～5256000 之间的整数（约 10 年）";
                    }
                    return undefined;
                },
            });
            if (rawMin === undefined)
                return;
            const durationMs = parseInt(String(rawMin).trim(), 10) * 60 * 1000;
            key = (0, license_1.generateLicenseToken)(secret, "timed", durationMs);
        }
        else {
            key = (0, license_1.generateLicenseToken)(secret, pick.dur);
        }
        await vscode.env.clipboard.writeText(key);
        const choice = await vscode.window.showInformationMessage(`卡密已复制到剪贴板。\n类型：${pick.label}\n（验证端 settings 中 wukong.licenseSecret 须与发卡时一致）`, "再复制一次");
        if (choice === "再复制一次") {
            await vscode.env.clipboard.writeText(key);
        }
    }));
    context.subscriptions.push(vscode.commands.registerCommand("wukong.clearLicense", async () => {
        const adminPwd = vscode.workspace.getConfiguration("wukong").get("adminPassword") ?? "";
        if (typeof adminPwd === "string" && adminPwd.trim().length > 0) {
            const pw = await vscode.window.showInputBox({
                password: true,
                title: "悟空mcp",
                prompt: "请输入管理员密码",
            });
            if (pw !== adminPwd) {
                void vscode.window.showErrorMessage("密码错误");
                return;
            }
        }
        const confirm = await vscode.window.showWarningMessage("将清除本机激活状态，需重新输入卡密后才能使用插件。", { modal: true }, "确定清除");
        if (confirm !== "确定清除")
            return;
        await (0, license_1.clearLicenseState)(context);
        await (0, license_1.clearTrialUntilState)(context);
        void vscode.window.showInformationMessage("已清除激活状态，请重新打开侧栏或激活。");
    }));
    const provider = {
        resolveWebviewView(webviewView) {
            console.log(`[${viewType}] resolveWebviewView() called`);
            webviewView.webview.options = {
                enableScripts: true,
                localResourceRoots: [context.extensionUri],
            };
            const nonce = getNonce();
            const extVer = String(context.extension.packageJSON.version ?? "");
            const payStoreRaw = vscode.workspace.getConfiguration("wukong").get("payStoreUrl");
            const payStoreUrl = typeof payStoreRaw === "string" && payStoreRaw.trim() ? payStoreRaw.trim() : DEFAULT_PAY_STORE_URL;
            webviewView.webview.html = getHtml(webviewView.webview, nonce, extVer, payStoreUrl);
            const queueDirFixed = path.join(os.homedir(), ".cursor", "my-mcp-messages");
            const lastReplyBySession = {};
            for (let n = 1; n <= MAX_WUKONG_SESSIONS; n++) {
                lastReplyBySession[String(n)] = "";
            }
            const pollIntervalMs = 800;
            const intervalId = setInterval(() => {
                for (let n = 1; n <= MAX_WUKONG_SESSIONS; n++) {
                    const sid = String(n);
                    try {
                        const replyPath = path.join(queueDirFixed, "s", sid, "reply.json");
                        if (!fs.existsSync(replyPath))
                            continue;
                        const raw = fs.readFileSync(replyPath, "utf-8");
                        const parsed = JSON.parse(raw);
                        const ts = String(parsed.timestamp ?? "");
                        if (!ts || ts === lastReplyBySession[sid])
                            continue;
                        lastReplyBySession[sid] = ts;
                        const reply = String(parsed.reply ?? "");
                        webviewView.webview.postMessage({
                            command: "cursorReply",
                            reply,
                            time: ts,
                            sessionId: sid,
                        });
                        try {
                            fs.unlinkSync(replyPath);
                        }
                        catch {
                            // ignore
                        }
                    }
                    catch {
                        // ignore
                    }
                }
            }, pollIntervalMs);
            const sessionOrder = readSessionOrder(context);
            setTimeout(() => {
                webviewView.webview.postMessage({ command: "restoreSessionOrder", order: sessionOrder });
                webviewView.webview.postMessage({ command: "restoreSessionMemos", memos: readSessionMemos(context) });
            }, 50);
            const savedHist = context.globalState.get(GLOBAL_STATE_SESSION_KEY);
            if (savedHist) {
                setTimeout(() => {
                    webviewView.webview.postMessage({ command: "restoreHistories", payload: savedHist });
                }, 100);
            }
            const disposable = webviewView.webview.onDidReceiveMessage(async (message) => {
                if (!message || typeof message !== "object")
                    return;
                const cmd = message.command;
                const cmdStr = typeof cmd === "string" ? cmd : "";
                if (cmdStr === "requestLicenseStatus") {
                    (0, license_1.clearExpiredLicenseIfNeeded)(context);
                    (0, license_1.clearExpiredTrialIfNeeded)(context);
                    await (0, license_1.enforceCloudLicenseRevocationCheck)(context);
                    (0, license_1.clearExpiredLicenseIfNeeded)(context);
                    webviewView.webview.postMessage({
                        command: "licenseStatus",
                        ...(0, license_1.getLicenseStatusForWebview)(context),
                    });
                    return;
                }
                if (cmdStr === "activateLicense") {
                    const key = String(message.key ?? "");
                    const r = await (0, license_1.tryActivateLicenseAsync)(context, key);
                    webviewView.webview.postMessage({
                        command: "licenseActivationResult",
                        ok: r.ok,
                        msg: r.msg,
                    });
                    if (r.ok) {
                        webviewView.webview.postMessage({
                            command: "licenseStatus",
                            ...(0, license_1.getLicenseStatusForWebview)(context),
                        });
                        const ord = readSessionOrder(context);
                        webviewView.webview.postMessage({ command: "restoreSessionOrder", order: ord });
                        webviewView.webview.postMessage({ command: "restoreSessionMemos", memos: readSessionMemos(context) });
                        const hist = context.globalState.get(GLOBAL_STATE_SESSION_KEY);
                        if (hist) {
                            webviewView.webview.postMessage({ command: "restoreHistories", payload: hist });
                        }
                    }
                    return;
                }
                if (cmdStr === "startTrial30") {
                    const r = (0, license_1.tryStartTrial30)(context);
                    webviewView.webview.postMessage({
                        command: "trialResult",
                        ok: r.ok,
                        msg: r.msg,
                    });
                    if (r.ok) {
                        webviewView.webview.postMessage({
                            command: "licenseStatus",
                            ...(0, license_1.getLicenseStatusForWebview)(context),
                        });
                        const ord = readSessionOrder(context);
                        webviewView.webview.postMessage({ command: "restoreSessionOrder", order: ord });
                        webviewView.webview.postMessage({ command: "restoreSessionMemos", memos: readSessionMemos(context) });
                        const hist = context.globalState.get(GLOBAL_STATE_SESSION_KEY);
                        if (hist) {
                            webviewView.webview.postMessage({ command: "restoreHistories", payload: hist });
                        }
                    }
                    return;
                }
                if (cmdStr === "deactivateLicense") {
                    const choice = await vscode.window.showWarningMessage("确定注销激活？清除后需重新输入卡密才能使用本扩展。", { modal: true }, "确定注销");
                    if (choice !== "确定注销") {
                        return;
                    }
                    await (0, license_1.clearLicenseState)(context);
                    await (0, license_1.clearTrialUntilState)(context);
                    webviewView.webview.postMessage({
                        command: "licenseStatus",
                        ...(0, license_1.getLicenseStatusForWebview)(context),
                    });
                    void vscode.window.showInformationMessage("已注销激活");
                    return;
                }
                if (cmdStr === "openPayStore") {
                    const raw = vscode.workspace.getConfiguration("wukong").get("payStoreUrl");
                    const u = typeof raw === "string" && raw.trim() ? raw.trim() : DEFAULT_PAY_STORE_URL;
                    await vscode.env.openExternal(vscode.Uri.parse(u));
                    return;
                }
                // 选择文件夹
                if (cmd === "selectFolder") {
                    try {
                        const result = await vscode.window.showOpenDialog({
                            canSelectFiles: false,
                            canSelectFolders: true,
                            canSelectMany: false,
                            openLabel: "选择工作区",
                            title: "选择要配置 MCP 的工作区文件夹",
                        });
                        if (result && result.length > 0) {
                            const selectedPath = result[0].fsPath;
                            webviewView.webview.postMessage({
                                command: "folderSelected",
                                path: selectedPath,
                            });
                        }
                    }
                    catch (e) {
                        webviewView.webview.postMessage({
                            command: "folderSelected",
                            path: null,
                            error: String(e),
                        });
                    }
                    return;
                }
                /** 将当前窗口打开的工作区根路径填回侧栏输入框 */
                if (cmd === "requestCurrentWorkspace") {
                    const folder = vscode.workspace.workspaceFolders?.[0];
                    if (folder) {
                        webviewView.webview.postMessage({
                            command: "folderSelected",
                            path: folder.uri.fsPath,
                            fromCurrentWorkspace: true,
                        });
                    }
                    else {
                        webviewView.webview.postMessage({
                            command: "folderSelected",
                            path: null,
                            error: "当前没有打开工作区，请先用「文件 → 打开文件夹」打开一个项目",
                        });
                    }
                    return;
                }
                // 配置工作区（带路径参数）
                if (cmd === "configureWorkspace") {
                    const targetPath = message.path;
                    const orderRaw = message.sessionOrder;
                    const orderFromUi = Array.isArray(orderRaw) ? orderRaw.map((x) => String(x)) : undefined;
                    try {
                        const result = await vscode.commands.executeCommand("my.cursorMyUi.configureWorkspace", targetPath, orderFromUi);
                        const mcpList = (result?.sessionIds ?? []).map((id) => `my-mcp-${id}`).join("、");
                        webviewView.webview.postMessage({
                            command: "configResult",
                            ok: true,
                            msg: `已配置 MCP！\n工作区：${result?.workspacePath}\n已按当前侧栏注册 ${result?.sessionIds?.length ?? 0} 路：${mcpList || "（无）"}\n已清理本扩展在旧配置里多余的 my-mcp-* 项。\n配置文件：${result?.mcpPath}\n规则：${result?.rulePath}\n保存后 Cursor 会按新列表加载 MCP。`,
                            workspacePath: result?.workspacePath,
                        });
                    }
                    catch (e) {
                        webviewView.webview.postMessage({
                            command: "configResult",
                            ok: false,
                            msg: String(e),
                        });
                    }
                    return;
                }
                if (cmd === "persistSessionOrder") {
                    const raw = message.order;
                    const next = normalizeSessionOrder(raw);
                    if (next.length === 0)
                        return;
                    void context.globalState.update(GLOBAL_STATE_SESSION_ORDER_KEY, next);
                    return;
                }
                if (cmd === "persistSessionMemos") {
                    const raw = message.memos;
                    if (!raw || typeof raw !== "object" || Array.isArray(raw))
                        return;
                    const next = {};
                    for (const [k, v] of Object.entries(raw)) {
                        if (!isValidSessionId(k))
                            continue;
                        const s = String(v ?? "")
                            .trim()
                            .slice(0, MAX_SESSION_MEMO_CHARS);
                        if (s)
                            next[k] = s;
                    }
                    void context.globalState.update(GLOBAL_STATE_SESSION_MEMOS_KEY, next);
                    return;
                }
                if (cmd === "copyCheckPhrase") {
                    const sid = String(message.sessionId ?? "1");
                    if (!isValidSessionId(sid)) {
                        return;
                    }
                    const phrase = `请使用 my-mcp-${sid} 的 check_messages`;
                    await vscode.env.clipboard.writeText(phrase);
                    webviewView.webview.postMessage({ command: "copyPhraseResult", ok: true });
                    return;
                }
                if (cmd === "persistHistories") {
                    const payload = message.payload;
                    if (typeof payload === "string") {
                        void context.globalState.update(GLOBAL_STATE_SESSION_KEY, payload);
                    }
                    return;
                }
                if (cmdStr === "voiceInputNative") {
                    if (process.platform !== "win32") {
                        webviewView.webview.postMessage({
                            command: "voiceInputResult",
                            ok: false,
                            msg: "系统语音仅支持 Windows",
                        });
                        return;
                    }
                    const r = await recognizeSpeechWindows(50000);
                    webviewView.webview.postMessage({
                        command: "voiceInputResult",
                        ok: r.ok,
                        text: r.text ?? "",
                        msg: r.err ?? "",
                    });
                    return;
                }
                if (cmd === "sendMessage") {
                    const msgObj = message;
                    const text = String(msgObj.text ?? "").trim();
                    const workspacePath = msgObj.workspacePath;
                    const sessionId = String(msgObj.sessionId ?? "1");
                    if (!isValidSessionId(sessionId)) {
                        webviewView.webview.postMessage({ command: "sendResult", ok: false, msg: "无效会话 ID（超出范围）" });
                        return;
                    }
                    const { images, files, error: attachErr } = parseSendAttachments(msgObj);
                    if (attachErr) {
                        webviewView.webview.postMessage({ command: "sendResult", ok: false, msg: attachErr });
                        return;
                    }
                    if (!text && images.length === 0 && files.length === 0) {
                        webviewView.webview.postMessage({
                            command: "sendResult",
                            ok: false,
                            msg: "请输入文字或添加图片/文件",
                        });
                        return;
                    }
                    const queueDir = path.join(os.homedir(), ".cursor", "my-mcp-messages");
                    const sessionDir = path.join(queueDir, "s", sessionId);
                    const queuePath = path.join(sessionDir, "messages.json");
                    if (workspacePath) {
                        const workspaceInfoPath = path.join(queueDir, "workspace.json");
                        try {
                            if (!fs.existsSync(queueDir))
                                fs.mkdirSync(queueDir, { recursive: true });
                            fs.writeFileSync(workspaceInfoPath, JSON.stringify({ workspacePath, time: new Date().toISOString() }, null, 2), "utf-8");
                        }
                        catch {
                            // ignore
                        }
                    }
                    let data = { messages: [] };
                    try {
                        if (fs.existsSync(queuePath)) {
                            data = JSON.parse(fs.readFileSync(queuePath, "utf-8"));
                        }
                    }
                    catch {
                        data = { messages: [] };
                    }
                    data.messages = data.messages ?? [];
                    const entry = {
                        text: text || (images.length || files.length ? "(附件)" : ""),
                        time: new Date().toISOString(),
                    };
                    if (images.length > 0)
                        entry.images = images;
                    if (files.length > 0)
                        entry.files = files;
                    data.messages.push(entry);
                    const attachmentLabels = [];
                    if (images.length > 0)
                        attachmentLabels.push(`图片 ×${images.length}`);
                    if (files.length > 0)
                        attachmentLabels.push(...files.map((f) => f.name));
                    try {
                        if (!fs.existsSync(sessionDir))
                            fs.mkdirSync(sessionDir, { recursive: true });
                        fs.writeFileSync(queuePath, JSON.stringify(data, null, 2), "utf-8");
                        webviewView.webview.postMessage({
                            command: "sendResult",
                            ok: true,
                            msg: `已发送到 MCP-${sessionId}！在对应 Cursor 对话中说「请使用 my-mcp-${sessionId} 的 check_messages」获取。`,
                            text: text || "(仅附件)",
                            attachmentLabels,
                            sessionId,
                        });
                    }
                    catch (e) {
                        webviewView.webview.postMessage({ command: "sendResult", ok: false, msg: String(e) });
                    }
                    return;
                }
                if (cmd === "ping") {
                    const text = String(message.text ?? "");
                    console.log(`[${viewType}] onDidReceiveMessage ping, text=`, text);
                    webviewView.webview.postMessage({ command: "pong", text, time: new Date().toISOString() });
                }
            });
            context.subscriptions.push(disposable);
            context.subscriptions.push({ dispose: () => clearInterval(intervalId) });
        },
    };
    context.subscriptions.push(vscode.window.registerWebviewViewProvider(viewType, provider));
}
exports.activate = activate;
function deactivate() { }
exports.deactivate = deactivate;
function escapeHtmlText(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function getHtml(webview, nonce, extensionVersion, payStoreUrl) {
    const payUrlDisplay = escapeHtmlText(payStoreUrl);
    const csp = `
    default-src 'none';
    img-src ${webview.cspSource} data:;
    style-src ${webview.cspSource} 'unsafe-inline';
    script-src 'nonce-${nonce}';
  `.replace(/\s+/g, " ").trim();
    return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <title>悟空mcp</title>
  <style>
    :root {
      --bg-primary: #1e1e2e;
      --bg-secondary: #313244;
      --bg-tertiary: #45475a;
      --text-primary: #cdd6f4;
      --text-secondary: #a6adc8;
      --text-muted: #6c7086;
      --accent: #89b4fa;
      --accent-hover: #b4befe;
      --success: #a6e3a1;
      --error: #f38ba8;
      --warning: #f9e2af;
      --border: #45475a;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html, body { height: 100%; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      padding: 8px;
      font-size: 13px;
      line-height: 1.5;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }
    #licenseGate { display: none !important; }
    .license-gate {
      flex: 1;
      display: flex;
      flex-direction: column;
      align-items: stretch;
      justify-content: center;
      max-width: 380px;
      margin: 0 auto;
      width: 100%;
      gap: 10px;
      min-height: 0;
    }
    .license-gate-head {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
    }
    .license-logo { font-size: 18px; font-weight: 700; text-align: center; letter-spacing: 0.02em; }
    .license-gate .header-version { margin-top: 0; }
    .license-desc { font-size: 12px; color: var(--text-muted); text-align: center; line-height: 1.45; }
    .license-pay-strip {
      width: 100%;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid rgba(137, 180, 250, 0.35);
      background: rgba(137, 180, 250, 0.08);
      text-align: center;
    }
    .license-pay-title {
      font-size: 11px;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 6px;
      letter-spacing: 0.02em;
    }
    .license-pay-url {
      font-family: ui-monospace, Consolas, monospace;
      font-size: 10px;
      color: var(--text-secondary);
      word-break: break-all;
      line-height: 1.4;
      margin-bottom: 8px;
      user-select: all;
    }
    .btn-pay-store {
      width: 100%;
      padding: 8px 12px;
      border-radius: 8px;
      border: 1px solid var(--accent);
      background: rgba(137, 180, 250, 0.15);
      color: var(--accent-hover);
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
    }
    .btn-pay-store:hover { filter: brightness(1.12); background: rgba(137, 180, 250, 0.22); }
    .license-key-input {
      width: 100%;
      padding: 10px 11px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--bg-primary);
      color: var(--text-primary);
      font-size: 12px;
      font-family: ui-monospace, Consolas, monospace;
      outline: none;
    }
    .license-key-input:focus { border-color: var(--accent); }
    .license-actions { display: flex; flex-direction: column; gap: 8px; width: 100%; }
    .license-gate .btn-primary { width: 100%; justify-content: center; }
    .btn-trial {
      width: 100%;
      padding: 9px 12px;
      border-radius: 8px;
      border: 1px dashed var(--border);
      background: transparent;
      color: var(--accent);
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
    }
    .btn-trial:hover { background: rgba(137, 180, 250, 0.1); border-style: solid; }
    .license-foot { font-size: 9px; color: var(--text-muted); text-align: center; margin-top: 8px; line-height: 1.45; }
    #licenseFeedback { margin-top: 4px; }
    .contact-strip {
      margin-top: 12px;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: rgba(137, 180, 250, 0.07);
      font-size: 10px;
      line-height: 1.55;
      color: var(--text-secondary);
      text-align: center;
    }
    .contact-strip--gate { margin-top: 14px; }
    .contact-strip-title {
      font-weight: 600;
      color: var(--accent);
      margin-bottom: 6px;
      font-size: 11px;
    }
    .contact-strip-line { margin: 3px 0; }
    .contact-num {
      font-family: ui-monospace, Consolas, monospace;
      color: var(--text-primary);
      user-select: all;
    }
    .contact-strip-note {
      margin-top: 8px;
      font-size: 9px;
      color: var(--text-muted);
    }
    .contact-strip--main {
      margin-top: 10px;
      flex-shrink: 0;
    }
    .app-layout {
      display: flex;
      flex: 1;
      gap: 0;
      min-height: 0;
      align-items: stretch;
    }
    .rail-resizer {
      width: 6px;
      flex-shrink: 0;
      margin: 0 2px;
      cursor: col-resize;
      align-self: stretch;
      border-radius: 4px;
      background: transparent;
      transition: background 0.15s;
    }
    .rail-resizer:hover,
    .rail-resizer.is-dragging {
      background: rgba(137, 180, 250, 0.35);
    }
    .session-rail {
      min-width: 56px;
      max-width: 220px;
      width: 88px;
      flex-shrink: 0;
      background: var(--bg-secondary);
      border-radius: 8px;
      padding: 8px 6px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      align-items: stretch;
      box-sizing: border-box;
    }
    .session-rail-title {
      font-size: 10px;
      font-weight: 600;
      color: var(--text-muted);
      text-align: center;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .session-item {
      border: 1px solid transparent;
      padding: 8px 4px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      transition: box-shadow 0.15s, border-color 0.15s, filter 0.15s;
    }
    .session-item:hover { filter: brightness(1.08); }
    .session-item.active {
      box-shadow: 0 0 0 2px var(--sess-ring, rgba(137, 180, 250, 0.55));
    }
    /* 12 色循环：MCP 编号按 (N-1)%12 取色，便于一眼区分各路 */
    .session-item.session-tone-0 { --sess-ring: rgba(34, 211, 238, 0.65); background: rgba(34, 211, 238, 0.14); border-color: rgba(34, 211, 238, 0.42); color: #a5f3fc; }
    .session-item.session-tone-1 { --sess-ring: rgba(96, 165, 250, 0.65); background: rgba(96, 165, 250, 0.14); border-color: rgba(96, 165, 250, 0.42); color: #bfdbfe; }
    .session-item.session-tone-2 { --sess-ring: rgba(129, 140, 248, 0.65); background: rgba(129, 140, 248, 0.14); border-color: rgba(129, 140, 248, 0.42); color: #c7d2fe; }
    .session-item.session-tone-3 { --sess-ring: rgba(192, 132, 252, 0.65); background: rgba(192, 132, 252, 0.14); border-color: rgba(192, 132, 252, 0.42); color: #e9d5ff; }
    .session-item.session-tone-4 { --sess-ring: rgba(244, 114, 182, 0.65); background: rgba(244, 114, 182, 0.14); border-color: rgba(244, 114, 182, 0.42); color: #fbcfe8; }
    .session-item.session-tone-5 { --sess-ring: rgba(251, 113, 133, 0.65); background: rgba(251, 113, 133, 0.14); border-color: rgba(251, 113, 133, 0.42); color: #fecdd3; }
    .session-item.session-tone-6 { --sess-ring: rgba(251, 146, 60, 0.65); background: rgba(251, 146, 60, 0.14); border-color: rgba(251, 146, 60, 0.42); color: #fed7aa; }
    .session-item.session-tone-7 { --sess-ring: rgba(250, 204, 21, 0.65); background: rgba(250, 204, 21, 0.14); border-color: rgba(250, 204, 21, 0.42); color: #fef08a; }
    .session-item.session-tone-8 { --sess-ring: rgba(163, 230, 53, 0.65); background: rgba(163, 230, 53, 0.14); border-color: rgba(163, 230, 53, 0.42); color: #d9f99d; }
    .session-item.session-tone-9 { --sess-ring: rgba(52, 211, 153, 0.65); background: rgba(52, 211, 153, 0.14); border-color: rgba(52, 211, 153, 0.42); color: #a7f3d0; }
    .session-item.session-tone-10 { --sess-ring: rgba(45, 212, 191, 0.65); background: rgba(45, 212, 191, 0.14); border-color: rgba(45, 212, 191, 0.42); color: #99f6e4; }
    .session-item.session-tone-11 { --sess-ring: rgba(125, 211, 252, 0.65); background: rgba(125, 211, 252, 0.14); border-color: rgba(125, 211, 252, 0.42); color: #bae6fd; }

    .session-memo-strip {
      border-radius: 8px;
      padding: 8px 10px;
      margin-bottom: 10px;
      border: 1px solid var(--border);
      border-left-width: 4px;
      background: var(--bg-secondary);
    }
    .session-memo-strip.session-tone-0 { border-left-color: #22d3ee; background: linear-gradient(90deg, rgba(34, 211, 238, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-1 { border-left-color: #60a5fa; background: linear-gradient(90deg, rgba(96, 165, 250, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-2 { border-left-color: #818cf8; background: linear-gradient(90deg, rgba(129, 140, 248, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-3 { border-left-color: #c084fc; background: linear-gradient(90deg, rgba(192, 132, 252, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-4 { border-left-color: #f472b6; background: linear-gradient(90deg, rgba(244, 114, 182, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-5 { border-left-color: #fb7185; background: linear-gradient(90deg, rgba(251, 113, 133, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-6 { border-left-color: #fb923c; background: linear-gradient(90deg, rgba(251, 146, 60, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-7 { border-left-color: #facc15; background: linear-gradient(90deg, rgba(250, 204, 21, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-8 { border-left-color: #a3e635; background: linear-gradient(90deg, rgba(163, 230, 53, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-9 { border-left-color: #34d399; background: linear-gradient(90deg, rgba(52, 211, 153, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-10 { border-left-color: #2dd4bf; background: linear-gradient(90deg, rgba(45, 212, 191, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip.session-tone-11 { border-left-color: #7dd3fc; background: linear-gradient(90deg, rgba(125, 211, 252, 0.1) 0%, var(--bg-secondary) 48%); }
    .session-memo-strip-head {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
    }
    .session-memo-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      background: var(--bg-tertiary);
      color: var(--text-primary);
      letter-spacing: 0.02em;
    }
    .session-memo-hint { font-size: 10px; color: var(--text-muted); }
    .session-memo-input {
      width: 100%;
      padding: 7px 9px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg-primary);
      color: var(--text-primary);
      font-size: 12px;
      outline: none;
    }
    .session-memo-input:focus { border-color: var(--accent); }
    .session-memo-input::placeholder { color: var(--text-muted); font-size: 11px; }

    .send-message-section.session-tone-0 { border-left: 4px solid #22d3ee; background: linear-gradient(180deg, rgba(34, 211, 238, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-1 { border-left: 4px solid #60a5fa; background: linear-gradient(180deg, rgba(96, 165, 250, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-2 { border-left: 4px solid #818cf8; background: linear-gradient(180deg, rgba(129, 140, 248, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-3 { border-left: 4px solid #c084fc; background: linear-gradient(180deg, rgba(192, 132, 252, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-4 { border-left: 4px solid #f472b6; background: linear-gradient(180deg, rgba(244, 114, 182, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-5 { border-left: 4px solid #fb7185; background: linear-gradient(180deg, rgba(251, 113, 133, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-6 { border-left: 4px solid #fb923c; background: linear-gradient(180deg, rgba(251, 146, 60, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-7 { border-left: 4px solid #facc15; background: linear-gradient(180deg, rgba(250, 204, 21, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-8 { border-left: 4px solid #a3e635; background: linear-gradient(180deg, rgba(163, 230, 53, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-9 { border-left: 4px solid #34d399; background: linear-gradient(180deg, rgba(52, 211, 153, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-10 { border-left: 4px solid #2dd4bf; background: linear-gradient(180deg, rgba(45, 212, 191, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section.session-tone-11 { border-left: 4px solid #7dd3fc; background: linear-gradient(180deg, rgba(125, 211, 252, 0.06) 0%, var(--bg-secondary) 36%); }
    .send-message-section .section-title { display: flex; align-items: center; gap: 8px; }
    .send-section-color-dot {
      width: 8px; height: 8px; border-radius: 50%;
      flex-shrink: 0;
    }
    .send-message-section.session-tone-0 .send-section-color-dot { background: #22d3ee; }
    .send-message-section.session-tone-1 .send-section-color-dot { background: #60a5fa; }
    .send-message-section.session-tone-2 .send-section-color-dot { background: #818cf8; }
    .send-message-section.session-tone-3 .send-section-color-dot { background: #c084fc; }
    .send-message-section.session-tone-4 .send-section-color-dot { background: #f472b6; }
    .send-message-section.session-tone-5 .send-section-color-dot { background: #fb7185; }
    .send-message-section.session-tone-6 .send-section-color-dot { background: #fb923c; }
    .send-message-section.session-tone-7 .send-section-color-dot { background: #eab308; }
    .send-message-section.session-tone-8 .send-section-color-dot { background: #a3e635; }
    .send-message-section.session-tone-9 .send-section-color-dot { background: #34d399; }
    .send-message-section.session-tone-10 .send-section-color-dot { background: #2dd4bf; }
    .send-message-section.session-tone-11 .send-section-color-dot { background: #7dd3fc; }
    .session-row {
      display: flex;
      align-items: stretch;
      gap: 4px;
    }
    .session-row .session-item { flex: 1; min-width: 0; }
    .session-del {
      flex-shrink: 0;
      width: 26px;
      border: 1px solid var(--border);
      background: var(--bg-primary);
      color: var(--text-muted);
      border-radius: 6px;
      font-size: 14px;
      line-height: 1;
      cursor: pointer;
      padding: 0;
    }
    .session-del:hover { color: var(--error); border-color: var(--error); }
    .btn-add-session {
      width: 100%;
      margin-top: 6px;
      padding: 6px 4px;
      border: 1px dashed var(--border);
      border-radius: 6px;
      background: transparent;
      color: var(--accent);
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-add-session:hover { border-color: var(--accent); background: rgba(137,180,250,0.08); }
    .btn-add-session:disabled { opacity: 0.4; cursor: not-allowed; }
    .session-rail-hint {
      font-size: 8px;
      color: var(--text-muted);
      line-height: 1.35;
      margin-top: 4px;
      text-align: center;
    }
    .app-main {
      flex: 1;
      min-width: 0;
      display: flex;
      flex-direction: column;
      gap: 0;
      overflow-y: auto;
      overflow-x: hidden;
    }
    .header {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border);
    }
    .header h2 { font-size: 15px; font-weight: 600; flex-shrink: 0; }
    .header-version {
      font-size: 10px;
      font-weight: 500;
      color: var(--text-muted);
      font-family: ui-monospace, Consolas, monospace;
      padding: 2px 8px;
      border-radius: 6px;
      background: var(--bg-primary);
      border: 1px solid var(--border);
      flex-shrink: 0;
    }
    .status-dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--text-muted);
      transition: background 0.3s;
    }
    .status-dot.connected { background: var(--success); }
    .status-dot.pending { background: var(--warning); animation: pulse 1.5s infinite; }
    .status-dot.error { background: var(--error); }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

    .section {
      background: var(--bg-secondary);
      border-radius: 8px;
      padding: 10px;
      margin-bottom: 10px;
    }
    .section-title {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--text-muted);
      margin-bottom: 8px;
      letter-spacing: 0.5px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 12px;
      border: none;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      background: var(--bg-tertiary);
      color: var(--text-primary);
    }
    .btn:hover { background: var(--accent); color: var(--bg-primary); }
    .btn:active { transform: scale(0.98); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: var(--accent); color: var(--bg-primary); }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-small { padding: 5px 10px; font-size: 11px; }

    .path-input-group {
      display: flex;
      gap: 6px;
      margin-bottom: 8px;
    }
    .path-input {
      flex: 1;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg-primary);
      color: var(--text-primary);
      font-size: 11px;
      outline: none;
      font-family: 'Consolas', 'Monaco', monospace;
    }
    .path-input:focus { border-color: var(--accent); }
    .path-input::placeholder { color: var(--text-muted); }

    .btn-row {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .input-actions {
      display: flex;
      flex-direction: column;
      gap: 6px;
      flex-shrink: 0;
      align-items: stretch;
    }
    .btn-voice {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      padding: 7px 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s, border-color 0.2s, box-shadow 0.2s;
      background: var(--bg-tertiary);
      color: var(--text-primary);
    }
    .btn-voice:hover { border-color: var(--accent); color: var(--accent); }
    .btn-voice:disabled { opacity: 0.45; cursor: not-allowed; }
    .btn-voice.listening {
      border-color: rgba(243, 139, 168, 0.55);
      color: #f38ba8;
      box-shadow: 0 0 0 2px rgba(243, 139, 168, 0.2);
      animation: pulse 1.2s ease-in-out infinite;
    }
    .input-group {
      display: flex;
      gap: 8px;
      margin-top: 8px;
      align-items: flex-end;
    }
    .input-group input,
    .input-group textarea {
      flex: 1;
      padding: 8px 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg-primary);
      color: var(--text-primary);
      font-size: 12px;
      outline: none;
    }
    .input-group textarea {
      min-height: 40px;
      max-height: 160px;
      resize: vertical;
      font-family: inherit;
      line-height: 1.45;
    }
    .input-group input:focus,
    .input-group textarea:focus { border-color: var(--accent); }
    .input-group input::placeholder,
    .input-group textarea::placeholder { color: var(--text-muted); }

    .feedback {
      margin-top: 8px;
      padding: 8px 10px;
      border-radius: 6px;
      font-size: 11px;
      display: none;
      animation: fadeIn 0.3s;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .feedback.show { display: block; }
    .feedback.success { background: rgba(166,227,161,0.15); color: var(--success); border: 1px solid rgba(166,227,161,0.3); }
    .feedback.error { background: rgba(243,139,168,0.15); color: var(--error); border: 1px solid rgba(243,139,168,0.3); }
    .feedback.info { background: rgba(137,180,250,0.15); color: var(--accent); border: 1px solid rgba(137,180,250,0.3); }
    .feedback.pending { background: rgba(249,226,175,0.15); color: var(--warning); border: 1px solid rgba(249,226,175,0.3); }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }

    .chat-container {
      max-height: 280px;
      overflow-y: auto;
      background: var(--bg-primary);
      border-radius: 6px;
      padding: 8px;
      border: 1px solid var(--border);
    }
    .chat-container::-webkit-scrollbar { width: 5px; }
    .chat-container::-webkit-scrollbar-track { background: var(--bg-secondary); }
    .chat-container::-webkit-scrollbar-thumb { background: var(--bg-tertiary); border-radius: 3px; }

    .message {
      padding: 8px 10px;
      border-radius: 8px;
      margin-bottom: 8px;
      animation: slideIn 0.3s;
    }
    .message:last-child { margin-bottom: 0; }
    @keyframes slideIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
    .message.user { background: var(--bg-tertiary); margin-left: 16px; }
    .message.cursor { background: rgba(137,180,250,0.1); border: 1px solid rgba(137,180,250,0.2); margin-right: 16px; }
    .message.system { background: rgba(249,226,175,0.1); border: 1px solid rgba(249,226,175,0.2); font-size: 11px; color: var(--text-secondary); }
    .message-header { display: flex; justify-content: space-between; margin-bottom: 4px; }
    .message-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
    .message.user .message-label { color: var(--text-muted); }
    .message.cursor .message-label { color: var(--accent); }
    .message-time { font-size: 10px; color: var(--text-muted); }
    .message-content { color: var(--text-primary); white-space: pre-wrap; word-break: break-word; font-size: 12px; }

    .empty-state { text-align: center; padding: 20px; color: var(--text-muted); }
    .empty-state svg { width: 40px; height: 40px; margin-bottom: 8px; opacity: 0.5; }
    .hint { font-size: 10px; color: var(--text-muted); margin-top: 6px; }

    .loading-spinner {
      display: inline-block;
      width: 12px; height: 12px;
      border: 2px solid var(--bg-tertiary);
      border-top-color: var(--accent);
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    .current-path {
      font-size: 10px;
      color: var(--text-muted);
      margin-top: 4px;
      padding: 4px 8px;
      background: var(--bg-primary);
      border-radius: 4px;
      font-family: 'Consolas', 'Monaco', monospace;
      word-break: break-all;
    }
    .current-path.set { color: var(--success); }

    .section-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 8px;
    }
    .section-head .section-title { margin-bottom: 0; }

    .attach-row {
      display: flex;
      flex-wrap: wrap;
      align-items: flex-start;
      gap: 8px;
      margin-top: 8px;
    }
    .attach-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
      flex: 1;
      min-width: 0;
    }
    .attach-chip {
      font-size: 10px;
      padding: 3px 6px 3px 8px;
      background: var(--bg-tertiary);
      border-radius: 4px;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      max-width: 100%;
    }
    .attach-chip span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 140px; }
    .attach-chip .rm {
      border: none;
      background: none;
      color: var(--text-muted);
      cursor: pointer;
      padding: 0 4px;
      font-size: 12px;
      line-height: 1;
    }
    .attach-chip .rm:hover { color: var(--error); }
    #filePick { display: none; }

    #messagesList { min-height: 0; }

    .hint-row { margin-top: 6px; }
    .hint-copy-line {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      flex-wrap: wrap;
    }
    .hint-code {
      flex: 1;
      min-width: 0;
      font-size: 11px;
      font-family: ui-monospace, Consolas, monospace;
      background: var(--bg-primary);
      color: var(--accent);
      padding: 8px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      word-break: break-all;
      line-height: 1.4;
    }
    .copy-hint-btn { flex-shrink: 0; }
    .btn-test-hello {
      border: 1px dashed rgba(137, 180, 250, 0.45);
      background: rgba(137, 180, 250, 0.08);
      color: var(--accent);
      font-size: 11px;
      font-weight: 600;
    }
    .btn-test-hello:hover:not(:disabled) {
      background: rgba(137, 180, 250, 0.18);
      border-style: solid;
    }
    .send-extra-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin-top: 8px;
    }
    .btn-help-open {
      width: 100%;
      margin-top: 4px;
      padding: 8px 12px;
      border-radius: 8px;
      border: 1px solid rgba(137, 180, 250, 0.35);
      background: rgba(137, 180, 250, 0.06);
      color: var(--accent);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .btn-help-open:hover {
      background: rgba(137, 180, 250, 0.14);
      border-color: var(--accent);
    }
    .btn-help-header {
      flex-shrink: 0;
      padding: 4px 10px;
      font-size: 10px;
      font-weight: 600;
      border: 1px solid rgba(137, 180, 250, 0.4);
      border-radius: 6px;
      background: rgba(137, 180, 250, 0.08);
      color: var(--accent);
      cursor: pointer;
    }
    .btn-help-header:hover {
      background: rgba(137, 180, 250, 0.16);
    }
    .help-overlay {
      display: none;
      position: fixed;
      inset: 0;
      z-index: 100000;
      align-items: center;
      justify-content: center;
      padding: 10px;
      box-sizing: border-box;
    }
    .help-overlay.visible {
      display: flex;
    }
    .help-overlay-backdrop {
      position: absolute;
      inset: 0;
      background: rgba(0, 0, 0, 0.55);
    }
    .help-panel {
      position: relative;
      z-index: 1;
      width: min(440px, 100%);
      max-height: min(88vh, 640px);
      display: flex;
      flex-direction: column;
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: 12px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      overflow: hidden;
    }
    .help-panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }
    .help-panel-header h3 {
      margin: 0;
      font-size: 14px;
      font-weight: 700;
      color: var(--text-primary);
    }
    .btn-close-help {
      flex-shrink: 0;
      padding: 5px 12px;
      font-size: 11px;
      font-weight: 600;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--bg-tertiary);
      color: var(--text-primary);
      cursor: pointer;
    }
    .btn-close-help:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .help-panel-body {
      padding: 12px 14px 16px;
      overflow-y: auto;
      font-size: 12px;
      line-height: 1.55;
      color: var(--text-secondary);
    }
    .help-panel-body .help-h {
      font-size: 12px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 14px 0 6px;
    }
    .help-panel-body .help-h:first-of-type { margin-top: 0; }
    .help-panel-body p { margin: 6px 0; }
    .help-panel-body ul {
      margin: 6px 0 8px;
      padding-left: 18px;
    }
    .help-panel-body li { margin: 4px 0; }
    .help-panel-body code {
      font-family: ui-monospace, Consolas, monospace;
      font-size: 11px;
      background: var(--bg-primary);
      padding: 1px 5px;
      border-radius: 4px;
      color: var(--accent);
    }
  </style>
</head>
<body>
  <div id="licenseGate" class="license-gate">
    <div class="license-gate-head">
      <div class="license-logo">悟空mcp</div>
      <span class="header-version" title="扩展版本">v${extensionVersion}</span>
    </div>
    <p class="license-desc"><strong>多项目、多窗口</strong>一起用：侧栏多路 MCP，各绑独立通道，<strong>稳定不断连</strong>。支持<strong>免费试用 30 分钟</strong>（每机一次），<strong>好用再下单</strong>。下方粘贴卡密激活即可。</p>
    <div class="license-pay-strip">
      <div class="license-pay-title">悟空 MCP 激活码 · 在线购买</div>
      <div class="license-pay-url" id="payStoreUrlDisplay">${payUrlDisplay}</div>
      <button type="button" class="btn-pay-store" id="openPayStoreBtn" title="在系统浏览器中打开支付页">在浏览器打开支付页</button>
    </div>
    <input type="text" class="license-key-input" id="licenseKeyInput" placeholder="粘贴卡密…" autocomplete="off" spellcheck="false" />
    <div class="license-actions">
      <button type="button" class="btn btn-primary" id="licenseActivateBtn">激活</button>
      <button type="button" class="btn-trial" id="trial30Btn" title="每机仅一次，30 分钟后需卡密或再次安装">试用30分钟</button>
    </div>
    <button type="button" class="btn-help-open" id="openHelpGateBtn">使用说明</button>
    <div class="feedback" id="licenseFeedback"></div>
    <p class="license-foot">试用与正式激活均可使用侧栏全部功能；到期后将返回本页。</p>
    <div class="contact-strip contact-strip--gate">
      <div class="contact-strip-title">购买卡密 · 交流群 · 技术支持</div>
      <div class="contact-strip-line">QQ 群：<span class="contact-num">1091740923</span></div>
      <div class="contact-strip-line">QQ：<span class="contact-num">3821703362</span></div>
      <div class="contact-strip-line">QQ：<span class="contact-num">1919066559</span></div>
      <div class="contact-strip-line">微信：<span class="contact-num">17519157525</span></div>
      <div class="contact-strip-note">加群交流、购买卡密与技术支持</div>
    </div>
  </div>
  <div class="app-layout" id="mainApp">
  <aside class="session-rail" id="sessionRail" aria-label="会话列表" style="width:88px">
    <div class="session-rail-title">会话</div>
    <div id="sessionRailInner"></div>
    <button type="button" class="btn-add-session" id="addSessionBtn" title="添加一路会话（对应 my-mcp-N）">+ 添加会话</button>
    <div class="session-rail-hint">每路对应 my-mcp-N。点「开始配置」只注册当前这几路；增删会话后请再配置一次</div>
  </aside>
  <div class="rail-resizer" id="railResizer" title="拖动调整会话栏宽度" role="separator" aria-orientation="vertical"></div>
  <div class="app-main">
  <div class="header">
    <h2>悟空mcp</h2>
    <span class="header-version" id="extVersionBadge" title="扩展版本">v${extensionVersion}</span>
    <div class="status-dot" id="statusDot" title="连接状态"></div>
    <span id="activeMcpHint" class="hint" style="margin-left:auto;font-size:10px;">当前：MCP-1</span>
    <button type="button" class="btn-help-header" id="openHelpMainBtn" title="查看详细使用说明">使用说明</button>
  </div>

  <div class="section">
    <div class="section-title">工作区配置</div>
    <div class="path-input-group">
      <input type="text" class="path-input" id="pathInput" placeholder="选择或输入工作区路径..." />
      <button class="btn btn-small" id="browseBtn" title="浏览文件夹">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
        </svg>
      </button>
    </div>
    <div class="btn-row">
      <button class="btn btn-primary" id="cfgBtn">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
        开始配置
      </button>
      <button class="btn btn-small" id="useCurrentBtn" title="使用当前工作区">
        使用当前
      </button>
    </div>
    <div class="hint">选择工作区后点「开始配置」：仅把<strong>当前侧栏会话</strong>写入 mcp.json（不会一次注册 32 个）</div>
    <div class="feedback" id="cfgFeedback"></div>
  </div>

  <div class="session-memo-strip session-tone-0" id="sessionMemoStrip">
    <div class="session-memo-strip-head">
      <span class="session-memo-badge" id="sessionMemoBadge">MCP-1</span>
      <span class="session-memo-hint">本路备忘（仅本机保存）</span>
    </div>
    <input type="text" class="session-memo-input" id="sessionMemoInput" placeholder="用途说明，例如：前端仓库 / 写文档 / 测试通道" maxlength="200" />
  </div>

  <div class="section send-message-section session-tone-0" id="sendMessageSection">
    <div class="section-title"><span class="send-section-color-dot" aria-hidden="true"></span>发送消息</div>
    <div class="input-group">
      <textarea id="msgInput" rows="2" placeholder="输入消息… 可直接 Ctrl+V 粘贴截图/图片，或与下方「图片/文件」一起发送"></textarea>
      <div class="input-actions">
        <button type="button" class="btn-voice" id="voiceInputBtn" title="语音输入" aria-pressed="false">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/>
            <path d="M19 10v2a7 7 0 0 1-14 0v-2M12 19v4M8 23h8"/>
          </svg>
          语音
        </button>
        <button class="btn btn-primary" id="sendBtn">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>
          </svg>
          发送
        </button>
      </div>
    </div>
    <div class="send-extra-actions">
      <button type="button" class="btn btn-small btn-test-hello" id="testHelloBtn" title="向当前通道发送一条「你好」测试消息">测试发送你好</button>
    </div>
    <div class="attach-row">
      <button class="btn btn-small" type="button" id="pickFilesBtn" title="选择图片或任意文件">图片/文件</button>
      <input type="file" id="filePick" multiple accept="image/*,*/*" />
      <div class="attach-chips" id="attachChips"></div>
    </div>
    <div class="hint-row">
      <div class="hint">发送后，在<strong>绑定本通道</strong>的 Cursor 对话里发送下方指令（可点「复制」）。单条约 2MB 附件上限。</div>
      <div class="hint-copy-line">
        <code class="hint-code" id="hintPhrase">请使用 my-mcp-1 的 check_messages</code>
        <button type="button" class="btn btn-small copy-hint-btn" id="copyHintBtn" title="复制到剪贴板">复制</button>
      </div>
    </div>
    <div class="feedback" id="sendFeedback"></div>
  </div>

  <div class="section">
    <div class="section-head">
      <div class="section-title">对话记录</div>
      <button class="btn btn-small" type="button" id="clearChatBtn" title="清空本面板中的记录">清空记录</button>
    </div>
    <div class="chat-container" id="chatContainer">
      <div id="messagesList"></div>
      <div class="empty-state" id="emptyState">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
        </svg>
        <div>暂无消息</div>
        <div style="font-size: 10px; margin-top: 4px;">发送消息开始对话</div>
      </div>
    </div>
  </div>
  <div class="contact-strip contact-strip--main">
    <div class="contact-strip-title">购买卡密 · 交流群 · 技术支持</div>
    <div class="contact-strip-line">QQ 群：<span class="contact-num">1091740923</span></div>
    <div class="contact-strip-line">QQ：<span class="contact-num">3821703362</span></div>
    <div class="contact-strip-line">QQ：<span class="contact-num">1919066559</span></div>
    <div class="contact-strip-line">微信：<span class="contact-num">17519157525</span></div>
    <div class="contact-strip-note">加群交流、购买卡密与技术支持</div>
  </div>
  </div>
  </div>

  <div id="helpOverlay" class="help-overlay" aria-hidden="true" role="presentation">
    <div class="help-overlay-backdrop" id="helpBackdrop" aria-hidden="true"></div>
    <div class="help-panel" role="dialog" aria-modal="true" aria-labelledby="helpTitle">
      <div class="help-panel-header">
        <h3 id="helpTitle">悟空mcp 使用说明</h3>
        <button type="button" class="btn-close-help" id="closeHelpBtn">关闭</button>
      </div>
      <div class="help-panel-body">
        <div class="help-h">1. 激活与试用</div>
        <p>在侧栏输入<strong>卡密</strong>后点「激活」；未购买可先点「试用 30 分钟」（每机一次）。激活或试用期间可使用侧栏全部功能，到期后会回到本页。</p>
        <div class="help-h">2. 工作区与 MCP 配置</div>
        <p>在「工作区配置」中填写或浏览项目路径，也可点「使用当前」自动填入当前 Cursor 打开的工作区根目录。点<strong>开始配置</strong>后，扩展会把<strong>当前侧栏会话列表</strong>写入本工作区的 <code>.cursor/mcp.json</code>，对应通道为 <code>my-mcp-1</code> … <code>my-mcp-N</code>。</p>
        <p><strong>注意：</strong>在侧栏<strong>添加或删除会话</strong>后，需要再点一次「开始配置」，否则 Cursor 里 MCP 列表与侧栏不一致。</p>
        <div class="help-h">3. 多路会话</div>
        <p>左侧「会话」可切换 MCP-1、MCP-2… 每路独立；拖动会话栏右侧竖条可调整宽度。每路可写<strong>本路备忘</strong>（仅本机保存）。</p>
        <div class="help-h">4. 发送消息</div>
        <p>在「发送消息」中输入文字，可粘贴截图或添加图片/文件。发送成功后，请在<strong>绑定该通道</strong>的 Cursor 对话窗口里，让 AI 执行侧栏提示的指令（例如 <code>请使用 my-mcp-1 的 check_messages</code>），以便拉取插件消息。</p>
        <p>可点「测试发送你好」快速发送一条「你好」做通道测试。</p>
        <div class="help-h">5. 设置（可选）</div>
        <p>在 Cursor 设置中搜索「悟空」可配置：云端核销地址 <code>wukong.redeemApiBaseUrl</code>、仅云端卡密 <code>wukong.cloudLicenseOnly</code>（默认关闭，可同时用本地 WKM1）、吊销校验间隔 <code>wukong.cloudLicenseVerifyIntervalMs</code> 等。</p>
        <div class="help-h">6. 常见问题</div>
        <ul>
          <li>MCP 连不上：确认已「开始配置」且对话里已按提示调用 <code>check_messages</code>。</li>
          <li>换电脑或重装：需重新激活（卡密按你的发卡规则可能一机一码）。</li>
        </ul>
      </div>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscodeApi = acquireVsCodeApi();
    var VOICE_USE_WIN_NATIVE = ${process.platform === "win32" ? "true" : "false"};

    function showLicenseFeedback(type, text) {
      var el = document.getElementById('licenseFeedback');
      if (!el) return;
      el.className = 'feedback show ' + type;
      el.textContent = text || '';
      if (type === 'success' || type === 'info') {
        setTimeout(function () { el.classList.remove('show'); }, 6000);
      }
    }
    function applyLicenseShell(ok, label) {
      document.body.classList.add('license-ok');
    }
    (function setupLicenseUi() {
      var licenseKeyInput = document.getElementById('licenseKeyInput');
      var licenseActivateBtn = document.getElementById('licenseActivateBtn');
      function doActivate() {
        if (!licenseKeyInput) return;
        showLicenseFeedback('pending', '正在校验…');
        vscodeApi.postMessage({ command: 'activateLicense', key: licenseKeyInput.value });
      }
      if (licenseActivateBtn) licenseActivateBtn.addEventListener('click', doActivate);
      var trial30Btn = document.getElementById('trial30Btn');
      if (trial30Btn) {
        trial30Btn.addEventListener('click', function () {
          showLicenseFeedback('pending', '正在开始试用…');
          vscodeApi.postMessage({ command: 'startTrial30' });
        });
      }
      if (licenseKeyInput) {
        licenseKeyInput.addEventListener('keydown', function (e) {
          if (e.key === 'Enter') { e.preventDefault(); doActivate(); }
        });
      }
      var openPayStoreBtn = document.getElementById('openPayStoreBtn');
      if (openPayStoreBtn) {
        openPayStoreBtn.addEventListener('click', function () {
          vscodeApi.postMessage({ command: 'openPayStore' });
        });
      }
    })();
    (function setupDeactivateLicense() {
      var btn = document.getElementById('deactivateLicenseBtn');
      if (!btn) return;
      btn.addEventListener('click', function () {
        vscodeApi.postMessage({ command: 'deactivateLicense' });
      });
    })();
    (function setupHelpOverlay() {
      var overlay = document.getElementById('helpOverlay');
      var closeBtn = document.getElementById('closeHelpBtn');
      var backdrop = document.getElementById('helpBackdrop');
      var openGate = document.getElementById('openHelpGateBtn');
      var openMain = document.getElementById('openHelpMainBtn');
      function open() {
        if (!overlay) return;
        overlay.classList.add('visible');
        overlay.setAttribute('aria-hidden', 'false');
      }
      function close() {
        if (!overlay) return;
        overlay.classList.remove('visible');
        overlay.setAttribute('aria-hidden', 'true');
      }
      if (openGate) openGate.addEventListener('click', open);
      if (openMain) openMain.addEventListener('click', open);
      if (closeBtn) closeBtn.addEventListener('click', close);
      if (backdrop) backdrop.addEventListener('click', close);
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && overlay && overlay.classList.contains('visible')) {
          close();
        }
      });
    })();
    applyLicenseShell(true, '');

    const statusDot = document.getElementById('statusDot');
    const pathInput = document.getElementById('pathInput');
    const browseBtn = document.getElementById('browseBtn');
    const cfgBtn = document.getElementById('cfgBtn');
    const useCurrentBtn = document.getElementById('useCurrentBtn');
    const cfgFeedback = document.getElementById('cfgFeedback');
    const msgInput = document.getElementById('msgInput');
    const voiceInputBtn = document.getElementById('voiceInputBtn');
    const sendBtn = document.getElementById('sendBtn');
    const testHelloBtn = document.getElementById('testHelloBtn');
    const sendFeedback = document.getElementById('sendFeedback');
    const chatContainer = document.getElementById('chatContainer');
    const messagesList = document.getElementById('messagesList');
    const emptyState = document.getElementById('emptyState');
    const pickFilesBtn = document.getElementById('pickFilesBtn');
    const filePick = document.getElementById('filePick');
    const attachChips = document.getElementById('attachChips');
    const clearChatBtn = document.getElementById('clearChatBtn');
    const sessionRail = document.getElementById('sessionRail');
    const railResizer = document.getElementById('railResizer');
    const sessionRailInner = document.getElementById('sessionRailInner');
    const addSessionBtn = document.getElementById('addSessionBtn');
    const activeMcpHint = document.getElementById('activeMcpHint');
    const hintPhrase = document.getElementById('hintPhrase');
    const copyHintBtn = document.getElementById('copyHintBtn');
    const sendMessageSection = document.getElementById('sendMessageSection');
    const sessionMemoStrip = document.getElementById('sessionMemoStrip');
    const sessionMemoBadge = document.getElementById('sessionMemoBadge');
    const sessionMemoInput = document.getElementById('sessionMemoInput');

    var MAX_SESSIONS = ${MAX_WUKONG_SESSIONS};
    /** @type string[] */
    var sessionOrder = ['1', '2', '3'];
    var activeSessionId = '1';
    /** @type Record<string, Array<{type:string,content:string,time:string|Date}>> */
    var messagesBySession = {};
    /** @type Record<string, Array<{id:number,name:string,mimeType:string,data:string,kind:string}>> */
    var pendingBySession = {};
    var persistTimer = null;
    var sessionOrderTimer = null;
    var memoTimer = null;
    /** @type Record<string, string> */
    var sessionMemos = {};

    let currentWorkspacePath = '';

    function sessionToneClass(sid) {
      var n = parseInt(sid, 10);
      if (!n || n < 1) n = 1;
      return 'session-tone-' + ((n - 1) % 12);
    }

    function persistMemoSoon() {
      if (memoTimer) clearTimeout(memoTimer);
      memoTimer = setTimeout(function () {
        memoTimer = null;
        vscodeApi.postMessage({ command: 'persistSessionMemos', memos: sessionMemos });
      }, 300);
    }

    function ensureSessionStructures(sid) {
      if (!messagesBySession[sid]) messagesBySession[sid] = [];
      if (!pendingBySession[sid]) pendingBySession[sid] = [];
    }

    function getPending() {
      ensureSessionStructures(activeSessionId);
      return pendingBySession[activeSessionId];
    }

    function setSessionUi() {
      var tone = sessionToneClass(activeSessionId);
      sessionRailInner.querySelectorAll('.session-item').forEach(function (el) {
        el.classList.toggle('active', el.getAttribute('data-sid') === activeSessionId);
      });
      if (sendMessageSection) sendMessageSection.className = 'section send-message-section ' + tone;
      if (sessionMemoStrip) sessionMemoStrip.className = 'session-memo-strip ' + tone;
      if (sessionMemoBadge) sessionMemoBadge.textContent = 'MCP-' + activeSessionId;
      if (sessionMemoInput) sessionMemoInput.value = sessionMemos[activeSessionId] || '';
      if (activeMcpHint) activeMcpHint.textContent = '当前：MCP-' + activeSessionId;
      if (hintPhrase) hintPhrase.textContent = '请使用 my-mcp-' + activeSessionId + ' 的 check_messages';
    }

    function persistSessionOrderSoon() {
      if (sessionOrderTimer) clearTimeout(sessionOrderTimer);
      sessionOrderTimer = setTimeout(function () {
        sessionOrderTimer = null;
        vscodeApi.postMessage({ command: 'persistSessionOrder', order: sessionOrder.slice() });
      }, 200);
    }

    function renderSessionRail() {
      if (!sessionRailInner || !addSessionBtn) return;
      sessionOrder.forEach(function (sid) { ensureSessionStructures(sid); });
      sessionRailInner.innerHTML = sessionOrder.map(function (sid) {
        var tc = sessionToneClass(sid);
        return '<div class="session-row">' +
          '<button type="button" class="session-item ' + tc + (sid === activeSessionId ? ' active' : '') + '" data-sid="' + sid + '">MCP-' + sid + '</button>' +
          '<button type="button" class="session-del" data-del-sid="' + sid + '" title="删除此会话">×</button>' +
          '</div>';
      }).join('');
      sessionRailInner.querySelectorAll('.session-item').forEach(function (btn) {
        btn.addEventListener('click', function () {
          switchSession(btn.getAttribute('data-sid'));
        });
      });
      sessionRailInner.querySelectorAll('.session-del').forEach(function (btn) {
        btn.addEventListener('click', function (e) {
          e.stopPropagation();
          deleteSession(btn.getAttribute('data-del-sid'));
        });
      });
      addSessionBtn.disabled = sessionOrder.length >= MAX_SESSIONS;
      setSessionUi();
    }

    function switchSession(sid) {
      if (sessionOrder.indexOf(sid) < 0) return;
      activeSessionId = sid;
      setSessionUi();
      renderAttachChips();
      renderMessages();
    }

    function addSession() {
      if (sessionOrder.length >= MAX_SESSIONS) return;
      var used = {};
      sessionOrder.forEach(function (s) { used[s] = true; });
      var next = null;
      for (var n = 1; n <= MAX_SESSIONS; n++) {
        var id = String(n);
        if (!used[id]) { next = id; break; }
      }
      if (!next) return;
      ensureSessionStructures(next);
      sessionOrder.push(next);
      activeSessionId = next;
      persistSessionOrderSoon();
      renderSessionRail();
      renderAttachChips();
      renderMessages();
      schedulePersist();
      hintReconfigureAfterSessionChange();
    }

    function deleteSession(sid) {
      if (!sid || sessionOrder.length <= 1) {
        showFeedback(sendFeedback, 'error', '至少保留一个会话');
        return;
      }
      var idx = sessionOrder.indexOf(sid);
      if (idx < 0) return;
      sessionOrder.splice(idx, 1);
      delete messagesBySession[sid];
      delete pendingBySession[sid];
      delete sessionMemos[sid];
      persistMemoSoon();
      if (activeSessionId === sid) {
        activeSessionId = sessionOrder[0];
      }
      persistSessionOrderSoon();
      renderSessionRail();
      renderAttachChips();
      renderMessages();
      schedulePersist();
      hintReconfigureAfterSessionChange();
    }

    addSessionBtn.addEventListener('click', function () { addSession(); });

    if (sessionMemoInput) {
      sessionMemoInput.addEventListener('input', function () {
        var v = sessionMemoInput.value.slice(0, 200);
        sessionMemoInput.value = v;
        sessionMemos[activeSessionId] = v;
        if (!v) delete sessionMemos[activeSessionId];
        persistMemoSoon();
      });
    }

    ['1', '2', '3'].forEach(function (s) { ensureSessionStructures(s); });
    renderSessionRail();

    copyHintBtn.addEventListener('click', function () {
      vscodeApi.postMessage({ command: 'copyCheckPhrase', sessionId: activeSessionId });
    });

    function schedulePersist() {
      if (persistTimer) clearTimeout(persistTimer);
      persistTimer = setTimeout(function () {
        persistTimer = null;
        var out = {};
        Object.keys(messagesBySession).forEach(function (sid) {
          out[sid] = (messagesBySession[sid] || []).map(function (m) {
            return { type: m.type, content: m.content, time: m.time instanceof Date ? m.time.toISOString() : m.time };
          });
        });
        vscodeApi.postMessage({ command: 'persistHistories', payload: JSON.stringify(out) });
      }, 400);
    }

    function showFeedback(el, type, text) {
      el.className = 'feedback show ' + type;
      el.textContent = text;
      if (type === 'success' || type === 'info') {
        setTimeout(() => el.classList.remove('show'), 8000);
      }
    }

    function formatTime(date) {
      const d = date instanceof Date ? date : new Date(date);
      return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    function addMessage(type, content, time, sessionId) {
      var sid = sessionId || activeSessionId;
      if (!messagesBySession[sid]) messagesBySession[sid] = [];
      messagesBySession[sid].push({ type: type, content: content, time: time || new Date() });
      if (sid === activeSessionId) renderMessages();
      schedulePersist();
    }

    function renderAttachChips() {
      var pendingAttachments = getPending();
      attachChips.innerHTML = pendingAttachments.map(function (a) {
        return '<span class="attach-chip"><span title="' + escapeHtml(a.name) + '">' + escapeHtml(a.name) + '</span>' +
          '<button type="button" class="rm" data-rm="' + a.id + '" title="移除">×</button></span>';
      }).join('');
    }

    attachChips.addEventListener('click', function (e) {
      const t = e.target;
      if (!t || !t.getAttribute) return;
      const id = t.getAttribute('data-rm');
      if (id == null) return;
      var pa = getPending();
      var idx = pa.findIndex(function (x) { return String(x.id) === String(id); });
      if (idx >= 0) pa.splice(idx, 1);
      renderAttachChips();
    });

    pickFilesBtn.addEventListener('click', function () { filePick.click(); });

    filePick.addEventListener('change', function () {
      const files = Array.prototype.slice.call(filePick.files || []);
      filePick.value = '';
      files.forEach(function (file) {
        const reader = new FileReader();
        reader.onload = function () {
          const result = reader.result;
          if (typeof result !== 'string') return;
          const comma = result.indexOf(',');
          const data = comma >= 0 ? result.slice(comma + 1) : result;
          const mimeType = file.type || 'application/octet-stream';
          const kind = mimeType.indexOf('image/') === 0 ? 'image' : 'file';
          getPending().push({
            id: Date.now() + Math.random(),
            name: file.name || (kind === 'image' ? 'image' : 'file'),
            mimeType: mimeType,
            data: data,
            kind: kind
          });
          renderAttachChips();
        };
        reader.readAsDataURL(file);
      });
    });

    clearChatBtn.addEventListener('click', function () {
      messagesBySession[activeSessionId] = [];
      renderMessages();
      schedulePersist();
    });

    function renderMessages() {
      var messages = messagesBySession[activeSessionId] || [];
      if (messages.length === 0) {
        messagesList.innerHTML = '';
        emptyState.style.display = 'block';
        return;
      }
      emptyState.style.display = 'none';
      messagesList.innerHTML = messages.map(function (m) {
        const label = m.type === 'user' ? '你' : m.type === 'cursor' ? 'Cursor' : '系统';
        return '<div class="message ' + m.type + '">' +
          '<div class="message-header">' +
            '<span class="message-label">' + label + '</span>' +
            '<span class="message-time">' + formatTime(m.time) + '</span>' +
          '</div>' +
          '<div class="message-content">' + escapeHtml(m.content) + '</div>' +
        '</div>';
      }).join('');
      chatContainer.scrollTop = chatContainer.scrollHeight;
    }

    function setLoading(btn, loading) {
      if (loading) {
        btn.disabled = true;
        btn.dataset.originalHtml = btn.innerHTML;
        btn.innerHTML = '<span class="loading-spinner"></span> 处理中...';
      } else {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalHtml || btn.innerHTML;
      }
    }

    // 浏览文件夹
    browseBtn.addEventListener('click', () => {
      vscodeApi.postMessage({ command: 'selectFolder' });
    });

    // 使用当前工作区：向扩展查询当前窗口工作区路径并填入输入框
    useCurrentBtn.addEventListener('click', () => {
      vscodeApi.postMessage({ command: 'requestCurrentWorkspace' });
    });

    function hintReconfigureAfterSessionChange() {
      showFeedback(cfgFeedback, 'info', '会话路数已变：请再点「开始配置」，才会按当前侧栏同步 .cursor/mcp.json（并清理多余的 my-mcp-*）。');
    }

    // 开始配置
    cfgBtn.addEventListener('click', () => {
      setLoading(cfgBtn, true);
      const targetPath = pathInput.value.trim() || undefined;
      showFeedback(cfgFeedback, 'pending', '正在配置工作区...' + (targetPath ? '\\n路径：' + targetPath : '（使用当前工作区）'));
      statusDot.className = 'status-dot pending';
      vscodeApi.postMessage({ command: 'configureWorkspace', path: targetPath, sessionOrder: sessionOrder.slice() });
    });

    sendBtn.addEventListener('click', sendMessage);
    function sendTestHello() {
      if (voiceNativePending) {
        showFeedback(sendFeedback, 'error', '请等待语音识别结束');
        return;
      }
      stopVoiceInput();
      var workspacePath = currentWorkspacePath || pathInput.value.trim();
      if (testHelloBtn) setLoading(testHelloBtn, true);
      showFeedback(sendFeedback, 'pending', '正在发送...');
      vscodeApi.postMessage({
        command: 'sendMessage',
        text: '你好',
        workspacePath: workspacePath,
        images: [],
        files: [],
        sessionId: activeSessionId
      });
    }
    if (testHelloBtn) testHelloBtn.addEventListener('click', sendTestHello);
    (function setupRailResize() {
      if (!railResizer || !sessionRail) return;
      var RAIL_MIN = 56;
      var RAIL_MAX = 220;
      try {
        var s = localStorage.getItem('wukong.sessionRailWidthPx');
        if (s) {
          var w = parseInt(s, 10);
          if (!isNaN(w) && w >= RAIL_MIN && w <= RAIL_MAX) {
            sessionRail.style.width = w + 'px';
          }
        }
      } catch (e) { /* ignore */ }
      railResizer.addEventListener('mousedown', function (e) {
        e.preventDefault();
        railResizer.classList.add('is-dragging');
        var startX = e.clientX;
        var startW = sessionRail.getBoundingClientRect().width;
        function onMove(e2) {
          var dx = e2.clientX - startX;
          var nw = Math.round(startW + dx);
          nw = Math.max(RAIL_MIN, Math.min(RAIL_MAX, nw));
          sessionRail.style.width = nw + 'px';
        }
        function onUp() {
          railResizer.classList.remove('is-dragging');
          document.removeEventListener('mousemove', onMove);
          document.removeEventListener('mouseup', onUp);
          try {
            localStorage.setItem(
              'wukong.sessionRailWidthPx',
              String(Math.round(sessionRail.getBoundingClientRect().width))
            );
          } catch (err) { /* ignore */ }
        }
        document.addEventListener('mousemove', onMove);
        document.addEventListener('mouseup', onUp);
      });
    })();
    msgInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });

    /** @type {SpeechRecognition | null} */
    var activeSpeechRec = null;
    var voiceBaseText = '';
    var voiceAccumulated = '';
    var voiceNativePending = false;

    function setVoiceNativeBusy(busy) {
      voiceNativePending = busy;
      if (!voiceInputBtn) return;
      if (busy) {
        voiceInputBtn.classList.add('listening');
        voiceInputBtn.setAttribute('aria-pressed', 'true');
        voiceInputBtn.disabled = true;
      } else {
        voiceInputBtn.classList.remove('listening');
        voiceInputBtn.setAttribute('aria-pressed', 'false');
        voiceInputBtn.disabled = false;
      }
    }

    function stopVoiceInput() {
      if (activeSpeechRec) {
        try {
          activeSpeechRec.stop();
        } catch (e) { /* ignore */ }
        activeSpeechRec = null;
      }
      if (voiceInputBtn) {
        voiceInputBtn.classList.remove('listening');
        voiceInputBtn.setAttribute('aria-pressed', 'false');
      }
    }

    function initVoiceInput() {
      if (!voiceInputBtn || !msgInput) return;
      if (VOICE_USE_WIN_NATIVE) {
        voiceInputBtn.title = '语音输入（Windows 系统识别：说完一句后自动结束，最长约 50 秒）';
        voiceInputBtn.addEventListener('click', function () {
          if (voiceNativePending) return;
          setVoiceNativeBusy(true);
          showFeedback(sendFeedback, 'pending', '正在听写… 请对着麦克风清晰说一句话');
          vscodeApi.postMessage({ command: 'voiceInputNative' });
        });
        return;
      }
      var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
      if (!SR) {
        voiceInputBtn.disabled = true;
        voiceInputBtn.title = '当前环境不支持浏览器语音识别';
        return;
      }
      voiceInputBtn.title = '语音输入（浏览器识别；再点一次结束）';

      voiceInputBtn.addEventListener('click', function () {
        if (activeSpeechRec) {
          stopVoiceInput();
          return;
        }
        var Rec = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (!Rec) {
          showFeedback(sendFeedback, 'error', '当前环境不支持语音输入');
          return;
        }
        var rec = new Rec();
        rec.lang = 'zh-CN';
        rec.continuous = true;
        rec.interimResults = true;
        voiceBaseText = msgInput.value;
        voiceAccumulated = '';

        rec.onstart = function () {
          voiceInputBtn.classList.add('listening');
          voiceInputBtn.setAttribute('aria-pressed', 'true');
          showFeedback(sendFeedback, 'info', '正在聆听… 再点「语音」结束');
        };

        rec.onresult = function (event) {
          var interim = '';
          for (var i = event.resultIndex; i < event.results.length; i++) {
            var r = event.results[i];
            var t = r[0] ? r[0].transcript : '';
            if (r.isFinal) {
              voiceAccumulated += t;
            } else {
              interim += t;
            }
          }
          msgInput.value = voiceBaseText + voiceAccumulated + interim;
        };

        rec.onerror = function (ev) {
          var err = ev.error || '';
          if (err === 'not-allowed') {
            showFeedback(sendFeedback, 'error', '侧栏页面无法使用麦克风（编辑器限制）。若在 macOS/Linux 可尝试系统听写；Windows 本扩展已改用系统识别。');
          } else if (err !== 'aborted' && err !== 'no-speech') {
            showFeedback(sendFeedback, 'error', '语音识别：' + err);
          }
          stopVoiceInput();
        };

        rec.onend = function () {
          activeSpeechRec = null;
          if (voiceInputBtn) {
            voiceInputBtn.classList.remove('listening');
            voiceInputBtn.setAttribute('aria-pressed', 'false');
          }
        };

        try {
          activeSpeechRec = rec;
          rec.start();
        } catch (e) {
          activeSpeechRec = null;
          showFeedback(sendFeedback, 'error', '无法启动语音识别：' + String(e));
        }
      });
    }
    initVoiceInput();

    function pushImageFromBlob(blob, nameHint) {
      var reader = new FileReader();
      reader.onload = function () {
        var result = reader.result;
        if (typeof result !== 'string') return;
        var comma = result.indexOf(',');
        var data = comma >= 0 ? result.slice(comma + 1) : result;
        var mimeType = blob.type || 'image/png';
        var ext = 'png';
        if (mimeType.indexOf('jpeg') >= 0 || mimeType.indexOf('jpg') >= 0) ext = 'jpg';
        else if (mimeType.indexOf('gif') >= 0) ext = 'gif';
        else if (mimeType.indexOf('webp') >= 0) ext = 'webp';
        var name = nameHint || ('粘贴-' + Date.now() + '.' + ext);
        getPending().push({
          id: Date.now() + Math.random(),
          name: name,
          mimeType: mimeType,
          data: data,
          kind: 'image'
        });
        renderAttachChips();
      };
      reader.readAsDataURL(blob);
    }

    msgInput.addEventListener('paste', function (e) {
      var cd = e.clipboardData;
      if (!cd) return;
      var foundImage = false;
      if (cd.files && cd.files.length) {
        for (var fi = 0; fi < cd.files.length; fi++) {
          var f = cd.files[fi];
          if (f.type && f.type.indexOf('image/') === 0) {
            e.preventDefault();
            foundImage = true;
            pushImageFromBlob(f, f.name || null);
          }
        }
      }
      if (!foundImage && cd.items) {
        for (var ii = 0; ii < cd.items.length; ii++) {
          var item = cd.items[ii];
          if (item.type && item.type.indexOf('image/') === 0) {
            e.preventDefault();
            var file = item.getAsFile();
            if (file) pushImageFromBlob(file, null);
            break;
          }
        }
      }
    });

    function sendMessage() {
      if (voiceNativePending) {
        showFeedback(sendFeedback, 'error', '请等待语音识别结束');
        return;
      }
      stopVoiceInput();
      const text = msgInput.value.trim();
      var pa = getPending();
      const images = pa.filter(function (a) { return a.kind === 'image'; }).map(function (a) {
        return { mimeType: a.mimeType, data: a.data };
      });
      const files = pa.filter(function (a) { return a.kind === 'file'; }).map(function (a) {
        return { name: a.name, mimeType: a.mimeType, data: a.data };
      });
      if (!text && images.length === 0 && files.length === 0) {
        showFeedback(sendFeedback, 'error', '请输入文字或添加图片/文件');
        return;
      }
      const workspacePath = currentWorkspacePath || pathInput.value.trim();
      setLoading(sendBtn, true);
      showFeedback(sendFeedback, 'pending', '正在发送...');
      vscodeApi.postMessage({
        command: 'sendMessage',
        text: text,
        workspacePath: workspacePath,
        images: images,
        files: files,
        sessionId: activeSessionId
      });
    }

    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (!msg || !msg.command) return;

      switch (msg.command) {
        case 'licenseStatus':
          if (msg.ok) {
            applyLicenseShell(true, msg.label || '');
          } else {
            applyLicenseShell(false, '');
          }
          break;
        case 'licenseActivationResult':
          if (msg.ok) {
            showLicenseFeedback('success', msg.msg || '激活成功');
            var lki = document.getElementById('licenseKeyInput');
            if (lki) lki.value = '';
          } else {
            showLicenseFeedback('error', msg.msg || '激活失败');
          }
          break;
        case 'trialResult':
          if (msg.ok) {
            showLicenseFeedback('success', msg.msg || '试用已开始');
          } else {
            showLicenseFeedback('error', msg.msg || '无法开始试用');
          }
          break;
        case 'copyPhraseResult':
          if (msg.ok) {
            showFeedback(sendFeedback, 'success', '已复制到剪贴板');
          }
          break;

        case 'folderSelected':
          if (msg.path) {
            pathInput.value = msg.path;
            var prefix = msg.fromCurrentWorkspace ? '已填入当前工作区：' : '已选择：';
            showFeedback(cfgFeedback, 'info', prefix + msg.path);
          } else if (msg.error) {
            var err = String(msg.error);
            showFeedback(cfgFeedback, 'error', err.indexOf('当前没有') === 0 ? err : '选择失败：' + err);
          }
          break;

        case 'configResult':
          setLoading(cfgBtn, false);
          if (msg.ok) {
            currentWorkspacePath = msg.workspacePath || '';
            showFeedback(cfgFeedback, 'success', msg.msg);
            statusDot.className = 'status-dot connected';
            addMessage('system', '工作区配置成功，MCP 已就绪\\n' + currentWorkspacePath);
          } else {
            showFeedback(cfgFeedback, 'error', '配置失败：' + msg.msg);
            statusDot.className = 'status-dot error';
          }
          break;

        case 'restoreSessionOrder':
          if (Array.isArray(msg.order) && msg.order.length) {
            sessionOrder = msg.order.map(String).filter(function (id) {
              var n = parseInt(id, 10);
              return n >= 1 && n <= MAX_SESSIONS && String(n) === id;
            });
            if (sessionOrder.length === 0) sessionOrder = ['1', '2', '3'];
            var seen = {};
            sessionOrder = sessionOrder.filter(function (id) {
              if (seen[id]) return false;
              seen[id] = true;
              return true;
            });
            if (sessionOrder.indexOf(activeSessionId) < 0) {
              activeSessionId = sessionOrder[0];
            }
            sessionOrder.forEach(function (s) { ensureSessionStructures(s); });
            renderSessionRail();
            renderAttachChips();
            renderMessages();
          }
          break;

        case 'restoreSessionMemos':
          if (msg.memos && typeof msg.memos === 'object') {
            Object.keys(msg.memos).forEach(function (k) {
              var raw = msg.memos[k];
              if (raw == null) return;
              var t = String(raw).trim().slice(0, 200);
              if (t) sessionMemos[k] = t;
            });
            if (sessionMemoInput) sessionMemoInput.value = sessionMemos[activeSessionId] || '';
          }
          break;

        case 'restoreHistories':
          try {
            var data = JSON.parse(msg.payload || '{}');
            Object.keys(data).forEach(function (sid) {
              if (!Array.isArray(data[sid])) return;
              ensureSessionStructures(sid);
              messagesBySession[sid] = data[sid].map(function (row) {
                return { type: row.type, content: row.content, time: row.time ? new Date(row.time) : new Date() };
              });
            });
            renderMessages();
          } catch (e) { /* ignore */ }
          break;

        case 'voiceInputResult':
          setVoiceNativeBusy(false);
          if (msg.ok) {
            var vt = String(msg.text || '').trim();
            if (vt) {
              var curV = msgInput.value;
              var sep = curV && !/\\s$/.test(curV) ? ' ' : '';
              msgInput.value = curV + sep + vt;
              showFeedback(sendFeedback, 'success', '已写入语音识别结果');
            } else {
              showFeedback(sendFeedback, 'info', '未获得有效文字');
            }
          } else {
            showFeedback(sendFeedback, 'error', msg.msg || '语音识别失败');
          }
          break;

        case 'sendResult':
          setLoading(sendBtn, false);
          if (testHelloBtn) setLoading(testHelloBtn, false);
          if (msg.ok) {
            var sid = msg.sessionId || activeSessionId;
            var line = msg.text || msgInput.value.trim() || '(仅附件)';
            if (msg.attachmentLabels && msg.attachmentLabels.length) {
              line += '\\n' + msg.attachmentLabels.join(' · ');
            }
            addMessage('user', line, undefined, sid);
            msgInput.value = '';
            pendingBySession[sid] = [];
            renderAttachChips();
            showFeedback(sendFeedback, 'success', msg.msg);
          } else {
            showFeedback(sendFeedback, 'error', '发送失败：' + msg.msg);
          }
          break;

        case 'cursorReply':
          if (msg.reply) {
            addMessage('cursor', msg.reply, msg.time, msg.sessionId || activeSessionId);
            statusDot.className = 'status-dot connected';
          }
          break;

        case 'pong':
          addMessage('system', 'pong: ' + msg.text);
          break;
      }
    });

    renderMessages();
  </script>
</body>
</html>`;
}
function getNonce() {
    let text = "";
    const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (let i = 0; i < 32; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}
//# sourceMappingURL=extension.js.map
