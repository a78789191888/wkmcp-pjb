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
exports.enforceCloudLicenseRevocationCheck = exports.clearExpiredTrialIfNeeded = exports.clearExpiredLicenseIfNeeded = exports.clearTrialUntilState = exports.clearLicenseState = exports.tryStartTrial30 = exports.tryActivateLicense = exports.tryActivateLicenseAsync = exports.getLicenseStatusForWebview = exports.formatLicenseExpiry = exports.checkLicenseValidity = exports.verifyAndParseToken = exports.generateLicenseToken = exports.getLicenseSecret = exports.MAX_LICENSE_DURATION_MS = exports.MIN_LICENSE_DURATION_MS = exports.TRIAL_DURATION_MS = exports.GLOBAL_STATE_TRIAL_USED_KEY = exports.GLOBAL_STATE_TRIAL_UNTIL_KEY = exports.GLOBAL_STATE_USED_NONCES_KEY = exports.GLOBAL_STATE_LICENSE_KEY = exports.DEFAULT_LICENSE_SECRET = void 0;
const crypto = __importStar(require("crypto"));
const http = __importStar(require("http"));
const https = __importStar(require("https"));
const vscode = __importStar(require("vscode"));
/** 与 settings 中 wukong.licenseSecret 一致；留空时使用（仅作开发/默认分发，正式环境请改密钥） */
exports.DEFAULT_LICENSE_SECRET = "wukong-mcp-dev-please-change-in-settings-2025";
exports.GLOBAL_STATE_LICENSE_KEY = "wukong.license.v1";
exports.GLOBAL_STATE_USED_NONCES_KEY = "wukong.usedLicenseNonces.v1";
exports.GLOBAL_STATE_TRIAL_UNTIL_KEY = "wukong.trialUntil.v1";
exports.GLOBAL_STATE_TRIAL_USED_KEY = "wukong.trialUsed.v1";
/** 试用时长（每机仅一次） */
exports.TRIAL_DURATION_MS = 30 * 60 * 1000;
const MAX_STORED_NONCES = 4000;
/** 1 分钟 */
exports.MIN_LICENSE_DURATION_MS = 60 * 1000;
/** 10 年（上限，防误填） */
exports.MAX_LICENSE_DURATION_MS = 10 * 365 * 24 * 3600 * 1000;
function getLicenseSecret() {
    const cfg = vscode.workspace.getConfiguration("wukong");
    const s = cfg.get("licenseSecret");
    if (typeof s === "string" && s.trim().length >= 8) {
        return s.trim();
    }
    return exports.DEFAULT_LICENSE_SECRET;
}
exports.getLicenseSecret = getLicenseSecret;
function toBase64Url(buf) {
    return buf
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}
function fromBase64Url(s) {
    const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
    return Buffer.from(b64, "base64");
}
function clampDurationMs(ms) {
    const x = Math.floor(ms);
    if (!Number.isFinite(x)) {
        return exports.MIN_LICENSE_DURATION_MS;
    }
    if (x < exports.MIN_LICENSE_DURATION_MS) {
        return exports.MIN_LICENSE_DURATION_MS;
    }
    if (x > exports.MAX_LICENSE_DURATION_MS) {
        return exports.MAX_LICENSE_DURATION_MS;
    }
    return x;
}
function signPayload(secret, dur, nonce, durationMs) {
    const n = nonce.toLowerCase();
    if (dur === "timed") {
        if (durationMs === undefined) {
            throw new Error("timed 卡密缺少 durationMs");
        }
        const msInt = clampDurationMs(durationMs);
        const msg = `v1|1|timed|${n}|${msInt}`;
        return crypto.createHmac("sha256", secret).update(msg, "utf8").digest();
    }
    const msg = `v1|1|${dur}|${n}`;
    return crypto.createHmac("sha256", secret).update(msg, "utf8").digest();
}
/**
 * 生成卡密（管理员侧，与当前密钥一致）。
 * `dur === "timed"` 时必须传入 `durationMs`（激活后起算的毫秒数，会被限制在合法区间内）。
 */
function generateLicenseToken(secret, dur, durationMs) {
    const nonce = crypto.randomBytes(16).toString("hex");
    let payload;
    let sig;
    if (dur === "timed") {
        if (durationMs === undefined || typeof durationMs !== "number" || !Number.isFinite(durationMs)) {
            throw new Error("自定义时长卡密需要有效的 durationMs（毫秒）");
        }
        const ms = clampDurationMs(durationMs);
        payload = { v: 1, dur: "timed", durationMs: ms, nonce };
        sig = signPayload(secret, "timed", nonce, ms);
    }
    else {
        payload = { v: 1, dur, nonce };
        sig = signPayload(secret, dur, nonce);
    }
    const pB64 = toBase64Url(Buffer.from(JSON.stringify(payload), "utf8"));
    const sB64 = toBase64Url(sig);
    return `WKM1.${pB64}.${sB64}`;
}
exports.generateLicenseToken = generateLicenseToken;
function verifyAndParseToken(secret, token) {
    const raw = token.trim().replace(/\s+/g, "");
    const parts = raw.split(".");
    if (parts.length !== 3 || parts[0] !== "WKM1") {
        return { ok: false, error: "卡密格式不正确（应以 WKM1. 开头）" };
    }
    let payload;
    try {
        payload = JSON.parse(fromBase64Url(parts[1]).toString("utf8"));
    }
    catch {
        return { ok: false, error: "卡密数据无法解析" };
    }
    if (!payload || typeof payload !== "object") {
        return { ok: false, error: "卡密数据无效" };
    }
    const p = payload;
    if (p.v !== 1) {
        return { ok: false, error: "不支持的卡密版本" };
    }
    const dur = p.dur;
    if (dur !== "perm" && dur !== "1d" && dur !== "1h" && dur !== "timed") {
        return { ok: false, error: "卡密类型无效" };
    }
    const nonce = String(p.nonce ?? "");
    if (!/^[0-9a-f]{32}$/i.test(nonce)) {
        return { ok: false, error: "卡密校验失败" };
    }
    let durationMs;
    if (dur === "timed") {
        const rawMs = p.durationMs;
        if (typeof rawMs !== "number" || !Number.isFinite(rawMs)) {
            return { ok: false, error: "自定义时长卡密缺少有效的 durationMs" };
        }
        durationMs = clampDurationMs(rawMs);
    }
    let sigBuf;
    try {
        sigBuf = fromBase64Url(parts[2]);
    }
    catch {
        return { ok: false, error: "签名块无效" };
    }
    if (sigBuf.length !== 32) {
        return { ok: false, error: "签名校验失败" };
    }
    const expected = dur === "timed"
        ? signPayload(secret, "timed", nonce, durationMs)
        : signPayload(secret, dur, nonce);
    if (!crypto.timingSafeEqual(sigBuf, expected)) {
        return { ok: false, error: "卡密无效或与当前签名密钥不匹配（请检查设置 wukong.licenseSecret）" };
    }
    if (dur === "timed") {
        if (durationMs === undefined) {
            return { ok: false, error: "卡密数据不完整" };
        }
        return { ok: true, dur: "timed", nonce: nonce.toLowerCase(), durationMs };
    }
    return { ok: true, dur: dur, nonce: nonce.toLowerCase() };
}
exports.verifyAndParseToken = verifyAndParseToken;
function readUsedNonces(context) {
    const raw = context.globalState.get(exports.GLOBAL_STATE_USED_NONCES_KEY);
    if (!Array.isArray(raw))
        return [];
    return raw.map((x) => String(x).toLowerCase()).filter((x) => /^[0-9a-f]{32}$/.test(x));
}
function checkStoredLicenseOnly(context) {
    const raw = context.globalState.get(exports.GLOBAL_STATE_LICENSE_KEY);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        return { valid: false, expiresAt: null };
    }
    const o = raw;
    const expiresAt = o.expiresAt;
    const dur = o.dur;
    if (expiresAt === null || expiresAt === undefined) {
        if (dur === "perm" || dur === undefined) {
            return { valid: true, expiresAt: null, dur: "perm" };
        }
        return { valid: false, expiresAt: null };
    }
    if (typeof expiresAt !== "number") {
        return { valid: false, expiresAt: null };
    }
    if (Date.now() >= expiresAt) {
        return { valid: false, expiresAt };
    }
    return { valid: true, expiresAt, dur };
}
function checkLicenseValidity(context) {
    const lic = checkStoredLicenseOnly(context);
    if (lic.valid) {
        return { ...lic, isTrial: false };
    }
    const trialUntil = context.globalState.get(exports.GLOBAL_STATE_TRIAL_UNTIL_KEY);
    if (typeof trialUntil === "number" && Date.now() < trialUntil) {
        return { valid: true, expiresAt: trialUntil, isTrial: true };
    }
    return { valid: false, expiresAt: null };
}
exports.checkLicenseValidity = checkLicenseValidity;
function formatLicenseExpiry(expiresAt) {
    if (expiresAt === null) {
        return "已激活 · 永久";
    }
    const ms = expiresAt - Date.now();
    if (ms <= 0) {
        return "已过期";
    }
    const totalM = Math.floor(ms / 60000);
    const d = Math.floor(totalM / (60 * 24));
    const h = Math.floor((totalM - d * 60 * 24) / 60);
    const m = totalM % 60;
    if (d > 0) {
        return `已激活 · 剩余约 ${d} 天 ${h} 小时`;
    }
    if (h > 0) {
        return `已激活 · 剩余约 ${h} 小时 ${m} 分钟`;
    }
    if (totalM < 1) {
        const sec = Math.max(1, Math.ceil(ms / 1000));
        return `已激活 · 剩余约 ${sec} 秒`;
    }
    return `已激活 · 剩余约 ${m} 分钟`;
}
exports.formatLicenseExpiry = formatLicenseExpiry;
function getLicenseStatusForWebview(context) {
    const st = checkLicenseValidity(context);
    if (!st.valid) {
        return { ok: false, expiresAt: null, label: "未激活" };
    }
    if (st.isTrial && st.expiresAt !== null) {
        return {
            ok: true,
            expiresAt: st.expiresAt,
            label: formatLicenseExpiry(st.expiresAt).replace("已激活", "试用中"),
        };
    }
    return {
        ok: true,
        expiresAt: st.expiresAt,
        label: formatLicenseExpiry(st.expiresAt),
    };
}
exports.getLicenseStatusForWebview = getLicenseStatusForWebview;
function postJsonToCloud(baseUrl, pathname, body, timeoutMs) {
    let u;
    try {
        u = new URL(pathname, baseUrl.replace(/\/+$/, ""));
    }
    catch {
        return Promise.reject(new Error("redeemApiBaseUrl 格式无效"));
    }
    const payload = Buffer.from(JSON.stringify(body), "utf8");
    const lib = u.protocol === "https:" ? https : http;
    const port = u.port !== "" ? parseInt(u.port, 10) : u.protocol === "https:" ? 443 : 80;
    return new Promise((resolve, reject) => {
        const req = lib.request({
            hostname: u.hostname,
            port,
            path: `${u.pathname}${u.search}`,
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": String(payload.length),
            },
        }, (res) => {
            const chunks = [];
            res.on("data", (c) => chunks.push(c));
            res.on("end", () => {
                resolve({
                    statusCode: res.statusCode ?? 0,
                    raw: Buffer.concat(chunks).toString("utf8"),
                });
            });
        });
        req.on("error", reject);
        req.setTimeout(timeoutMs, () => {
            req.destroy();
            reject(new Error("连接超时"));
        });
        req.write(payload);
        req.end();
    });
}
function postRedeemToCloud(baseUrl, body, timeoutMs) {
    return postJsonToCloud(baseUrl, "/api/redeem", body, timeoutMs);
}
/**
 * 激活：以 `WKM1.` 开头的走本地 HMAC 卡密；否则请求云端 `redeemApiBaseUrl` + `/api/redeem` 核销后写入本机授权（永久）。
 */
async function tryActivateLicenseAsync(context, keyInput) {
    const key = keyInput.trim().replace(/\s+/g, "");
    if (!key) {
        return { ok: false, msg: "请输入卡密" };
    }
    const cur = checkLicenseValidity(context);
    if (cur.valid && !cur.isTrial) {
        return { ok: false, msg: "本机已激活且未过期，无需重复激活" };
    }
    const cfg = vscode.workspace.getConfiguration("wukong");
    if (key.startsWith("WKM1.")) {
        const cloudOnly = cfg.get("cloudLicenseOnly") !== false;
        if (cloudOnly) {
            return {
                ok: false,
                msg: "当前为仅云端卡密模式：请使用发卡系统生成的卡密格式（可在设置中将 wukong.cloudLicenseOnly 设为 false 以使用 WKM1 本地卡密）。",
            };
        }
        return tryActivateLicense(context, keyInput);
    }
    const baseRaw = cfg.get("redeemApiBaseUrl");
    const baseUrl = typeof baseRaw === "string" ? baseRaw.trim() : "";
    if (!baseUrl) {
        return {
            ok: false,
            msg: "未配置云端核销地址：请在设置中填写 wukong.redeemApiBaseUrl（例如 http://5245.fun）",
        };
    }
    const rawTimeout = cfg.get("redeemTimeoutMs");
    const timeoutMs = Math.min(120000, Math.max(3000, typeof rawTimeout === "number" && Number.isFinite(rawTimeout) ? rawTimeout : 20000));
    let machineId = vscode.env.machineId || "unknown";
    if (machineId === "someValue.machineId") {
        machineId = "dev-machine";
    }
    let res;
    try {
        res = await postRedeemToCloud(baseUrl, { code: key, user: machineId.length > 128 ? machineId.slice(0, 128) : machineId }, timeoutMs);
    }
    catch (e) {
        const err = e instanceof Error ? e.message : String(e);
        return { ok: false, msg: `无法连接核销服务：${err}` };
    }
    let data;
    try {
        data = JSON.parse(res.raw);
    }
    catch {
        return { ok: false, msg: `服务器返回异常（HTTP ${res.statusCode}）` };
    }
    if (data.ok !== true) {
        const err = typeof data.error === "string" ? data.error : "invalid_or_used";
        if (err === "invalid_or_used") {
            return { ok: false, msg: "卡密无效或已被使用" };
        }
        return { ok: false, msg: "核销失败，请稍后再试" };
    }
    const now = Date.now();
    const nonce = `cloud:${crypto.randomBytes(16).toString("hex")}`;
    const cloudCodeHash = typeof data.codeHash === "string" && /^[0-9a-f]{64}$/i.test(data.codeHash.trim())
        ? data.codeHash.trim().toLowerCase()
        : undefined;
    let expiresAt = null;
    let dur = "perm";
    let durationMs;
    if (data.licenseExpiresAt != null && typeof data.licenseExpiresAt === "string") {
        const t = Date.parse(data.licenseExpiresAt);
        if (!Number.isNaN(t) && t > now) {
            expiresAt = t;
            dur = "timed";
            durationMs = t - now;
        }
    }
    const stored = {
        activatedAt: now,
        expiresAt,
        nonce,
        dur,
        ...(durationMs !== undefined ? { durationMs } : {}),
        ...(cloudCodeHash ? { cloudCodeHash } : {}),
    };
    void context.globalState.update(exports.GLOBAL_STATE_LICENSE_KEY, stored);
    void context.globalState.update(exports.GLOBAL_STATE_TRIAL_UNTIL_KEY, undefined);
    const sub = expiresAt !== null
        ? `激活成功（云端 · 约 ${Math.ceil((expiresAt - now) / 86400000)} 天）`
        : "激活成功（云端 · 永久）";
    return { ok: true, msg: sub };
}
exports.tryActivateLicenseAsync = tryActivateLicenseAsync;
function tryActivateLicense(context, keyInput) {
    const key = keyInput.trim().replace(/\s+/g, "");
    if (!key) {
        return { ok: false, msg: "请输入卡密" };
    }
    const cur = checkLicenseValidity(context);
    if (cur.valid && !cur.isTrial) {
        return { ok: false, msg: "本机已激活且未过期，无需重复激活" };
    }
    const secret = getLicenseSecret();
    const parsed = verifyAndParseToken(secret, key);
    if (!parsed.ok) {
        return { ok: false, msg: parsed.error };
    }
    const used = readUsedNonces(context);
    if (used.includes(parsed.nonce)) {
        return { ok: false, msg: "此卡密已在本机使用过（一卡一用）" };
    }
    const now = Date.now();
    let expiresAt = null;
    if (parsed.dur === "timed") {
        expiresAt = now + parsed.durationMs;
    }
    else if (parsed.dur === "1h") {
        expiresAt = now + 3600 * 1000;
    }
    else if (parsed.dur === "1d") {
        expiresAt = now + 24 * 3600 * 1000;
    }
    else {
        expiresAt = null;
    }
    const nextUsed = [...used, parsed.nonce];
    if (nextUsed.length > MAX_STORED_NONCES) {
        nextUsed.splice(0, nextUsed.length - MAX_STORED_NONCES);
    }
    const stored = {
        activatedAt: now,
        expiresAt,
        nonce: parsed.nonce,
        dur: parsed.dur,
        ...(parsed.dur === "timed" ? { durationMs: parsed.durationMs } : {}),
    };
    void context.globalState.update(exports.GLOBAL_STATE_USED_NONCES_KEY, nextUsed);
    void context.globalState.update(exports.GLOBAL_STATE_LICENSE_KEY, stored);
    void context.globalState.update(exports.GLOBAL_STATE_TRIAL_UNTIL_KEY, undefined);
    return { ok: true, msg: "激活成功" };
}
exports.tryActivateLicense = tryActivateLicense;
/** 每机仅一次：30 分钟试用 */
function tryStartTrial30(context) {
    if (context.globalState.get(exports.GLOBAL_STATE_TRIAL_USED_KEY)) {
        return { ok: false, msg: "本机已使用过试用" };
    }
    const st = checkLicenseValidity(context);
    if (st.valid && !st.isTrial) {
        return { ok: false, msg: "当前已激活" };
    }
    if (st.valid && st.isTrial) {
        return { ok: false, msg: "试用尚未结束" };
    }
    const until = Date.now() + exports.TRIAL_DURATION_MS;
    void context.globalState.update(exports.GLOBAL_STATE_TRIAL_UNTIL_KEY, until);
    void context.globalState.update(exports.GLOBAL_STATE_TRIAL_USED_KEY, true);
    return { ok: true, msg: "试用已开始" };
}
exports.tryStartTrial30 = tryStartTrial30;
async function clearLicenseState(context) {
    await context.globalState.update(exports.GLOBAL_STATE_LICENSE_KEY, undefined);
}
exports.clearLicenseState = clearLicenseState;
async function clearTrialUntilState(context) {
    await context.globalState.update(exports.GLOBAL_STATE_TRIAL_UNTIL_KEY, undefined);
}
exports.clearTrialUntilState = clearTrialUntilState;
/** 限时授权已到期时清掉本机 license 记录（永久授权不处理） */
function clearExpiredLicenseIfNeeded(context) {
    const raw = context.globalState.get(exports.GLOBAL_STATE_LICENSE_KEY);
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
        return;
    const o = raw;
    const expiresAt = o.expiresAt;
    if (expiresAt === null || expiresAt === undefined)
        return;
    if (typeof expiresAt === "number" && Date.now() >= expiresAt) {
        void clearLicenseState(context);
    }
}
exports.clearExpiredLicenseIfNeeded = clearExpiredLicenseIfNeeded;
/** 试用到期后清除 trialUntil */
function clearExpiredTrialIfNeeded(context) {
    const trialUntil = context.globalState.get(exports.GLOBAL_STATE_TRIAL_UNTIL_KEY);
    if (typeof trialUntil === "number" && Date.now() >= trialUntil) {
        void context.globalState.update(exports.GLOBAL_STATE_TRIAL_UNTIL_KEY, undefined);
    }
}
exports.clearExpiredTrialIfNeeded = clearExpiredTrialIfNeeded;
const CLOUD_VERIFY_FAIL_ERRORS = new Set(["revoked", "not_found", "expired", "device_mismatch"]);
/**
 * 云端卡：定期请求 /api/license/verify；服务端吊销或过期则清除本机授权。
 * 无 cloudCodeHash 的旧数据无法远程吊销；网络失败时不撤销（避免误伤离线用户）。
 */
async function enforceCloudLicenseRevocationCheck(context) {
    const raw = context.globalState.get(exports.GLOBAL_STATE_LICENSE_KEY);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        return;
    }
    const o = raw;
    const nonce = String(o.nonce ?? "");
    if (!nonce.startsWith("cloud:")) {
        return;
    }
    const codeHash = typeof o.cloudCodeHash === "string" ? o.cloudCodeHash.trim().toLowerCase() : "";
    if (!codeHash || !/^[0-9a-f]{64}$/.test(codeHash)) {
        return;
    }
    const cfg = vscode.workspace.getConfiguration("wukong");
    const baseRaw = cfg.get("redeemApiBaseUrl");
    const baseUrl = typeof baseRaw === "string" ? baseRaw.trim() : "";
    if (!baseUrl) {
        return;
    }
    const rawTimeout = cfg.get("redeemTimeoutMs");
    const timeoutMs = Math.min(120000, Math.max(3000, typeof rawTimeout === "number" && Number.isFinite(rawTimeout) ? rawTimeout : 20000));
    let machineId = vscode.env.machineId || "unknown";
    if (machineId === "someValue.machineId") {
        machineId = "dev-machine";
    }
    const user = machineId.length > 128 ? machineId.slice(0, 128) : machineId;
    let res;
    try {
        res = await postJsonToCloud(baseUrl, "/api/license/verify", { codeHash, user }, timeoutMs);
    }
    catch {
        return;
    }
    let data;
    try {
        data = JSON.parse(res.raw);
    }
    catch {
        return;
    }
    if (data.ok === true) {
        return;
    }
    const err = typeof data.error === "string" ? data.error : "";
    if (CLOUD_VERIFY_FAIL_ERRORS.has(err)) {
        await clearLicenseState(context);
    }
}
exports.enforceCloudLicenseRevocationCheck = enforceCloudLicenseRevocationCheck;
//# sourceMappingURL=license.js.map