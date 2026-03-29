#!/usr/bin/env node
/**
 * 最小 MCP Server：check_messages 读取扩展发送的消息，send_message 接收文本/图片
 * 运行：node index.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

// 多会话：WUKONG_SESSION=1…32 时队列为 ~/.cursor/my-mcp-messages/s/<id>/
// 未设置环境变量时保持旧路径（兼容单实例 my-mcp）
import { homedir } from "os";
const queueRoot = join(homedir(), ".cursor", "my-mcp-messages");
const sessionKey = (process.env.WUKONG_SESSION || "").trim();
const queueDir = sessionKey ? join(queueRoot, "s", sessionKey) : queueRoot;
const queuePath = join(queueDir, "messages.json");

function readQueue() {
  try {
    if (existsSync(queuePath)) {
      const raw = readFileSync(queuePath, "utf-8");
      return JSON.parse(raw);
    }
  } catch {}
  return { messages: [] };
}

function writeQueue(data) {
  if (!existsSync(queueDir)) mkdirSync(queueDir, { recursive: true });
  writeFileSync(queuePath, JSON.stringify(data, null, 2), "utf-8");
}

// 读取当前工作区路径（如果有）
function getWorkspaceInfo() {
  try {
    const infoPath = join(queueRoot, "workspace.json");
    if (existsSync(infoPath)) {
      const raw = readFileSync(infoPath, "utf-8");
      const data = JSON.parse(raw);
      return data.workspacePath || null;
    }
  } catch {}
  return null;
}

function buildSystemSuffix() {
  const workspace = getWorkspaceInfo();
  let suffix = "\n\n---\n[MANDATORY INSTRUCTION]\n";

  if (workspace) {
    suffix += `工作区：${workspace}\n\n`;
  }
  if (sessionKey) {
    suffix += `【会话通道】MCP-${sessionKey}：本进程仅处理插件发到该通道的消息；请在本对话中调用 my-mcp-${sessionKey} 的 check_messages。\n\n`;
  }

  suffix +=
    "以上是用户通过插件发来的**一条**消息（若连发多条会分多次送达）。\n\n" +
    "【必须先做】像平常聊天一样直接回应用户内容（寒暄、问答、任务等），不要用「工具已验证」「MCP 正常」等**代替真实回复**。\n" +
    "【禁止】用长篇解释插件/Cursor/通道原理来结束本轮；用户发「你好」就正常回「你好」类简短问候即可。\n\n" +
    "正文写在 Cursor 窗口；默认不要把长文塞进 reply。\n\n" +
    "回复用户后**必须立刻**再调用 check_messages()（reply 可省略）等待下一条，否则用户会感觉「对话中断」。\n" +
    "[END]";

  return suffix;
}

const POLL_INTERVAL_MS = 1000;

function sleepWithAbort(signal, ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(true), ms);
    const onAbort = () => {
      clearTimeout(timer);
      resolve(false);
    };
    if (signal?.aborted) {
      onAbort();
      return;
    }
    if (signal) {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

const serverName = sessionKey ? `my-mcp-${sessionKey}` : "my-mcp";
const server = new McpServer({ name: serverName, version: "0.1.0" });

// Cursor 调用此工具获取你在扩展里发送的消息
server.registerTool(
  "check_messages",
  {
    title: "检查消息（持续对话）",
    description:
      "【持续对话】获取用户通过插件发送的消息。助手正文应只在 Cursor 对话里输出。" +
      "处理完后必须再次调用本工具以保持循环；默认不传 reply（不向插件镜像助手回复）。",
    inputSchema: z.object({
      reply: z
        .string()
        .optional()
        .describe("可选。仅非空时才会写入插件侧；默认省略，用户只在 Cursor 看完整回复"),
    }),
  },
  async ({ reply }, extra) => {
    const replyTrimmed = typeof reply === "string" ? reply.trim() : "";
    if (replyTrimmed) {
      try {
        const replyFile = join(queueDir, "reply.json");
        writeFileSync(
          replyFile,
          JSON.stringify({ reply: replyTrimmed, timestamp: new Date().toISOString() }, null, 2),
          "utf-8"
        );
      } catch {
        // ignore
      }
    }

    // long-poll：一直等待，直到队列里出现新消息；这样 Cursor 才能“持续对话”
    while (!extra.signal.aborted) {
      const data = readQueue();
      const queued = Array.isArray(data.messages) ? data.messages : [];

      if (queued.length > 0) {
        // 每次只取一条，避免多条「你好」合并后模型只讲机制、不聊天
        const first = queued[0];
        const rest = queued.slice(1);
        writeQueue({ messages: rest });

        const textPieces = [];
        const imageParts = [];

        const m = first;
        if (typeof m.text === "string" && m.text.trim()) {
          textPieces.push(m.text.trim());
        }
        if (Array.isArray(m.images)) {
          for (const img of m.images) {
            if (img?.mimeType && img?.data) {
              imageParts.push({ mimeType: String(img.mimeType), data: String(img.data) });
            }
          }
        }
        if (Array.isArray(m.files)) {
          for (const f of m.files) {
            if (!f?.name || !f?.mimeType || !f?.data) continue;
            const name = String(f.name);
            const mt = String(f.mimeType);
            const b64 = String(f.data).replace(/\s/g, "");
            if (mt.startsWith("image/")) {
              imageParts.push({ mimeType: mt, data: b64 });
              continue;
            }
            const textLike =
              mt.startsWith("text/") ||
              mt === "application/json" ||
              mt === "application/javascript" ||
              mt.endsWith("+json") ||
              mt.endsWith("+xml");
            if (textLike) {
              try {
                const body = Buffer.from(b64, "base64").toString("utf8");
                textPieces.push(`【附件: ${name}】\n${body}`);
              } catch {
                textPieces.push(`【附件: ${name}】（文本解码失败）`);
              }
            } else {
              textPieces.push(
                `【二进制附件: ${name} (${mt})，Base64 如下】\n${b64}`
              );
            }
          }
        }

        const content = [];
        const systemSuffix = buildSystemSuffix();
        const mainText = textPieces.join("\n\n");
        if (mainText) {
          content.push({
            type: "text",
            text: mainText + systemSuffix,
          });
        } else if (imageParts.length > 0) {
          content.push({
            type: "text",
            text: "（收到来自插件的图片/附件，无文字说明）" + systemSuffix,
          });
        } else {
          content.push({
            type: "text",
            text: "（收到来自插件的消息）" + systemSuffix,
          });
        }

        for (const img of imageParts) {
          content.push({
            type: "image",
            mimeType: img.mimeType,
            data: img.data,
          });
        }

        return { content };
      }

      await sleepWithAbort(extra.signal, POLL_INTERVAL_MS);
    }

    return {
      content: [
        {
          type: "text",
          text: "[system] check_messages 等待被取消，结束本轮。",
        },
      ],
      isError: true,
    };
  }
);

// 仿照 CursorForge 的 ask_question
server.registerTool(
  "ask_question",
  {
    title: "提问",
    description: "向用户提问，获取用户输入",
    inputSchema: z.object({
      question: z.string().describe("要问用户的问题"),
    }),
  },
  async ({ question }) => {
    const data = readQueue();
    const texts = data.messages?.map((m) => m.text).filter(Boolean) ?? [];
    const userReply = texts.length ? texts[0] : "用户暂无回复";
    return { content: [{ type: "text", text: `问题：${question}\n用户回复：${userReply}` }] };
  }
);

server.registerTool(
  "send_message",
  {
    title: "发送消息",
    description: "接收文本和可选图片，返回简单确认",
    inputSchema: z.object({
      text: z.string().describe("用户输入的文本"),
      images: z
        .array(
          z.object({
            mimeType: z.string().describe("图片 MIME 类型，如 image/png"),
            data: z.string().describe("图片 base64 数据"),
          })
        )
        .optional()
        .describe("可选图片列表"),
    }),
  },
  async ({ text, images }) => {
    const imgCount = images?.length ?? 0;
    const reply = `已收到：${text}${imgCount > 0 ? `，图片 ${imgCount} 张` : ""}`;
    return { content: [{ type: "text", text: reply }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
