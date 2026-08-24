// 违禁词表（政治敏感/领导人名讳/键政攻击，骂人不管——自由搏击）
const BAD_WORDS = ['习近平','李强','胡锦涛','温家宝','江泽民','李克强','坦克人','六四','独裁','暴政','太子党','天安门事件','某地事件'];
function hasBadWord(t){ return BAD_WORDS.some(w => (t||'').includes(w)); }

// 极简实时聊天室（Cloudflare Workers + Durable Objects）
// 一个房间，WebSocket 广播，消息持久化 + 一起看（iframe URL 同步）+ LiveKit token

// ---- LiveKit access token（JWT HS256，用 WebCrypto 手写）----
function b64url(obj) {
  return btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
async function signJWT(claim, secret) {
  const enc = new TextEncoder();
  const header = b64url({ alg: "HS256", typ: "JWT" });
  const payload = b64url(claim);
  const data = header + "." + payload;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  return data + "." + sigB64;
}
async function makeLiveKitToken(identity, room, env) {
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: env.LIVEKIT_API_KEY,
    sub: identity,
    nbf: now - 10,
    exp: now + 3600, // 1 小时有效
    video: { room: room, roomJoin: true, canPublish: true, canSubscribe: true }
  };
  return await signJWT(claim, env.LIVEKIT_API_SECRET);
}

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Set(); // 所有活跃 WebSocket 连接
  }

  async fetch(request) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // 路由：/update-live 接收本地脚本推送的直播状态（POST）
    if (pathname === "/update-live" && request.method === "POST") {
      try {
        const data = await request.json();
        const members = (data.members || []).map(m => ({ name: String(m.name).slice(0,20), room: Number(m.room)||0, live: !!m.live, title: String(m.title||"").slice(0,60), url: String(m.url||"") }));
        await this.state.storage.put("asoulLive", members);
        await this.state.storage.put("liveUpdated", Date.now());
        return new Response(JSON.stringify({ ok: true, count: members.length }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false }), { status: 400 });
      }
    }

    // 路由：/asoul-live 读脚本推送的状态（不再实时查 B站）
    if (pathname === "/asoul-live") {
      const members = await this.state.storage.get("asoulLive") || [
        { name: "嘉然", room: 22637261, live: false, title: "", url: "https://live.bilibili.com/22637261" },
        { name: "乃琳", room: 22625027, live: false, title: "", url: "https://live.bilibili.com/22625027" },
        { name: "贝拉", room: 22632424, live: false, title: "", url: "https://live.bilibili.com/22632424" },
        { name: "心宜", room: 30849777, live: false, title: "", url: "https://live.bilibili.com/30849777" },
        { name: "思诺", room: 30858592, live: false, title: "", url: "https://live.bilibili.com/30858592" }
      ];
      const updated = await this.state.storage.get("liveUpdated");
      // 无 liveUpdated 时不返回 updated（避免"0分钟前"误导）
      const body = { members };
      if (updated) body.updated = updated;
      return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }

    // 路由：/set-live-pass 设置屏幕共享密码——只有"正在共享的人（密码主人）"能设/改
    if (pathname === "/set-live-pass") {
      const pass = (url.searchParams.get("pass") || "").slice(0, 20);
      const uid = (url.searchParams.get("uid") || "").slice(0, 40);
      const setter = await this.state.storage.get("livePassSetter");
      if (pass) {
        // 已有密码且不是密码主人 → 拒绝（只有当前共享者能改）
        if (setter && setter !== uid) {
          return new Response(JSON.stringify({ ok: false, msg: "只有当前共享者能设置密码" }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
        await this.state.storage.put("livePass", pass);
        await this.state.storage.put("livePassRev", Date.now()); // 版本号 = 设置时间
        await this.state.storage.put("livePassSetter", uid); // 记录密码主人
      } else {
        // 清密码：也只有密码主人能清
        if (setter && setter !== uid) {
          return new Response(JSON.stringify({ ok: false, msg: "只有当前共享者能清除密码" }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        }
        await this.state.storage.delete("livePass");
        await this.state.storage.delete("livePassRev");
        await this.state.storage.delete("livePassSetter");
      }
      return new Response(JSON.stringify({ ok: true, hasPass: !!pass }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }
    // 路由：/get-live-pass 查当前密码+版本号（观众用）
    if (pathname === "/get-live-pass") {
      const pass = await this.state.storage.get("livePass") || "";
      const rev = await this.state.storage.get("livePassRev") || 0;
      return new Response(JSON.stringify({ pass, rev }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }

    // 路由：/chat-his 拉取最近消息（HTTP 轮询，wss 连不上的降级）
    if (pathname === "/chat-his") {
      const history = await this.state.storage.get("messages") || [];
      return new Response(JSON.stringify({ messages: history }), {
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
    // 路由：/chat-send 发送消息（HTTP 轮询模式）
    if (pathname === "/chat-send" && request.method === "POST") {
      const paused = await this.state.storage.get("paused");
      if (paused) { return new Response(JSON.stringify({ ok: false, paused: true }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }); }
      let data = {};
      try { data = await request.json(); } catch(e) {}
      const msg = { name: (data.name || "匿名").slice(0, 20), text: (data.text || "").slice(0, 500), time: Date.now() };
      // 违禁词检查（HTTP 发送也拦）
      if (hasBadWord(msg.text)) { return new Response(JSON.stringify({ ok: false, blocked: true }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }); }
      if (data.image && typeof data.image === "string" && data.image.indexOf("data:image") === 0 && data.image.length < 2000000) {
        msg.image = data.image;
      }
      // 每 12 小时清空闲聊记录（懒清除，HTTP 也检查）
      const lastClear = await this.state.storage.get("lastClearAt") || 0;
      if (Date.now() - lastClear > 43200000) {
        await this.state.storage.put("messages", []);
        await this.state.storage.put("lastClearAt", Date.now());
      }
      const history = await this.state.storage.get("messages") || [];
      history.push(msg);
      let trimmed = history.length > 100 ? history.slice(-100) : history;
      await this.state.storage.put("messages", trimmed);
      for (const s of this.sessions) { try { s.send(JSON.stringify({ type: "chat", message: msg })); } catch (e) {} }
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }

    // 路由：/clear-messages 清空聊天记录（主人控制，带密钥）
    if (pathname === "/clear-messages") {
      if (url.searchParams.get("k") !== "abing-pause-key-2026") { return new Response(JSON.stringify({ ok: false }), { status: 403 }); }
      await this.state.storage.put("messages", []);
      return new Response(JSON.stringify({ ok: true, cleared: true }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }

    // 路由：/schedule 读本周直播安排（每周更新）
    if (pathname === "/schedule") {
      const sched = await this.state.storage.get("schedule") || [];
      return new Response(JSON.stringify({ schedule: sched }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }
    // 路由：/set-schedule 更新本周安排（主人/鱼，带密钥）
    if (pathname === "/set-schedule" && request.method === "POST") {
      if (url.searchParams.get("k") !== "abing-pause-key-2026") { return new Response(JSON.stringify({ ok: false }), { status: 403 }); }
      let data = {}; try { data = await request.json(); } catch(e){}
      const sched = Array.isArray(data.schedule) ? data.schedule.slice(0, 20) : [];
      await this.state.storage.put("schedule", sched);
      return new Response(JSON.stringify({ ok: true, count: sched.length }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }

    // 路由：/hall-data 名人堂/冥人堂成员+票数
    if (pathname === "/hall-data") {
      const votes = await this.state.storage.get("hallVotes") || {};
      const MING = [
        { name:"狂小椿", desc:"卷 a冰 sc 钱跑路，吞米潜逃孚众望，杳无音信" },
        { name:"五级游侠", desc:"海力士亏钱不堪重负，隐于市井。江湖传闻，以跳楼" },
        { name:"乃琳的皮鞭", desc:"鬼屋嫌弃鬼屋。身为鬼屋不自知，今日方知我是我" },
        { name:"就看看p", desc:"护妻心切七进七出，道心破碎遁入空门" },
        { name:"有爆有爆", desc:"「我换来了一代人的和平」——咸鱼星在斩杀他后如是说道。结果后面的事情大家都知道了……" }
      ];
      const MINGREN = [
        { name:"上流贝极星", desc:"蓝色臭狗。引导完毕，功成身退。如今化作 a冰 吉祥物，终日受人瞻仰" },
        { name:"崔东山", desc:"428 一役，贴吧众口铄金，遂断其志。然虽身处残年，仍念咸鱼星归位之日，夙夜难寐" },
        { name:"咸鱼星", desc:"功过难论，无冕之王，a冰 无权为你授勋" },
        { name:"星龟", desc:"师承咸鱼星。继贴吧吧主投降之后，又开创 QQ 群群主投降之先河。线下盗播一事更为津津乐道，大头通缉令亦曾漫天飞舞。虽败而不改其志，至今仍思使危楼复安，幽日重明" },
        { name:"五更明月/折木", desc:"在天愿作比翼鸟，在地愿为连理枝。折木既毕业搬砖，五更明月亦随之销声匿迹。曾经比翼，终成散席" },
        { name:"小三月", desc:"a冰 唯一不会下跪的男人，a冰 b站 办事处主任。晚年开动脑筋犯了 vr 倾错误，功过七三，尚未可盖棺而论" },
        { name:"然宜", desc:"a冰 最 SIGMA 的男人，老颦蹙最后的明珠，露早嘉然星瞳最忠实的粉丝，爱慕予琳愿" },
        { name:"030", desc:"a冰 第一圣女，滴泪妹，站街挣钱 ing" },
        { name:"苹果派（予琳愿）", desc:"雀魂 xtt 大明星，乃友、粥皮，B站 UP 主。所涉领域甚广，一身数职" },
        { name:"B猫", desc:"a冰 创始人，乌托邦计划发起者，愿梦中巴别塔长存" }
      ];
      const mk = (list, h) => list.map(m => { const v = (votes[h]||{})[m.name] || {up:0,down:0}; return { name:m.name, desc:m.desc, up:v.up, down:v.down }; });
      return new Response(JSON.stringify({ ming: mk(MING,"ming"), mingren: mk(MINGREN,"mingren") }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }
    // 路由：/vote 投票（每人每日 3 正 + 3 负）
    if (pathname === "/vote" && request.method === "POST") {
      let data = {}; try { data = await request.json(); } catch(e){}
      const uid = String(data.uid || "").slice(0,40);
      const hall = data.hall === "mingren" ? "mingren" : "ming";
      const name = String(data.name || "").slice(0,30);
      const dir = data.dir === "up" ? "up" : "down";
      if (!uid || !name) { return new Response(JSON.stringify({ ok:false, msg:"参数错" }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } }); }
      const today = new Date().toISOString().slice(0,10);
      const uidVotes = await this.state.storage.get("uidVotes") || {};
      const my = uidVotes[uid] || {};
      if (my.date !== today) { my.date = today; my.up = 0; my.down = 0; }
      if (dir === "up" && my.up >= 3) return new Response(JSON.stringify({ ok:false, msg:"今日正向票已用完" }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      if (dir === "down" && my.down >= 3) return new Response(JSON.stringify({ ok:false, msg:"今日负向票已用完" }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
      if (dir === "up") my.up++; else my.down++;
      uidVotes[uid] = my;
      const votes = await this.state.storage.get("hallVotes") || {};
      const h = votes[hall] = votes[hall] || {};
      const m = h[name] = h[name] || { up:0, down:0 };
      if (dir === "up") m.up++; else m.down++;
      await this.state.storage.put("hallVotes", votes);
      await this.state.storage.put("uidVotes", uidVotes);
      return new Response(JSON.stringify({ ok:true, remainingUp: 3 - my.up, remainingDown: 3 - my.down, up:m.up, down:m.down }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }

    // 路由：/set-paused 暂停/恢复聊天互动（主人控制，带密钥）
    if (pathname === "/set-paused") {
      const k = url.searchParams.get("k");
      const PAUSE_KEY = "abing-pause-key-2026";
      if (k !== PAUSE_KEY) { return new Response(JSON.stringify({ ok: false }), { status: 403 }); }
      const p = url.searchParams.get("p") === "1";
      await this.state.storage.put("paused", p);
      return new Response(JSON.stringify({ ok: true, paused: p }), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    }

    // 路由：/token 签发 LiveKit token（给屏幕共享用）
    if (pathname === "/token") {
      const identity = url.searchParams.get("identity") || "guest";
      const room = url.searchParams.get("room") || "abing";
      try {
        const token = await makeLiveKitToken(identity, room, this.env);
        return new Response(JSON.stringify({ token: token, url: this.env.LIVEKIT_URL }), {
          headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: "token failed" }), { status: 500 });
      }
    }

    const upgrade = request.headers.get("Upgrade");
    if (upgrade !== "websocket") {
      return new Response("Chat: use WebSocket", { status: 400 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();
    this.sessions.add(server);

    // 给新连接发历史消息（最近 100 条）+ 当前"一起看"状态 + 暂停状态
    const history = await this.state.storage.get("messages") || [];
    server.send(JSON.stringify({ type: "history", messages: history }));
    const watch = await this.state.storage.get("watch");
    if (watch && watch.url) {
      server.send(JSON.stringify({ type: "watch", watch: watch }));
    }
    const isPaused = await this.state.storage.get("paused");
    if (isPaused) {
      server.send(JSON.stringify({ type: "paused" }));
    }

    // 收到消息 -> 广播 + 保存
    let lastMsgAt = 0; // 该连接上次发消息时间（限速 2 秒一条）
    server.addEventListener("message", async (event) => {
      try {
        const data = JSON.parse(event.data);
        const now = Date.now();
        if (now - lastMsgAt < 2000) { return; } // 限速：2 秒内只接受 1 条，防刷屏
        lastMsgAt = now;

        // 暂停：聊天/弹幕/一起看在暂停时丢弃（主人断电）
        const paused = await this.state.storage.get("paused");
        if (paused && (data.type === "chat" || data.type === "danmu" || data.type === "watch")) {
          server.send(JSON.stringify({ type: "paused" }));
          return;
        }

        // 一起看：换视频/网页 URL
        if (data.type === "watch") {
          const url = (data.url || "").slice(0, 500);
          if (!url) return;
          const watch = { url: url, name: (data.name || "匿名").slice(0, 20), time: Date.now() };
          await this.state.storage.put("watch", watch);
          this.broadcastWatch(watch);
          return;
        }

        if (data.type !== "chat") {
          // 弹幕：广播（不存档）
          if (data.type === "danmu") {
            // 违禁词检查（弹幕也拦）
            if (hasBadWord(data.text)) { server.send(JSON.stringify({ type: "blocked" })); return; }
            const msg = { name: (data.name || "匿名").slice(0, 20), text: (data.text || "").slice(0, 60), time: Date.now() };
            for (const s of this.sessions) { try { s.send(JSON.stringify({ type: "danmu", message: msg })); } catch (e) {} }
          }
          return;
        }
        // 违禁词检查：含违禁词 → 拦截 + 提示（不广播）
        if (hasBadWord(data.text)) { server.send(JSON.stringify({ type: "blocked" })); return; }
        const msg = {
          name: (data.name || "匿名").slice(0, 20),
          text: (data.text || "").slice(0, 500),
          time: Date.now(),
        };
        // 图片（base64，限制大小避免爆存储）
        if (data.image && typeof data.image === "string") {
          const preview = data.image.slice(0, 200);
          if (preview.indexOf("data:image") === 0 && data.image.length < 2000000) {
            msg.image = data.image;
          }
        }
        // 每 12 小时清空闲聊记录（懒清除）
        const lastClear = await this.state.storage.get("lastClearAt") || 0;
        if (Date.now() - lastClear > 43200000) {
          await this.state.storage.put("messages", []);
          await this.state.storage.put("lastClearAt", Date.now());
        }
        // 保存（最近 100 条）
        let history2 = await this.state.storage.get("messages") || [];
        history2.push(msg);
        if (history2.length > 100) history2 = history2.slice(-100);
        await this.state.storage.put("messages", history2);
        // 广播给所有人
        this.broadcastChat(msg);
      } catch (e) { /* 忽略坏消息 */ }
    });

    server.addEventListener("close", () => {
      this.sessions.delete(server);
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  broadcastChat(msg) {
    for (const s of this.sessions) {
      try { s.send(JSON.stringify({ type: "chat", message: msg })); } catch (e) {}
    }
  }

  broadcastWatch(watch) {
    for (const s of this.sessions) {
      try { s.send(JSON.stringify({ type: "watch", watch: watch })); } catch (e) {}
    }
  }
}

export default {
  async fetch(request, env) {
    const id = env.CHAT_ROOM.idFromName("main-room");
    const room = env.CHAT_ROOM.get(id);
    return room.fetch(request);
  },
};
