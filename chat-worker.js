// 违禁词表（政治敏感/领导人名讳/键政攻击，骂人不管——自由搏击）
const BAD_WORDS = ['习近平','李强','胡锦涛','温家宝','江泽民','李克强','坦克人','六四','独裁','暴政','太子党','天安门事件','某地事件'];
function hasBadWord(t){ return BAD_WORDS.some(w => (t||'').includes(w)); }

// ---- CORS ----
const JSON_HEADERS = { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" };
// 聊天图片只允许位图格式（拒绝 SVG 等可能带脚本/外链的格式）
const IMAGE_RE = /^data:image\/(png|jpeg|jpg|gif|webp);/i;

// ---- A-SOUL 直播日程源（asoulcalendar.com 公开 API，聚合官方+突击）----
const ASOUL_CAL_URL = "https://asoulcalendar.com/api/lives";
const DAY_NAMES = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];

// 把 asoulcalendar 的 lives 数组解析成本周 schedule（按北京时间 UTC+8）
function buildSchedule(lives) {
  const nowUTC = Date.now();
  const bjNow = new Date(nowUTC + 8 * 3600 * 1000);
  const bjDay = bjNow.getUTCDay(); // 0=周日
  const mondayOffset = bjDay === 0 ? -6 : 1 - bjDay;
  const mondayBJ = new Date(Date.UTC(bjNow.getUTCFullYear(), bjNow.getUTCMonth(), bjNow.getUTCDate() + mondayOffset, 0, 0, 0));
  const weekStartUTC = mondayBJ.getTime() - 8 * 3600 * 1000;
  const weekEndUTC = weekStartUTC + 7 * 24 * 3600 * 1000;

  const byDay = [[], [], [], [], [], [], []];
  for (const live of lives || []) {
    if (live.kind !== "schedule" || live.hide || !live.start_time) continue;
    const t = Date.parse(live.start_time + "+08:00");
    if (isNaN(t) || t < weekStartUTC || t >= weekEndUTC) continue;
    const bj = new Date(t + 8 * 3600 * 1000);
    const idx = (bj.getUTCDay() + 6) % 7; // 周一=0
    const hh = String(bj.getUTCHours()).padStart(2, "0");
    const mm = String(bj.getUTCMinutes()).padStart(2, "0");
    byDay[idx].push({
      m: String(live.title || live.host || "直播").slice(0, 18),
      t: hh + ":" + mm,
    });
  }
  return DAY_NAMES.map((day, i) => {
    const items = byDay[i].sort((a, b) => (a.t < b.t ? -1 : a.t > b.t ? 1 : 0));
    return { day, items: items.length ? items : [{ m: "休息日", t: "" }] };
  });
}

// ---- 管理密钥：只从 Worker secret 读（不再硬编码，防公开仓库泄漏）----
function isAdmin(request, env) {
  const key = env.ADMIN_KEY || "";
  if (!key) return false;
  const u = new URL(request.url);
  return u.searchParams.get("k") === key || request.headers.get("X-Admin-Key") === key;
}

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
async function makeLiveKitToken(identity, room, env, canPublish) {
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: env.LIVEKIT_API_KEY,
    sub: identity,
    nbf: now - 10,
    exp: now + 3600, // 1 小时有效
    video: { room: room, roomJoin: true, canPublish: !!canPublish, canSubscribe: true }
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

    // CORS 预检处理（OPTIONS）——所有跨域 fetch POST 先发 preflight，必须回应
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,X-Admin-Key,X-Update-Secret", "Access-Control-Max-Age": "86400" } });
    }

    // 路由：/heartbeat 记录 cron 心跳（内部，X-Internal-Key）
    if (pathname === "/heartbeat") {
      const key = this.env.ADMIN_KEY || "";
      if (!key || request.headers.get("X-Internal-Key") !== key) {
        return new Response(JSON.stringify({ ok: false }), { status: 403, headers: JSON_HEADERS });
      }
      await this.state.storage.put("lastCronAt", Date.now());
      return new Response(JSON.stringify({ ok: true }), { headers: JSON_HEADERS });
    }
    // 路由：/cron-heartbeat 查 cron 心跳（公开，诊断用）
    if (pathname === "/cron-heartbeat") {
      const lastCronAt = await this.state.storage.get("lastCronAt") || 0;
      return new Response(JSON.stringify({ lastCronAt, now: Date.now(), diffMin: Math.round((Date.now() - lastCronAt) / 60000) }), { headers: JSON_HEADERS });
    }

    // 路由：/update-live 接收 GitHub Actions 推送的直播状态（POST，需 secret）
    if (pathname === "/update-live" && request.method === "POST") {
      const secret = this.env.UPDATE_SECRET || "";
      const provided = request.headers.get("X-Update-Secret") || "";
      if (!secret || provided !== secret) {
        return new Response(JSON.stringify({ ok: false, msg: "unauthorized" }), { status: 403, headers: JSON_HEADERS });
      }
      try {
        const data = await request.json();
        const members = (data.members || []).map(m => ({ name: String(m.name).slice(0,20), room: Number(m.room)||0, live: !!m.live, title: String(m.title||"").slice(0,60), url: String(m.url||"") }));
        await this.state.storage.put("asoulLive", members);
        await this.state.storage.put("liveUpdated", Date.now());
        return new Response(JSON.stringify({ ok: true, count: members.length }), { headers: JSON_HEADERS });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false }), { status: 400, headers: JSON_HEADERS });
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
      return new Response(JSON.stringify(body), { headers: JSON_HEADERS });
    }

    // 路由：/set-live-pass 设置屏幕共享密码——只有"正在共享的人（密码主人）"能设/改
    // 支持管理密钥 force=1 强制清密码/改密码（救抢注场景）
    if (pathname === "/set-live-pass") {
      const pass = (url.searchParams.get("pass") || "").slice(0, 20);
      const uid = (url.searchParams.get("uid") || "").slice(0, 40);
      const setter = await this.state.storage.get("livePassSetter");
      // 管理密钥强制改/清密码（force=1）
      if (url.searchParams.get("force") === "1" && isAdmin(request, this.env)) {
        if (pass) {
          await this.state.storage.put("livePass", pass);
          await this.state.storage.put("livePassRev", Date.now());
          await this.state.storage.put("livePassSetter", uid || "admin");
        } else {
          await this.state.storage.delete("livePass");
          await this.state.storage.delete("livePassRev");
          await this.state.storage.delete("livePassSetter");
        }
        return new Response(JSON.stringify({ ok: true, hasPass: !!pass, force: true }), { headers: JSON_HEADERS });
      }
      if (pass) {
        // 已有密码且不是密码主人 → 拒绝（只有当前共享者能改）
        if (setter && setter !== uid) {
          return new Response(JSON.stringify({ ok: false, msg: "只有当前共享者能设置密码" }), { headers: JSON_HEADERS });
        }
        await this.state.storage.put("livePass", pass);
        await this.state.storage.put("livePassRev", Date.now()); // 版本号 = 设置时间
        await this.state.storage.put("livePassSetter", uid); // 记录密码主人
      } else {
        // 清密码：也只有密码主人能清
        if (setter && setter !== uid) {
          return new Response(JSON.stringify({ ok: false, msg: "只有当前共享者能清除密码" }), { headers: JSON_HEADERS });
        }
        await this.state.storage.delete("livePass");
        await this.state.storage.delete("livePassRev");
        await this.state.storage.delete("livePassSetter");
      }
      return new Response(JSON.stringify({ ok: true, hasPass: !!pass }), { headers: JSON_HEADERS });
    }

    // 路由：/get-live-pass 查是否有密码+版本号（观众用）——不返回明文，明文比对在 /token 端点做
    if (pathname === "/get-live-pass") {
      const pass = await this.state.storage.get("livePass") || "";
      const rev = await this.state.storage.get("livePassRev") || 0;
      return new Response(JSON.stringify({ hasPass: !!pass, rev: rev }), { headers: JSON_HEADERS });
    }

    // 路由：/chat-his 拉取最近消息（HTTP 轮询，wss 连不上的降级）
    // 支持 ?since=<timestamp> 增量拉取（轮询只拉新消息，省流量）
    if (pathname === "/chat-his") {
      const history = await this.state.storage.get("messages") || [];
      const since = Number(url.searchParams.get("since")) || 0;
      const messages = since > 0 ? history.filter(m => (m.time || 0) > since) : history;
      return new Response(JSON.stringify({ messages }), { headers: JSON_HEADERS });
    }
    // 路由：/chat-send 发送消息（HTTP 轮询模式）
    if (pathname === "/chat-send" && request.method === "POST") {
      const paused = await this.state.storage.get("paused");
      if (paused) { return new Response(JSON.stringify({ ok: false, paused: true }), { headers: JSON_HEADERS }); }
      let data = {};
      try { data = await request.json(); } catch(e) {}
      const msg = { id: String(data.id || crypto.randomUUID()).slice(0, 64), name: (data.name || "匿名").slice(0, 20), text: (data.text || "").slice(0, 500), time: Date.now() };
      // 违禁词检查（HTTP 发送也拦）
      if (hasBadWord(msg.text)) { return new Response(JSON.stringify({ ok: false, blocked: true }), { headers: JSON_HEADERS }); }
      if (data.image && typeof data.image === "string" && IMAGE_RE.test(data.image.slice(0, 64)) && data.image.length < 1000000) {
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
      return new Response(JSON.stringify({ ok: true }), { headers: JSON_HEADERS });
    }

    // 路由：/clear-messages 清空聊天记录（主人控制，管理密钥）
    if (pathname === "/clear-messages") {
      if (!isAdmin(request, this.env)) { return new Response(JSON.stringify({ ok: false }), { status: 403, headers: JSON_HEADERS }); }
      await this.state.storage.put("messages", []);
      return new Response(JSON.stringify({ ok: true, cleared: true }), { headers: JSON_HEADERS });
    }

    // 路由：/schedule 读本周直播安排（每周更新）
    if (pathname === "/schedule") {
      const sched = await this.state.storage.get("schedule") || [];
      return new Response(JSON.stringify({ schedule: sched }), { headers: JSON_HEADERS });
    }
    // 路由：/set-schedule 更新本周安排（主人/鱼，管理密钥）
    if (pathname === "/set-schedule" && request.method === "POST") {
      if (!isAdmin(request, this.env)) { return new Response(JSON.stringify({ ok: false }), { status: 403, headers: JSON_HEADERS }); }
      let data = {}; try { data = await request.json(); } catch(e){}
      const sched = Array.isArray(data.schedule) ? data.schedule.slice(0, 20) : [];
      await this.state.storage.put("schedule", sched);
      return new Response(JSON.stringify({ ok: true, count: sched.length }), { headers: JSON_HEADERS });
    }

    // 路由：/refresh-schedule 手动抓取 asoulcalendar 更新本周安排（管理密钥）
    if (pathname === "/refresh-schedule") {
      if (!isAdmin(request, this.env)) { return new Response(JSON.stringify({ ok: false }), { status: 403, headers: JSON_HEADERS }); }
      const r = await this.refreshSchedule();
      return new Response(JSON.stringify(r), { headers: JSON_HEADERS });
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
        { name:"上流贝极星", desc:"蓝色臭狗。引导完毕，功成身退。几个月前漏味被乃组单手擒拿，闻风而逃，惶惶如丧之犬，改头换面削去姓名沦为饭后谈资" },
        { name:"小海诺", desc:"b猫的左膀右将，得力助手，a冰两大创始人之一。随着b猫得势不复从前随之衰颓，好在b猫分割一部分⭕使得二人也算幸福，不过当年的壮志随风飘散，如今拿回4.0的大权会做何打算" },
        { name:"张哥", desc:"卢边一条 人送外号学小弟，半步霓虹金，在鹅鸭杀中以椰果和凶狠闻名，令人闻风丧胆；在腾讯会议多次主持群内聚会，播放内容不好多聊，高考成绩239.5" },
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
      return new Response(JSON.stringify({ ming: mk(MING,"ming"), mingren: mk(MINGREN,"mingren") }), { headers: JSON_HEADERS });
    }
    // 路由：/vote 投票（每人每日 3 正 + 3 负）
    if (pathname === "/vote" && request.method === "POST") {
      let data = {}; try { data = await request.json(); } catch(e){}
      const uid = String(data.uid || "").slice(0,40);
      const hall = data.hall === "mingren" ? "mingren" : "ming";
      const name = String(data.name || "").slice(0,30);
      const dir = data.dir === "up" ? "up" : "down";
      if (!uid || !name) { return new Response(JSON.stringify({ ok:false, msg:"参数错" }), { headers: JSON_HEADERS }); }
      const today = new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0,10); // 按北京时间算"今天"（UTC+8）
      const uidVotes = await this.state.storage.get("uidVotes") || {};
      const my = uidVotes[uid] || {};
      if (my.date !== today) { my.date = today; my.up = 0; my.down = 0; }
      if (dir === "up" && my.up >= 3) return new Response(JSON.stringify({ ok:false, msg:"今日正向票已用完" }), { headers: JSON_HEADERS });
      if (dir === "down" && my.down >= 3) return new Response(JSON.stringify({ ok:false, msg:"今日负向票已用完" }), { headers: JSON_HEADERS });
      if (dir === "up") my.up++; else my.down++;
      uidVotes[uid] = my;
      const votes = await this.state.storage.get("hallVotes") || {};
      const h = votes[hall] = votes[hall] || {};
      const m = h[name] = h[name] || { up:0, down:0 };
      if (dir === "up") m.up++; else m.down++;
      await this.state.storage.put("hallVotes", votes);
      await this.state.storage.put("uidVotes", uidVotes);
      return new Response(JSON.stringify({ ok:true, remainingUp: 3 - my.up, remainingDown: 3 - my.down, up:m.up, down:m.down }), { headers: JSON_HEADERS });
    }

    // 路由：/set-paused 暂停/恢复聊天互动（主人控制，管理密钥）
    if (pathname === "/set-paused") {
      if (!isAdmin(request, this.env)) { return new Response(JSON.stringify({ ok: false }), { status: 403, headers: JSON_HEADERS }); }
      const p = url.searchParams.get("p") === "1";
      await this.state.storage.put("paused", p);
      return new Response(JSON.stringify({ ok: true, paused: p }), { headers: JSON_HEADERS });
    }

    // 路由：/token 签发 LiveKit token（带鉴权）
    // - 订阅（默认）：有密码时必须带 pass 正确；无密码开放
    // - 发布（publish=1）：有密码时只有密码主人 uid 能拿；无密码开放（与"无密码谁都能共享"一致）
    if (pathname === "/token") {
      const identity = (url.searchParams.get("identity") || "guest").slice(0, 40);
      const room = (url.searchParams.get("room") || "abing").slice(0, 40);
      const wantPublish = url.searchParams.get("publish") === "1";
      const pass = (url.searchParams.get("pass") || "").slice(0, 20);
      const uid = (url.searchParams.get("uid") || "").slice(0, 40);
      const livePass = await this.state.storage.get("livePass") || "";
      const setter = await this.state.storage.get("livePassSetter") || "";
      let canPublish = false;
      if (wantPublish) {
        if (livePass) {
          if (!uid || uid !== setter) {
            return new Response(JSON.stringify({ error: "not-allowed" }), { status: 403, headers: JSON_HEADERS });
          }
        }
        canPublish = true;
      } else {
        if (livePass && pass !== livePass) {
          return new Response(JSON.stringify({ error: "wrong-pass" }), { status: 403, headers: JSON_HEADERS });
        }
      }
      try {
        const token = await makeLiveKitToken(identity, room, this.env, canPublish);
        return new Response(JSON.stringify({ token: token, url: this.env.LIVEKIT_URL }), { headers: JSON_HEADERS });
      } catch (e) {
        return new Response(JSON.stringify({ error: "token failed" }), { status: 500, headers: JSON_HEADERS });
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

        // 一起看：换视频/网页 URL（只允许 http/https，防奇怪协议）
        if (data.type === "watch") {
          const url = (data.url || "").slice(0, 500);
          if (!url || !/^https?:\/\//i.test(url)) return;
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
          id: String(data.id || crypto.randomUUID()).slice(0, 64),
          name: (data.name || "匿名").slice(0, 20),
          text: (data.text || "").slice(0, 500),
          time: Date.now(),
        };
        // 图片（base64，只收位图格式，限制大小避免爆存储）
        if (data.image && typeof data.image === "string") {
          if (IMAGE_RE.test(data.image.slice(0, 64)) && data.image.length < 1000000) {
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

  // 抓 asoulcalendar.com 更新本周直播安排（30 分钟节流，避免频繁打扰人家）
  async refreshSchedule() {
    try {
      const lastFetch = await this.state.storage.get("lastScheduleFetch") || 0;
      if (Date.now() - lastFetch < 24 * 60 * 60 * 1000) {
        return { ok: true, skipped: true, msg: "24 小时内已抓过" };
      }
      const res = await fetch(ASOUL_CAL_URL);
      if (!res.ok) return { ok: false, status: res.status };
      const lives = await res.json();
      if (!Array.isArray(lives)) return { ok: false, msg: "数据格式不对" };
      const sched = buildSchedule(lives);
      await this.state.storage.put("schedule", sched);
      await this.state.storage.put("lastScheduleFetch", Date.now());
      return { ok: true, count: sched.length, days: sched };
    } catch (e) {
      return { ok: false, msg: String(e && e.message || e) };
    }
  }
}

export default {
  async fetch(request, env) {
    const id = env.CHAT_ROOM.idFromName("main-room");
    const room = env.CHAT_ROOM.get(id);
    return room.fetch(request);
  },
  // 定时（每10分钟）：① 记心跳 ② 触发 GitHub Actions 查直播状态 ③ 抓 asoulcalendar 更新本周安排
  async scheduled(event, env, ctx) {
    const key = env.ADMIN_KEY || "";
    const id = env.CHAT_ROOM.idFromName("main-room");
    const room = env.CHAT_ROOM.get(id);
    // ① 记 cron 心跳（诊断用）
    try {
      await room.fetch(new Request("https://internal/heartbeat", { headers: { "X-Internal-Key": key } }));
    } catch(e) {}
    // ② 触发 GitHub 查直播状态（需要 GITHUB_TOKEN）
    const token = env.GITHUB_TOKEN || "";
    if (token) {
      try {
        await fetch("https://api.github.com/repos/lct123456y-one/abing/actions/workflows/push-asoul-live.yml/dispatches", {
          method: "POST",
          headers: { "Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "Content-Type": "application/json", "User-Agent": "abing-chat-cron" },
          body: JSON.stringify({ ref: "master" })
        });
      } catch(e) {}
    }
    // ③ 抓 asoulcalendar 更新本周直播安排（24 小时节流，不依赖 GitHub token）
    try {
      await room.fetch(new Request("https://internal/refresh-schedule", { headers: { "X-Internal-Key": key } }));
    } catch(e) {}
  },
};
