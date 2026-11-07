import json
import os
import aiosqlite
from aiohttp import web

DB_NAME = "tg_database.db"
online_users = {}

async def init_db():
    async with aiosqlite.connect(DB_NAME) as db:
        # Таблица пользователей
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                device_id TEXT UNIQUE NOT NULL,
                avatar TEXT DEFAULT '',
                is_verified INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0
            )
        """)
        # Таблица личных сообщений
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0
            )
        """)
        # Таблица каналов
        await db.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                tag TEXT UNIQUE NOT NULL,
                description TEXT DEFAULT '',
                avatar TEXT DEFAULT '',
                owner TEXT NOT NULL
            )
        """)
        # Подписчики каналов
        await db.execute("""
            CREATE TABLE IF NOT EXISTS channel_subscribers (
                channel_id INTEGER,
                username TEXT,
                PRIMARY KEY (channel_id, username)
            )
        """)
        # Посты в каналах
        await db.execute("""
            CREATE TABLE IF NOT EXISTS channel_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()

async def index_handler(request):
    return web.FileResponse('static/index.html')

async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=10*1024*1024)
    await ws.prepare(request)
    current_user = None

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                data = json.loads(msg.data)
                action = data.get("action")

                # --- АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ ---
                if action == "device_init":
                    device_id = data.get("device_id", "").strip()
                    if not device_id: continue
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT username, avatar, is_verified, is_admin FROM users WHERE device_id = ?", (device_id,))
                        row = await cursor.fetchone()
                        if row:
                            current_user = row[0]
                            online_users[current_user] = ws
                            await ws.send_str(json.dumps({
                                "action": "auth_success",
                                "username": row[0],
                                "avatar": row[1],
                                "verified": bool(row[2]),
                                "is_admin": bool(row[3])
                            }))
                        else:
                            cursor = await db.execute("SELECT COUNT(*) FROM users")
                            count = (await cursor.fetchone())[0]
                            await ws.send_str(json.dumps({"action": "auth_need_reg", "is_first": (count == 0)}))

                elif action == "device_register":
                    device_id = data.get("device_id", "").strip()
                    username = data.get("username", "").strip().lower()
                    avatar = data.get("avatar", "")
                    if not device_id or not username: continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT id FROM users WHERE username = ?", (username,))
                        if await cursor.fetchone():
                            await ws.send_str(json.dumps({"action": "reg_error", "msg": "Этот юзернейм уже занят!"}))
                            continue

                        cursor = await db.execute("SELECT COUNT(*) FROM users")
                        is_first = (await cursor.fetchone())[0] == 0
                        is_admin_flag = 1 if is_first else 0
                        is_verified_flag = 1 if is_first else 0

                        await db.execute(
                            "INSERT INTO users (username, device_id, avatar, is_verified, is_admin) VALUES (?, ?, ?, ?, ?)",
                            (username, device_id, avatar, is_verified_flag, is_admin_flag)
                        )
                        await db.commit()
                        current_user = username
                        online_users[current_user] = ws
                        await ws.send_str(json.dumps({
                            "action": "auth_success",
                            "username": username,
                            "avatar": avatar,
                            "verified": bool(is_verified_flag),
                            "is_admin": bool(is_admin_flag)
                        }))

                # --- ЛОГИКА КАНАЛОВ ---
                elif action == "create_channel" and current_user:
                    name = data.get("name", "").strip()
                    tag = data.get("tag", "").strip().lower().replace("@", "")
                    desc = data.get("desc", "").strip()
                    avatar = data.get("avatar", "")

                    if not name or not tag:
                        await ws.send_str(json.dumps({"action": "toast", "msg": "Укажите имя и тег канала!"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT id FROM channels WHERE tag = ?", (tag,))
                        if await cursor.fetchone():
                            await ws.send_str(json.dumps({"action": "toast", "msg": "Тег @ уже занят!"}))
                            continue

                        cursor = await db.execute(
                            "INSERT INTO channels (name, tag, description, avatar, owner) VALUES (?, ?, ?, ?, ?)",
                            (name, tag, desc, avatar, current_user)
                        )
                        ch_id = cursor.lastrowid
                        # Создатель автоматически подписывается
                        await db.execute("INSERT INTO channel_subscribers (channel_id, username) VALUES (?, ?)", (ch_id, current_user))
                        await db.commit()

                    await ws.send_str(json.dumps({"action": "channel_created", "id": ch_id, "tag": tag}))

                elif action == "get_channels" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT c.id, c.name, c.tag, c.description, c.avatar, c.owner,
                            (SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = c.id) as subs_count,
                            EXISTS(SELECT 1 FROM channel_subscribers WHERE channel_id = c.id AND username = ?) as is_sub
                            FROM channels c
                        """, (current_user,))
                        rows = await cursor.fetchall()
                        ch_list = [{
                            "id": r[0], "name": r[1], "tag": r[2], "desc": r[3],
                            "avatar": r[4], "owner": r[5], "subs": r[6], "is_sub": bool(r[7])
                        } for r in rows]
                    await ws.send_str(json.dumps({"action": "channels_list", "items": ch_list}))

                elif action == "subscribe_channel" and current_user:
                    ch_id = data.get("channel_id")
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT 1 FROM channel_subscribers WHERE channel_id = ? AND username = ?", (ch_id, current_user))
                        if await cursor.fetchone():
                            await db.execute("DELETE FROM channel_subscribers WHERE channel_id = ? AND username = ?", (ch_id, current_user))
                            status = False
                        else:
                            await db.execute("INSERT INTO channel_subscribers (channel_id, username) VALUES (?, ?)", (ch_id, current_user))
                            status = True
                        await db.commit()
                        cursor = await db.execute("SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = ?", (ch_id,))
                        count = (await cursor.fetchone())[0]

                    await ws.send_str(json.dumps({"action": "sub_status", "channel_id": ch_id, "is_sub": status, "count": count}))

                elif action == "get_channel_posts" and current_user:
                    ch_id = data.get("channel_id")
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT id, sender, text, strftime('%H:%M', timestamp) FROM channel_posts
                            WHERE channel_id = ? ORDER BY id ASC
                        """, (ch_id,))
                        rows = await cursor.fetchall()
                        posts = [{"id": r[0], "sender": r[1], "text": r[2], "time": r[3]} for r in rows]
                    await ws.send_str(json.dumps({"action": "channel_history", "channel_id": ch_id, "items": posts}))

                elif action == "post_to_channel" and current_user:
                    ch_id = data.get("channel_id")
                    text = data.get("text", "").strip()
                    if not text: continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT owner FROM channels WHERE id = ?", (ch_id,))
                        row = await cursor.fetchone()
                        if not row or row[0] != current_user:
                            await ws.send_str(json.dumps({"action": "toast", "msg": "Только создатель может писать в канал!"}))
                            continue

                        cursor = await db.execute("INSERT INTO channel_posts (channel_id, sender, text) VALUES (?, ?, ?)", (ch_id, current_user, text))
                        await db.commit()
                        p_id = cursor.lastrowid
                        cursor = await db.execute("SELECT strftime('%H:%M', timestamp) FROM channel_posts WHERE id = ?", (p_id,))
                        p_time = (await cursor.fetchone())[0]

                        # Список всех подписчиков для рассылки поста
                        cursor = await db.execute("SELECT username FROM channel_subscribers WHERE channel_id = ?", (ch_id,))
                        subscribers = [r[0] for r in await cursor.fetchall()]

                    post_payload = json.dumps({"action": "new_post", "channel_id": ch_id, "id": p_id, "sender": current_user, "text": text, "time": p_time})
                    for sub in subscribers:
                        if sub in online_users:
                            await online_users[sub].send_str(post_payload)

                # --- ЛИЧНЫЕ ДИАЛОГИ (КАК И БЫЛО) ---
                elif action == "get_chats" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT DISTINCT CASE WHEN sender = ? THEN recipient ELSE sender END as chat_peer
                            FROM messages WHERE sender = ? OR recipient = ?
                        """, (current_user, current_user, current_user))
                        peer_names = [r[0] for r in await cursor.fetchall()]
                        chats = []
                        for peer in peer_names:
                            p_cur = await db.execute("SELECT username, avatar, is_verified FROM users WHERE username = ?", (peer,))
                            p_row = await p_cur.fetchone()
                            if p_row:
                                chats.append({"username": p_row[0], "avatar": p_row[1], "verified": bool(p_row[2])})
                    await ws.send_str(json.dumps({"action": "chat_list", "items": chats}))

                elif action == "get_history" and current_user:
                    target = data.get("with", "").strip().lower()
                    async with aiosqlite.connect(DB_NAME) as db:
                        await db.execute("UPDATE messages SET is_read = 1 WHERE sender = ? AND recipient = ?", (target, current_user))
                        await db.commit()
                        cursor = await db.execute("""
                            SELECT id, sender, recipient, text, strftime('%H:%M', timestamp), is_read FROM messages 
                            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                            ORDER BY id ASC
                        """, (current_user, target, target, current_user))
                        rows = await cursor.fetchall()
                        history = [{"id": r[0], "sender": r[1], "recipient": r[2], "text": r[3], "time": r[4] or "12:00", "is_read": r[5]} for r in rows]

                    await ws.send_str(json.dumps({"action": "history", "with": target, "items": history}))

                elif action == "send_msg" and current_user:
                    target = data.get("to", "").strip().lower()
                    text = data.get("text", "").strip()
                    if not text or not target: continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("INSERT INTO messages (sender, recipient, text, is_read) VALUES (?, ?, ?, 0)", (current_user, target, text))
                        await db.commit()
                        msg_id = cursor.lastrowid
                        cursor = await db.execute("SELECT strftime('%H:%M', timestamp) FROM messages WHERE id = ?", (msg_id,))
                        row = await cursor.fetchone()
                        msg_time = row[0] if row and row[0] else "12:00"

                    out = json.dumps({"action": "new_msg", "id": msg_id, "sender": current_user, "recipient": target, "text": text, "time": msg_time, "is_read": 0})
                    if target in online_users:
                        await online_users[target].send_str(out)
                    await ws.send_str(out)

    finally:
        if current_user and current_user in online_users:
            del online_users[current_user]
    return ws

async def make_app():
    await init_db()
    app = web.Application(client_max_size=10*1024*1024)
    app.router.add_get('/', index_handler)
    app.router.add_get('/ws', ws_handler)
    return app

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    web.run_app(make_app(), host='0.0.0.0', port=port)
