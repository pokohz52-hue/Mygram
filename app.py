import json
import os
import aiosqlite
from aiohttp import web

DB_NAME = "tg_database.db"
online_users = {}

async def init_db():
    async with aiosqlite.connect(DB_NAME) as db:
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
                            await ws.send_str(json.dumps({
                                "action": "auth_need_reg",
                                "is_first": (count == 0)
                            }))

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

                elif action == "admin_get_users" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT is_admin FROM users WHERE username = ?", (current_user,))
                        adm = await cursor.fetchone()
                        if adm and adm[0] == 1:
                            cursor = await db.execute("SELECT id, username, device_id, is_verified, is_admin FROM users")
                            all_users = [{"id": r[0], "username": r[1], "device": r[2][:8]+"...", "verified": bool(r[3]), "admin": bool(r[4])} for r in await cursor.fetchall()]
                            await ws.send_str(json.dumps({"action": "admin_users_list", "items": all_users}))

                elif action == "admin_toggle_verify" and current_user:
                    target_u = data.get("target")
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT is_admin FROM users WHERE username = ?", (current_user,))
                        adm = await cursor.fetchone()
                        if adm and adm[0] == 1:
                            await db.execute("UPDATE users SET is_verified = CASE WHEN is_verified=1 THEN 0 ELSE 1 END WHERE username = ?", (target_u,))
                            await db.commit()
                            cursor = await db.execute("SELECT is_verified FROM users WHERE username = ?", (target_u,))
                            new_v = bool((await cursor.fetchone())[0])

                            # Оповещаем админа об обновлении списка
                            cursor = await db.execute("SELECT id, username, device_id, is_verified, is_admin FROM users")
                            all_users = [{"id": r[0], "username": r[1], "device": r[2][:8]+"...", "verified": bool(r[3]), "admin": bool(r[4])} for r in await cursor.fetchall()]
                            await ws.send_str(json.dumps({"action": "admin_users_list", "items": all_users}))

                            # Если пользователь онлайн, обновляем его галочку без вылета
                            if target_u in online_users:
                                await online_users[target_u].send_str(json.dumps({
                                    "action": "verify_status_changed",
                                    "verified": new_v
                                }))

                elif action == "search_users" and current_user:
                    query = data.get("query", "").strip().lower()
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute(
                            "SELECT username, avatar, is_verified FROM users WHERE username LIKE ? AND username != ? LIMIT 15", (f"%{query}%", current_user)
                        )
                        results = [{"username": r[0], "avatar": r[1], "verified": bool(r[2])} for r in await cursor.fetchall()]
                    await ws.send_str(json.dumps({"action": "search_results", "items": results}))

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
                    if target in online_users:
                        await online_users[target].send_str(json.dumps({"action": "messages_read", "by": current_user}))

                elif action == "typing" and current_user:
                    target = data.get("to", "").strip().lower()
                    if target in online_users:
                        await online_users[target].send_str(json.dumps({"action": "user_typing", "from": current_user}))

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
    web.run_app(make_app(), host='0.0.0.0', port=8000)
