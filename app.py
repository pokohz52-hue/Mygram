import json
import os
import hashlib
import secrets
import asyncio
import aiosqlite
from aiohttp import web

DB_NAME = "tg_database.db"
online_users = {}  # {username: ws}

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return hashed, salt

async def init_db():
    async with aiosqlite.connect(DB_NAME) as db:
        # Включение режима WAL для многопоточной скорости SQLite
        await db.execute("PRAGMA journal_mode = WAL")
        await db.execute("PRAGMA synchronous = NORMAL")

        # Пользователи
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                bio TEXT DEFAULT 'Пользуюсь MyGram ✨',
                emoji_status TEXT DEFAULT '',
                is_verified INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                session_token TEXT UNIQUE
            )
        """)
        # Сообщения
        await db.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                text TEXT NOT NULL,
                media_type TEXT DEFAULT 'text',
                media_data TEXT DEFAULT '',
                is_spoiler INTEGER DEFAULT 0,
                reply_to_id INTEGER DEFAULT 0,
                forward_from TEXT DEFAULT '',
                is_pinned INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0
            )
        """)
        # Реакции
        await db.execute("""
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                emoji TEXT NOT NULL,
                UNIQUE(target_type, target_id, username)
            )
        """)
        # Истории
        await db.execute("""
            CREATE TABLE IF NOT EXISTS stories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                media_data TEXT NOT NULL,
                caption TEXT DEFAULT '',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Каналы
        await db.execute("""
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                tag TEXT UNIQUE NOT NULL,
                description TEXT DEFAULT '',
                owner TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0
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
        # Посты каналов
        await db.execute("""
            CREATE TABLE IF NOT EXISTS channel_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id INTEGER,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                media_type TEXT DEFAULT 'text',
                media_data TEXT DEFAULT '',
                is_spoiler INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()

# Автоматический фоновый процесс очистки старых историй (раз в 30 минут)
async def auto_cleaner_task():
    while True:
        try:
            await asyncio.sleep(1800)
            async with aiosqlite.connect(DB_NAME) as db:
                await db.execute("DELETE FROM stories WHERE timestamp < datetime('now', '-1 day')")
                await db.commit()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[AutoCleaner Error]: {e}")

async def get_reactions(db, target_type, target_id):
    cursor = await db.execute("""
        SELECT emoji, COUNT(*), GROUP_CONCAT(username)
        FROM reactions 
        WHERE target_type = ? AND target_id = ?
        GROUP BY emoji
    """, (target_type, target_id))
    rows = await cursor.fetchall()
    return [{"emoji": r[0], "count": r[1], "users": r[2].split(",") if r[2] else []} for r in rows]

async def index_handler(request):
    if os.path.exists('static/index.html'):
        return web.FileResponse('static/index.html')
    return web.FileResponse('index.html')

async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=60*1024*1024)
    await ws.prepare(request)
    current_user = None

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                data = json.loads(msg.data)
                action = data.get("action")

                if action == "auth_by_token":
                    token = data.get("token", "").strip()
                    if not token:
                        await ws.send_str(json.dumps({"action": "require_login"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute(
                            "SELECT username, is_verified, is_admin, bio, emoji_status FROM users WHERE session_token = ?",
                            (token,)
                        )
                        row = await cursor.fetchone()
                        if row:
                            current_user = row[0]
                            online_users[current_user] = ws
                            await ws.send_str(json.dumps({
                                "action": "auth_success",
                                "username": row[0],
                                "verified": bool(row[1]),
                                "is_admin": bool(row[2]),
                                "bio": row[3],
                                "emoji_status": row[4],
                                "token": token
                            }))
                            status_payload = json.dumps({"action": "user_status", "username": current_user, "online": True})
                            for u, client in online_users.items():
                                if u != current_user and not client.closed:
                                    await client.send_str(status_payload)
                        else:
                            await ws.send_str(json.dumps({"action": "require_login"}))

                elif action == "login":
                    username = data.get("identifier", "").strip().lower()
                    password = data.get("password", "")
                    if not username or not password:
                        await ws.send_str(json.dumps({"action": "auth_error", "msg": "Заполните все поля"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute(
                            "SELECT username, password_hash, password_salt, is_verified, is_admin, bio, emoji_status FROM users WHERE username = ?",
                            (username,)
                        )
                        row = await cursor.fetchone()
                        if not row:
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Неверный логин или пароль"}))
                            continue

                        uname, real_hash, salt, is_ver, is_adm, bio, em_status = row
                        test_hash, _ = hash_password(password, salt)
                        if test_hash != real_hash:
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Неверный логин или пароль"}))
                            continue

                        session_token = secrets.token_hex(32)
                        await db.execute("UPDATE users SET session_token = ? WHERE username = ?", (session_token, uname))
                        await db.commit()

                    current_user = uname
                    online_users[current_user] = ws
                    await ws.send_str(json.dumps({
                        "action": "auth_success",
                        "username": uname,
                        "verified": bool(is_ver),
                        "is_admin": bool(is_adm),
                        "bio": bio,
                        "emoji_status": em_status,
                        "token": session_token
                    }))

                elif action == "register":
                    username = data.get("username", "").strip().lower()
                    password = data.get("password", "")
                    if not username or not password:
                        await ws.send_str(json.dumps({"action": "auth_error", "msg": "Заполните поля"}))
                        continue
                    if len(password) < 6:
                        await ws.send_str(json.dumps({"action": "auth_error", "msg": "Пароль от 6 символов"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT id FROM users WHERE username = ?", (username,))
                        if await cursor.fetchone():
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Никнейм занят"}))
                            continue

                        cursor = await db.execute("SELECT COUNT(*) FROM users")
                        is_first = (await cursor.fetchone())[0] == 0
                        is_adm = 1 if is_first else 0
                        is_ver = 1 if is_first else 0
                        session_token = secrets.token_hex(32)
                        p_hash, p_salt = hash_password(password)

                        await db.execute("""
                            INSERT INTO users (username, password_hash, password_salt, is_verified, is_admin, session_token, emoji_status)
                            VALUES (?, ?, ?, ?, ?, ?, '⚡')
                        """, (username, p_hash, p_salt, is_ver, is_adm, session_token))
                        await db.commit()

                    current_user = username
                    online_users[current_user] = ws
                    await ws.send_str(json.dumps({
                        "action": "auth_success",
                        "username": username,
                        "verified": bool(is_ver),
                        "is_admin": bool(is_adm),
                        "bio": "Пользуюсь MyGram ✨",
                        "emoji_status": "⚡",
                        "token": session_token
                    }))

                elif action == "update_status" and current_user:
                    new_status = data.get("status", "")[:4]
                    async with aiosqlite.connect(DB_NAME) as db:
                        await db.execute("UPDATE users SET emoji_status = ? WHERE username = ?", (new_status, current_user))
                        await db.commit()
                    await ws.send_str(json.dumps({"action": "status_updated", "status": new_status}))

                elif action == "get_stories" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT s.id, s.username, s.media_data, s.caption, strftime('%H:%M', s.timestamp), u.emoji_status
                            FROM stories s JOIN users u ON s.username = u.username
                            WHERE s.timestamp >= datetime('now', '-1 day')
                            ORDER BY s.id DESC
                        """)
                        rows = await cursor.fetchall()
                        st_list = [{
                            "id": r[0], "username": r[1], "media": r[2], "caption": r[3], "time": r[4], "status": r[5]
                        } for r in rows]
                    await ws.send_str(json.dumps({"action": "stories_list", "items": st_list}))

                elif action == "add_story" and current_user:
                    media = data.get("media", "")
                    caption = data.get("caption", "").strip()
                    if not media: continue
                    async with aiosqlite.connect(DB_NAME) as db:
                        await db.execute("INSERT INTO stories (username, media_data, caption) VALUES (?, ?, ?)", (current_user, media, caption))
                        await db.commit()
                    bcast = json.dumps({"action": "new_story_alert"})
                    for client in online_users.values():
                        if not client.closed: await client.send_str(bcast)

                elif action == "search" and current_user:
                    q = data.get("query", "").strip().lower().replace("@", "")
                    if not q: continue
                    search_pat = f"%{q}%"
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT username, is_verified, bio, emoji_status FROM users 
                            WHERE username LIKE ? AND username != ? LIMIT 10
                        """, (search_pat, current_user))
                        found_users = [{
                            "username": r[0], "verified": bool(r[1]), "bio": r[2], "status": r[3], "online": r[0] in online_users
                        } for r in await cursor.fetchall()]

                        cursor = await db.execute("""
                            SELECT c.id, c.name, c.tag, c.description, c.owner, c.is_verified,
                            (SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = c.id) as subs_count,
                            EXISTS(SELECT 1 FROM channel_subscribers WHERE channel_id = c.id AND username = ?) as is_sub
                            FROM channels c WHERE c.tag LIKE ? OR c.name LIKE ? LIMIT 10
                        """, (current_user, search_pat, search_pat))
                        found_channels = [{
                            "id": r[0], "name": r[1], "tag": r[2], "desc": r[3], "owner": r[4],
                            "verified": bool(r[5]), "subs": r[6], "is_sub": bool(r[7])
                        } for r in await cursor.fetchall()]

                    await ws.send_str(json.dumps({"action": "search_results", "users": found_users, "channels": found_channels}))

                elif action == "get_chats" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT DISTINCT CASE WHEN sender = ? THEN recipient ELSE sender END as peer
                            FROM messages WHERE sender = ? OR recipient = ?
                        """, (current_user, current_user, current_user))
                        peers = [r[0] for r in await cursor.fetchall()]
                        chats = []
                        for p in peers:
                            p_cur = await db.execute("SELECT username, is_verified, bio, emoji_status FROM users WHERE username = ?", (p,))
                            p_row = await p_cur.fetchone()
                            if p_row:
                                last_msg_cur = await db.execute("""
                                    SELECT text, media_type, strftime('%H:%M', timestamp)
                                    FROM messages WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                                    ORDER BY id DESC LIMIT 1
                                """, (current_user, p, p, current_user))
                                last_row = await last_msg_cur.fetchone()
                                unread_cur = await db.execute("SELECT COUNT(*) FROM messages WHERE sender = ? AND recipient = ? AND is_read = 0", (p, current_user))
                                unread_count = (await unread_cur.fetchone())[0]

                                last_preview = ""
                                if last_row:
                                    if last_row[1] == 'image': last_preview = '📷 Фотография'
                                    elif last_row[1] == 'audio': last_preview = '🎤 Голосовое сообщение'
                                    else: last_preview = last_row[0]

                                chats.append({
                                    "username": p_row[0], "verified": bool(p_row[1]), "bio": p_row[2], "status": p_row[3],
                                    "online": p_row[0] in online_users,
                                    "last_text": last_preview,
                                    "last_time": last_row[2] if last_row else "",
                                    "unread": unread_count
                                })
                    await ws.send_str(json.dumps({"action": "chat_list", "items": chats}))

                elif action == "get_history" and current_user:
                    target = data.get("with", "").strip().lower()
                    async with aiosqlite.connect(DB_NAME) as db:
                        await db.execute("UPDATE messages SET is_read = 1 WHERE sender = ? AND recipient = ?", (target, current_user))
                        await db.commit()
                        cursor = await db.execute("""
                            SELECT m.id, m.sender, m.recipient, m.text, m.media_type, m.media_data, 
                                   m.reply_to_id, m.is_pinned, m.is_spoiler, m.forward_from,
                                   strftime('%H:%M', m.timestamp), m.is_read,
                                   rm.sender, rm.text
                            FROM messages m
                            LEFT JOIN messages rm ON m.reply_to_id = rm.id
                            WHERE (m.sender = ? AND m.recipient = ?) OR (m.sender = ? AND m.recipient = ?)
                            ORDER BY m.id ASC
                        """, (current_user, target, target, current_user))
                        rows = await cursor.fetchall()
                        history = []
                        pinned_msg = None
                        for r in rows:
                            reacts = await get_reactions(db, "msg", r[0])
                            item = {
                                "id": r[0], "sender": r[1], "recipient": r[2], "text": r[3],
                                "media_type": r[4], "media_data": r[5], "reply_to_id": r[6],
                                "is_pinned": bool(r[7]), "is_spoiler": bool(r[8]), "forward_from": r[9],
                                "time": r[10] or "12:00", "is_read": bool(r[11]),
                                "reply_user": r[12], "reply_text": r[13], "reactions": reacts
                            }
                            if r[7]: pinned_msg = item
                            history.append(item)

                    if target in online_users:
                        await online_users[target].send_str(json.dumps({"action": "messages_read", "by": current_user}))

                    await ws.send_str(json.dumps({
                        "action": "history", "with": target, "items": history, "pinned": pinned_msg, "online": target in online_users
                    }))

                elif action == "send_msg" and current_user:
                    target = data.get("to", "").strip().lower()
                    text = data.get("text", "").strip()
                    media_type = data.get("media_type", "text")
                    media_data = data.get("media_data", "")
                    reply_id = int(data.get("reply_to_id", 0))
                    is_spoiler = 1 if data.get("is_spoiler") else 0
                    forward_from = data.get("forward_from", "")

                    if not text and not media_data: continue

                    reply_user, reply_text = None, None
                    async with aiosqlite.connect(DB_NAME) as db:
                        if reply_id > 0:
                            r_cur = await db.execute("SELECT sender, text FROM messages WHERE id = ?", (reply_id,))
                            r_row = await r_cur.fetchone()
                            if r_row: reply_user, reply_text = r_row[0], r_row[1]

                        cursor = await db.execute("""
                            INSERT INTO messages (sender, recipient, text, media_type, media_data, reply_to_id, is_spoiler, forward_from, is_read) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                        """, (current_user, target, text, media_type, media_data, reply_id, is_spoiler, forward_from))
                        await db.commit()
                        msg_id = cursor.lastrowid
                        cursor = await db.execute("SELECT strftime('%H:%M', timestamp) FROM messages WHERE id = ?", (msg_id,))
                        msg_time = (await cursor.fetchone())[0]

                    payload = {
                        "action": "new_msg", "id": msg_id, "sender": current_user, "recipient": target,
                        "text": text, "media_type": media_type, "media_data": media_data, "is_spoiler": bool(is_spoiler),
                        "forward_from": forward_from, "reply_to_id": reply_id, "reply_user": reply_user,
                        "reply_text": reply_text, "time": msg_time, "is_read": False, "reactions": []
                    }
                    if target in online_users:
                        await online_users[target].send_str(json.dumps(payload))
                    await ws.send_str(json.dumps(payload))

                    # Автоматический Smart AI Bot (@ai)
                    if text.startswith("@ai"):
                        prompt = text.replace("@ai", "").strip()
                        ai_resp = f"🤖 [AI-Assistant]: Запрос принят! «{prompt}». Всё работает в реальном времени!" if prompt else "🤖 [AI-Assistant]: Чем могу помочь?"
                        await asyncio.sleep(0.5)
                        async with aiosqlite.connect(DB_NAME) as db:
                            c = await db.execute("""
                                INSERT INTO messages (sender, recipient, text, is_read) VALUES ('AI Assistant', ?, ?, 1)
                            """, (current_user, ai_resp))
                            await db.commit()
                            ai_id = c.lastrowid
                        ai_payload = json.dumps({
                            "action": "new_msg", "id": ai_id, "sender": "AI Assistant", "recipient": current_user,
                            "text": ai_resp, "media_type": "text", "media_data": "", "is_spoiler": False,
                            "forward_from": "", "reply_to_id": msg_id, "reply_user": current_user,
                            "reply_text": text, "time": "сейчас", "is_read": True, "reactions": []
                        })
                        await ws.send_str(ai_payload)

                elif action == "pin_msg" and current_user:
                    msg_id = data.get("id")
                    target = data.get("with", "").strip().lower()
                    async with aiosqlite.connect(DB_NAME) as db:
                        await db.execute("""
                            UPDATE messages SET is_pinned = 0 
                            WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)
                        """, (current_user, target, target, current_user))
                        await db.execute("UPDATE messages SET is_pinned = 1 WHERE id = ?", (msg_id,))
                        await db.commit()
                        cur = await db.execute("SELECT sender, text FROM messages WHERE id = ?", (msg_id,))
                        r = await cur.fetchone()

                    pin_data = json.dumps({"action": "pinned_update", "id": msg_id, "sender": r[0], "text": r[1]})
                    await ws.send_str(pin_data)
                    if target in online_users: await online_users[target].send_str(pin_data)

                elif action == "typing" and current_user:
                    target = data.get("to", "").strip().lower()
                    if target in online_users:
                        await online_users[target].send_str(json.dumps({"action": "user_typing", "from": current_user}))

                elif action == "react" and current_user:
                    target_type = data.get("type")
                    target_id = data.get("id")
                    emoji = data.get("emoji")
                    async with aiosqlite.connect(DB_NAME) as db:
                        cur = await db.execute("SELECT id FROM reactions WHERE target_type = ? AND target_id = ? AND username = ? AND emoji = ?", (target_type, target_id, current_user, emoji))
                        if await cur.fetchone():
                            await db.execute("DELETE FROM reactions WHERE target_type = ? AND target_id = ? AND username = ? AND emoji = ?", (target_type, target_id, current_user, emoji))
                        else:
                            await db.execute("INSERT OR REPLACE INTO reactions (target_type, target_id, username, emoji) VALUES (?, ?, ?, ?)", (target_type, target_id, current_user, emoji))
                        await db.commit()
                        reacts = await get_reactions(db, target_type, target_id)

                    broadcast_data = json.dumps({"action": "reaction_update", "type": target_type, "id": target_id, "reactions": reacts})
                    for u, client in online_users.items():
                        if not client.closed: await client.send_str(broadcast_data)

                elif action == "delete_msg" and current_user:
                    msg_id = data.get("id")
                    async with aiosqlite.connect(DB_NAME) as db:
                        cur = await db.execute("SELECT sender, recipient FROM messages WHERE id = ?", (msg_id,))
                        row = await cur.fetchone()
                        if row and (row[0] == current_user or row[1] == current_user):
                            await db.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
                            await db.execute("DELETE FROM reactions WHERE target_type = 'msg' AND target_id = ?", (msg_id,))
                            await db.commit()
                            del_payload = json.dumps({"action": "msg_deleted", "id": msg_id})
                            if row[0] in online_users: await online_users[row[0]].send_str(del_payload)
                            if row[1] in online_users: await online_users[row[1]].send_str(del_payload)

                elif action == "get_channels" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT c.id, c.name, c.tag, c.description, c.owner, c.is_verified,
                            (SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = c.id) as subs_count,
                            EXISTS(SELECT 1 FROM channel_subscribers WHERE channel_id = c.id AND username = ?) as is_sub
                            FROM channels c
                        """, (current_user,))
                        rows = await cursor.fetchall()
                        ch_list = [{
                            "id": r[0], "name": r[1], "tag": r[2], "desc": r[3], "owner": r[4],
                            "verified": bool(r[5]), "subs": r[6], "is_sub": bool(r[7])
                        } for r in rows]
                    await ws.send_str(json.dumps({"action": "channels_list", "items": ch_list}))

                elif action == "create_channel" and current_user:
                    name = data.get("name", "").strip()
                    tag = data.get("tag", "").strip().lower().replace("@", "")
                    desc = data.get("desc", "").strip()
                    if not name or not tag: continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cur = await db.execute("SELECT id FROM channels WHERE tag = ?", (tag,))
                        if await cur.fetchone():
                            await ws.send_str(json.dumps({"action": "toast", "msg": "Тег канала занят!"}))
                            continue
                        cur = await db.execute("SELECT is_admin FROM users WHERE username = ?", (current_user,))
                        u_adm = await cur.fetchone()
                        chan_ver = 1 if (u_adm and u_adm[0] == 1) else 0

                        cur = await db.execute("INSERT INTO channels (name, tag, description, owner, is_verified) VALUES (?, ?, ?, ?, ?)", (name, tag, desc, current_user, chan_ver))
                        ch_id = cur.lastrowid
                        await db.execute("INSERT INTO channel_subscribers (channel_id, username) VALUES (?, ?)", (ch_id, current_user))
                        await db.commit()
                    await ws.send_str(json.dumps({"action": "channel_created", "id": ch_id, "tag": tag}))

                elif action == "subscribe_channel" and current_user:
                    ch_id = data.get("channel_id")
                    async with aiosqlite.connect(DB_NAME) as db:
                        cur = await db.execute("SELECT 1 FROM channel_subscribers WHERE channel_id = ? AND username = ?", (ch_id, current_user))
                        if await cur.fetchone():
                            await db.execute("DELETE FROM channel_subscribers WHERE channel_id = ? AND username = ?", (ch_id, current_user))
                            status = False
                        else:
                            await db.execute("INSERT INTO channel_subscribers (channel_id, username) VALUES (?, ?)", (ch_id, current_user))
                            status = True
                        await db.commit()
                        cur = await db.execute("SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = ?", (ch_id,))
                        count = (await cur.fetchone())[0]
                    await ws.send_str(json.dumps({"action": "sub_status", "channel_id": ch_id, "is_sub": status, "count": count}))

                elif action == "get_channel_posts" and current_user:
                    ch_id = data.get("channel_id")
                    async with aiosqlite.connect(DB_NAME) as db:
                        cur = await db.execute("SELECT id, sender, text, media_type, media_data, is_spoiler, strftime('%H:%M', timestamp) FROM channel_posts WHERE channel_id = ? ORDER BY id ASC", (ch_id,))
                        rows = await cur.fetchall()
                        posts = []
                        for r in rows:
                            reacts = await get_reactions(db, "post", r[0])
                            posts.append({
                                "id": r[0], "sender": r[1], "text": r[2], "media_type": r[3],
                                "media_data": r[4], "is_spoiler": bool(r[5]), "time": r[6], "reactions": reacts
                            })
                    await ws.send_str(json.dumps({"action": "channel_history", "channel_id": ch_id, "items": posts}))

                elif action == "post_to_channel" and current_user:
                    ch_id = data.get("channel_id")
                    text = data.get("text", "").strip()
                    media_type = data.get("media_type", "text")
                    media_data = data.get("media_data", "")
                    is_spoiler = 1 if data.get("is_spoiler") else 0
                    if not text and not media_data: continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cur = await db.execute("SELECT owner FROM channels WHERE id = ?", (ch_id,))
                        row = await cur.fetchone()
                        if not row or row[0] != current_user: continue
                        cur = await db.execute("""
                            INSERT INTO channel_posts (channel_id, sender, text, media_type, media_data, is_spoiler) 
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (ch_id, current_user, text, media_type, media_data, is_spoiler))
                        await db.commit()
                        p_id = cur.lastrowid
                        cur = await db.execute("SELECT strftime('%H:%M', timestamp) FROM channel_posts WHERE id = ?", (p_id,))
                        p_time = (await cur.fetchone())[0]
                        cur = await db.execute("SELECT username FROM channel_subscribers WHERE channel_id = ?", (ch_id,))
                        subscribers = [r[0] for r in await cur.fetchall()]

                    payload = json.dumps({
                        "action": "new_post", "channel_id": ch_id, "id": p_id, "sender": current_user,
                        "text": text, "media_type": media_type, "media_data": media_data, "is_spoiler": bool(is_spoiler),
                        "time": p_time, "reactions": []
                    })
                    for s in subscribers:
                        if s in online_users: await online_users[s].send_str(payload)

    finally:
        if current_user and current_user in online_users:
            del online_users[current_user]
            off_payload = json.dumps({"action": "user_status", "username": current_user, "online": False})
            for client in online_users.values():
                if not client.closed: asyncio.create_task(client.send_str(off_payload))
    return ws

async def make_app():
    await init_db()
    asyncio.create_task(auto_cleaner_task())
    app = web.Application(client_max_size=60*1024*1024)
    app.router.add_get('/', index_handler)
    app.router.add_get('/ws', ws_handler)
    return app

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    print(f"💎 MyGram Ultra запущен: http://127.0.0.1:{port}")
    web.run_app(make_app(), host='0.0.0.0', port=port)
