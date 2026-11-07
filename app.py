import json
import os
import hashlib
import secrets
import smtplib
import asyncio
from email.message import EmailMessage
import aiosqlite
from aiohttp import web

# Имя файла локальной базы данных
DB_NAME = "tg_database.db"

# Словарь активных WebSocket-подключений: {username: ws}
online_users = {}

# Параметры почтового сервера Gmail SMTP
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = os.environ.get("SMTP_EMAIL", "lol52alo228@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "pkkozadhwncdqltr")

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    """Хэширование пароля алгоритмом SHA-256 с солью."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return hashed, salt

def send_smtp_code(to_email: str, code: str) -> bool:
    """Отправка 6-значного пин-кода подтверждения на почту Gmail."""
    try:
        msg = EmailMessage()
        msg["Subject"] = f"{code} — код подтверждения MyGram"
        msg["From"] = SMTP_EMAIL
        msg["To"] = to_email
        msg.set_content(
            f"Ваш проверочный код для входа в MyGram: {code}\n\n"
            f"Никогда и никому не передавайте этот код."
        )

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as error:
        print(f"[Ошибка отправки почты SMTP]: {error}")
        return False

async def init_db():
    """Инициализация таблиц базы данных SQLite."""
    async with aiosqlite.connect(DB_NAME) as db:
        # Таблица зарегистрированных пользователей
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                session_token TEXT UNIQUE
            )
        """)
        # Таблица временных заявок на регистрацию до ввода кода
        await db.execute("""
            CREATE TABLE IF NOT EXISTS pending_verifications (
                email TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                code TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
                owner TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0
            )
        """)
        # Таблица подписчиков каналов
        await db.execute("""
            CREATE TABLE IF NOT EXISTS channel_subscribers (
                channel_id INTEGER,
                username TEXT,
                PRIMARY KEY (channel_id, username)
            )
        """)
        # Таблица публикаций каналов
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
    """Отдача главного HTML-интерфейса."""
    return web.FileResponse('static/index.html')

async def ws_handler(request):
    """Обработчик интерактивных WebSocket-соединений."""
    ws = web.WebSocketResponse(max_msg_size=10*1024*1024)
    await ws.prepare(request)
    current_user = None

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                data = json.loads(msg.data)
                action = data.get("action")

                # Проверка ранее сохранённого токена сессии
                if action == "auth_by_token":
                    token = data.get("token", "").strip()
                    if not token:
                        await ws.send_str(json.dumps({"action": "require_login"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute(
                            "SELECT username, is_verified, is_admin FROM users WHERE session_token = ?",
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
                                "token": token
                            }))
                        else:
                            await ws.send_str(json.dumps({"action": "require_login"}))

                # Авторизация по логину/почте и паролю
                elif action == "login":
                    identifier = data.get("identifier", "").strip().lower()
                    password = data.get("password", "")

                    if not identifier or not password:
                        await ws.send_str(json.dumps({"action": "auth_error", "msg": "Заполните все поля!"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT username, password_hash, password_salt, is_verified, is_admin 
                            FROM users WHERE username = ? OR email = ?
                        """, (identifier, identifier))
                        row = await cursor.fetchone()

                        if not row:
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Неверный логин или пароль!"}))
                            continue

                        uname, real_hash, salt, is_ver, is_adm = row
                        test_hash, _ = hash_password(password, salt)

                        if test_hash != real_hash:
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Неверный логин или пароль!"}))
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
                        "token": session_token
                    }))

                # Заявка на регистрацию и генерация проверочного кода
                elif action == "register_request":
                    username = data.get("username", "").strip().lower()
                    email = data.get("email", "").strip().lower()
                    password = data.get("password", "")

                    if not username or not email or not password:
                        await ws.send_str(json.dumps({"action": "auth_error", "msg": "Заполните логин, email и пароль!"}))
                        continue

                    if len(password) < 6:
                        await ws.send_str(json.dumps({"action": "auth_error", "msg": "Пароль должен состоять минимум из 6 символов!"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT id FROM users WHERE username = ?", (username,))
                        if await cursor.fetchone():
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Этот никнейм уже занят!"}))
                            continue

                        cursor = await db.execute("SELECT id FROM users WHERE email = ?", (email,))
                        if await cursor.fetchone():
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Email уже привязан к другому аккаунту!"}))
                            continue

                        p_hash, p_salt = hash_password(password)
                        code = f"{secrets.randbelow(900000) + 100000}"

                        await db.execute("""
                            INSERT OR REPLACE INTO pending_verifications (email, username, password_hash, password_salt, code)
                            VALUES (?, ?, ?, ?, ?)
                        """, (email, username, p_hash, p_salt, code))
                        await db.commit()

                    # Отправка письма в фоновом потоке
                    loop = asyncio.get_running_loop()
                    ok = await loop.run_in_executor(None, send_smtp_code, email, code)
                    if ok:
                        await ws.send_str(json.dumps({"action": "code_sent", "email": email}))
                    else:
                        await ws.send_str(json.dumps({
                            "action": "auth_error",
                            "msg": "Ошибка отправки письма. Проверьте правильность почты или настройки почтового сервера."
                        }))

                # Проверка кода и создание профиля
                elif action == "verify_code":
                    email = data.get("email", "").strip().lower()
                    code = data.get("code", "").strip()

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute(
                            "SELECT username, password_hash, password_salt, code FROM pending_verifications WHERE email = ?",
                            (email,)
                        )
                        row = await cursor.fetchone()

                        if not row or row[3] != code:
                            await ws.send_str(json.dumps({"action": "auth_error", "msg": "Неверный код из письма!"}))
                            continue

                        uname, p_hash, p_salt, _ = row
                        
                        # Первый зарегистрированный аккаунт автоматически становится Создателем
                        cursor = await db.execute("SELECT COUNT(*) FROM users")
                        is_first = (await cursor.fetchone())[0] == 0
                        is_adm = 1 if is_first else 0
                        is_ver = 1 if is_first else 0
                        session_token = secrets.token_hex(32)

                        await db.execute("""
                            INSERT INTO users (username, email, password_hash, password_salt, is_verified, is_admin, session_token)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (uname, email, p_hash, p_salt, is_ver, is_adm, session_token))
                        await db.execute("DELETE FROM pending_verifications WHERE email = ?", (email,))
                        await db.commit()

                    current_user = uname
                    online_users[current_user] = ws
                    await ws.send_str(json.dumps({
                        "action": "auth_success",
                        "username": uname,
                        "verified": bool(is_ver),
                        "is_admin": bool(is_adm),
                        "token": session_token
                    }))

                # Создание нового канала
                elif action == "create_channel" and current_user:
                    name = data.get("name", "").strip()
                    tag = data.get("tag", "").strip().lower().replace("@", "")
                    desc = data.get("desc", "").strip()
                    avatar = data.get("avatar", "")

                    if not name or not tag:
                        await ws.send_str(json.dumps({"action": "toast", "msg": "Укажите название и уникальный тег канала!"}))
                        continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT id FROM channels WHERE tag = ?", (tag,))
                        if await cursor.fetchone():
                            await ws.send_str(json.dumps({"action": "toast", "msg": "Тег @ уже кем-то занят!"}))
                            continue

                        # Если канал создает админ, сразу выдается галочка верификации
                        cursor = await db.execute("SELECT is_admin FROM users WHERE username = ?", (current_user,))
                        u_adm = await cursor.fetchone()
                        chan_verified = 1 if (u_adm and u_adm[0] == 1) else 0

                        cursor = await db.execute(
                            "INSERT INTO channels (name, tag, description, avatar, owner, is_verified) VALUES (?, ?, ?, ?, ?, ?)",
                            (name, tag, desc, avatar, current_user, chan_verified)
                        )
                        ch_id = cursor.lastrowid
                        await db.execute("INSERT INTO channel_subscribers (channel_id, username) VALUES (?, ?)", (ch_id, current_user))
                        await db.commit()

                    await ws.send_str(json.dumps({"action": "channel_created", "id": ch_id, "tag": tag}))

                # Получение списка каналов
                elif action == "get_channels" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT c.id, c.name, c.tag, c.description, c.avatar, c.owner, c.is_verified,
                            (SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = c.id) as subs_count,
                            EXISTS(SELECT 1 FROM channel_subscribers WHERE channel_id = c.id AND username = ?) as is_sub
                            FROM channels c
                        """, (current_user,))
                        rows = await cursor.fetchall()
                        ch_list = [{
                            "id": r[0], "name": r[1], "tag": r[2], "desc": r[3],
                            "avatar": r[4], "owner": r[5], "verified": bool(r[6]),
                            "subs": r[7], "is_sub": bool(r[8])
                        } for r in rows]
                    await ws.send_str(json.dumps({"action": "channels_list", "items": ch_list}))

                # Подписка / отписка от канала
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

                # Получение публикаций канала
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

                # Публикация нового поста в канале
                elif action == "post_to_channel" and current_user:
                    ch_id = data.get("channel_id")
                    text = data.get("text", "").strip()
                    if not text: continue

                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("SELECT owner FROM channels WHERE id = ?", (ch_id,))
                        row = await cursor.fetchone()
                        if not row or row[0] != current_user:
                            await ws.send_str(json.dumps({"action": "toast", "msg": "Только владелец канала может публиковать записи!"}))
                            continue

                        cursor = await db.execute("INSERT INTO channel_posts (channel_id, sender, text) VALUES (?, ?, ?)", (ch_id, current_user, text))
                        await db.commit()
                        p_id = cursor.lastrowid
                        cursor = await db.execute("SELECT strftime('%H:%M', timestamp) FROM channel_posts WHERE id = ?", (p_id,))
                        p_time = (await cursor.fetchone())[0]

                        cursor = await db.execute("SELECT username FROM channel_subscribers WHERE channel_id = ?", (ch_id,))
                        subscribers = [r[0] for r in await cursor.fetchall()]

                    post_payload = json.dumps({"action": "new_post", "channel_id": ch_id, "id": p_id, "sender": current_user, "text": text, "time": p_time})
                    for sub in subscribers:
                        if sub in online_users:
                            await online_users[sub].send_str(post_payload)

                # Получение списка личных диалогов
                elif action == "get_chats" and current_user:
                    async with aiosqlite.connect(DB_NAME) as db:
                        cursor = await db.execute("""
                            SELECT DISTINCT CASE WHEN sender = ? THEN recipient ELSE sender END as chat_peer
                            FROM messages WHERE sender = ? OR recipient = ?
                        """, (current_user, current_user, current_user))
                        peer_names = [r[0] for r in await cursor.fetchall()]
                        chats = []
                        for peer in peer_names:
                            p_cur = await db.execute("SELECT username, is_verified FROM users WHERE username = ?", (peer,))
                            p_row = await p_cur.fetchone()
                            if p_row:
                                chats.append({"username": p_row[0], "verified": bool(p_row[1])})
                    await ws.send_str(json.dumps({"action": "chat_list", "items": chats}))

                # История переписки с собеседником
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

                # Отправка личного сообщения
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
        # Удаление отключившегося пользователя из списка онлайн
        if current_user and current_user in online_users:
            del online_users[current_user]
    return ws

async def make_app():
    """Сборка приложения aiohttp."""
    await init_db()
    app = web.Application(client_max_size=10*1024*1024)
    app.router.add_get('/', index_handler)
    app.router.add_get('/ws', ws_handler)
    return app

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    print(f"[Запуск сервера MyGram] Порт: {port}")
    web.run_app(make_app(), host='0.0.0.0', port=port)