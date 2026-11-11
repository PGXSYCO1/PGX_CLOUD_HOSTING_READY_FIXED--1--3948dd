import os
import html
import sqlite3
import logging
from datetime import datetime, timezone

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ContextTypes, filters,
)

TOKEN = "9172745172:AAHWO7uoQFoUOSC6TjXrkD8cNc6iR8MlLwY"
OWNER_ID = 7145380245
DB_PATH = os.getenv("bot.db", "bot.db")

logging.basicConfig(level=logging.INFO)
db = sqlite3.connect(DB_PATH)

db.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    coins INTEGER NOT NULL DEFAULT 0,
    access_until INTEGER NOT NULL DEFAULT 0,
    referred_by INTEGER
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
""")

for key, value in {
    "refreward": 10,
    "unlockprice": 100,
    "duration": 30,
}.items():
    db.execute(
        "INSERT OR IGNORE INTO settings VALUES (?, ?)",
        (key, value),
    )
db.commit()


def setting(key):
    return db.execute(
        "SELECT value FROM settings WHERE key=?", (key,)
    ).fetchone()[0]


def user(uid):
    return db.execute(
        "SELECT id, coins, access_until, referred_by "
        "FROM users WHERE id=?", (uid,)
    ).fetchone()


def ensure_user(uid):
    db.execute("INSERT OR IGNORE INTO users(id) VALUES (?)", (uid,))
    db.commit()


def now():
    return int(datetime.now(timezone.utc).timestamp())


def allowed(uid):
    if uid == OWNER_ID:
        return True
    row = user(uid)
    return bool(row and (row[2] == -1 or row[2] > now()))


def expiry_text(value):
    if value == -1:
        return "Permanent"
    if value <= now():
        return "Locked / expired"
    return datetime.fromtimestamp(
        value, timezone.utc
    ).strftime("%d %b %Y, %H:%M UTC")


def extend_access(current, days):
    if days == 0 or current == -1:
        return -1
    return max(current, now()) + days * 86400


def markup(rows):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(label, callback_data=data)
         for label, data in row]
        for row in rows
    ])


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    fresh = user(uid) is None

    # Referral is credited only once: on a user's first /start.
    with db:
        if fresh:
            ref = None
            if context.args and context.args[0].startswith("ref_"):
                try:
                    candidate = int(context.args[0][4:])
                    if candidate != uid and user(candidate):
                        ref = candidate
                except ValueError:
                    pass

            db.execute(
                "INSERT INTO users(id, referred_by) VALUES (?, ?)",
                (uid, ref),
            )
            if ref:
                db.execute(
                    "UPDATE users SET coins=coins+? WHERE id=?",
                    (setting("refreward"), ref),
                )

    await update.message.reply_text(
        "Welcome ✨\n\n"
        "/compose — message style karo\n"
        "/balance — coins aur access\n"
        "/referral — apna invite link\n"
        "/unlock — coins se access lo\n"
        "/cancel — current action cancel\n"
        "/myid — apni Telegram ID"
    )


async def myid(update, context):
    await update.message.reply_text(str(update.effective_user.id))


async def balance(update, context):
    uid = update.effective_user.id
    ensure_user(uid)
    row = user(uid)
    access = "Owner" if uid == OWNER_ID else expiry_text(row[2])
    await update.message.reply_text(
        f"🪙 Coins: {row[1]}\n🔓 Access: {access}"
    )


async def referral(update, context):
    uid = update.effective_user.id
    ensure_user(uid)
    me = await context.bot.get_me()
    count = db.execute(
        "SELECT COUNT(*) FROM users WHERE referred_by=?", (uid,)
    ).fetchone()[0]
    await update.message.reply_text(
        f"🔗 https://t.me/{me.username}?start=ref_{uid}\n\n"
        f"Reward: {setting('refreward')} coins per new user\n"
        f"Referrals: {count}\n\n"
        "Self-referral aur repeat /start par reward nahi milta."
    )


async def unlock(update, context):
    uid = update.effective_user.id
    ensure_user(uid)

    if allowed(uid):
        await update.message.reply_text(
            "Tumhara access already active hai. /compose bhejo."
        )
        return

    days = setting("duration")
    duration = "Permanent" if days == 0 else f"{days} din"
    await update.message.reply_text(
        f"🔓 Access: {duration}\n"
        f"🪙 Price: {setting('unlockprice')} coins\n\n"
        "Confirm karke coins spend karo.",
        reply_markup=markup([
            [("✅ Unlock", "buy"), ("❌ Cancel", "dismiss")]
        ]),
    )


# Unicode fonts work mainly for English letters and numbers.
def fancy(text, style):
    bases = {
        "bold": (0x1D400, 0x1D41A, 0x1D7CE),
        "italic": (0x1D434, 0x1D44E, None),
        "mono": (0x1D670, 0x1D68A, 0x1D7F6),
    }
    upper, lower, digits = bases[style]
    result = []
    for ch in text:
        if style == "italic" and ch == "h":
            result.append("ℎ")
        elif "A" <= ch <= "Z":
            result.append(chr(upper + ord(ch) - ord("A")))
        elif "a" <= ch <= "z":
            result.append(chr(lower + ord(ch) - ord("a")))
        elif "0" <= ch <= "9" and digits:
            result.append(chr(digits + ord(ch) - ord("0")))
        else:
            result.append(ch)
    return "".join(result)


def render(context):
    draft = context.user_data["draft"]
    text = context.user_data["text"]

    if draft["font"] != "normal":
        text = fancy(text, draft["font"])

    if draft["border"]:
        text = f"╔══════════════╗\n{text}\n╚══════════════╝"

    text = html.escape(text)

    if draft["bold"]:
        text = f"<b>{text}</b>"
    if draft["spoiler"]:
        text = f"<tg-spoiler>{text}</tg-spoiler>"
    if draft["quote"]:
        text = f"<blockquote>{text}</blockquote>"

    return text


def style_keyboard(context):
    d = context.user_data["draft"]

    def flag(name):
        return "✅" if d[name] else "⬜"

    return markup([
        [("Normal", "font:normal"), ("𝗕𝗼𝗹𝗱", "font:bold")],
        [("𝘐𝘵𝘢𝘭𝘪𝘤", "font:italic"), ("Mono", "font:mono")],
        [(f"{flag('quote')} Quote", "toggle:quote"),
         (f"{flag('border')} Border", "toggle:border")],
        [(f"{flag('bold')} Bold", "toggle:bold"),
         (f"{flag('spoiler')} Spoiler", "toggle:spoiler")],
        [("✅ Done", "done"), ("❌ Cancel", "dismiss")],
    ])


async def compose(update, context):
    if not allowed(update.effective_user.id):
        await update.message.reply_text(
            "Pehle access unlock karo: /unlock\n"
            "Coins earn karne ke liye: /referral"
        )
        return
    context.user_data.clear()
    context.user_data["mode"] = "compose"
    await update.message.reply_text(
        "✍️ Apna text bhejo (maximum 1500 characters)."
    )


ADMIN_ACTIONS = {
    "setrefreward": ("Referral reward", "Amount bhejo, jaise: 10"),
    "setunlockprice": ("Unlock price", "Price bhejo, jaise: 100"),
    "setduration": ("Access duration", "Days bhejo. 0 = permanent"),
    "addcoins":("Coins dena", "USER_ID AMOUNT bhejo"),
    "removecoins": ("Coins hatana", "USER_ID AMOUNT bhejo"),
    "userinfo": ("User details", "USER_ID bhejo"),
    "grantaccess": ("Access dena", "USER_ID DAYS bhejo. 0 = permanent"),
    "revokeaccess": ("Access hatana", "USER_ID bhejo"),
}


async def admin_panel(update, context):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("⛔ Owner only.")
        return

    rows = [
        [(title, f"admin:{action}")]
        for action, (title, _) in ADMIN_ACTIONS.items()
    ]
    total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    await update.message.reply_text(
        f"👑 Admin Panel\n\n"
        f"Users: {total}\n"
        f"Referral reward: {setting('refreward')}\n"
        f"Unlock price: {setting('unlockprice')}\n"
        f"Duration: {setting('duration')} days (0 = permanent)",
        reply_markup=markup(rows),
    )


def execute_admin(action, raw):
    parts = raw.split()
    settings_map = {
        "setrefreward": "refreward",
        "setunlockprice": "unlockprice",
        "setduration": "duration",
    }

    if action in settings_map:
        if len(parts) != 1:
            raise ValueError("Ek non-negative number bhejo.")
        value = int(parts[0])
        if value < 0:
            raise ValueError("Negative value allowed nahi hai.")
        with db:
            db.execute(
                "UPDATE settings SET value=? WHERE key=?",
                (value, settings_map[action]),
            )
        return "✅ Setting updated."

    expected = 2 if action in {
        "addcoins", "removecoins", "grantaccess"
    } else 1

    if len(parts) != expected:
        raise ValueError(ADMIN_ACTIONS[action][1])

    uid = int(parts[0])
    row = user(uid)
    if not row:
        raise ValueError("User ko pehle bot par /start karna hoga.")

    amount = int(parts[1]) if expected == 2 else 0
    if amount < 0:
        raise ValueError("Negative value allowed nahi hai.")

    with db:
        if action == "addcoins":
            db.execute(
                "UPDATE users SET coins=coins+? WHERE id=?", (amount, uid)
            )
        elif action == "removecoins":
            if amount > row[1]:
                raise ValueError("User ke paas itne coins nahi hain.")
            db.execute(
                "UPDATE users SET coins=coins-? WHERE id=?", (amount, uid)
            )
        elif action == "grantaccess":
            db.execute(
                "UPDATE users SET access_until=? WHERE id=?",
                (extend_access(row[2], amount), uid),
            )
        elif action == "revokeaccess":
            db.execute(
                "UPDATE users SET access_until=0 WHERE id=?", (uid,)
            )
        elif action == "userinfo":
            count = db.execute(
                "SELECT COUNT(*) FROM users WHERE referred_by=?", (uid,)
            ).fetchone()[0]
            return (
                f"ID: {uid}\nCoins: {row[1]}\n"
                f"Access: {expiry_text(row[2])}\nReferrals: {count}"
            )

    return f"✅ Updated user {uid}."


async def admin_command(update, context):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("⛔ Owner only.")
        return

    action = update.message.text.split()[0][1:].split("@")[0]
    if not context.args:
        context.user_data["mode"] = f"admin:{action}"
        await update.message.reply_text(ADMIN_ACTIONS[action][1])
        return

    try:
        result = execute_admin(action, " ".join(context.args))
    except ValueError as exc:
        result = f"❌ {exc}"
    await update.message.reply_text(result)


async def text_message(update, context):
    mode = context.user_data.get("mode", "")

    if mode.startswith("admin:"):
        if update.effective_user.id != OWNER_ID:
            return

        try:
            result = execute_admin(
                mode.split(":")[1],
                update.message.text,
            )
        except ValueError as exc:
            await update.message.reply_text(f"❌ {exc}")
            return

        context.user_data.pop("mode", None)
        await update.message.reply_text(result)
        return

    if mode == "compose":
        if not allowed(update.effective_user.id):
            await update.message.reply_text(
                "Access expire ho gaya. /unlock"
            )
            return

        text = update.message.text

        if len(text) > 1500:
            await update.message.reply_text(
                "Maximum 1500 characters bhejo."
            )
            return

        context.user_data["text"] = text
        context.user_data["draft"] = {
            "font": "normal",
            "quote": False,
            "border": False,
            "bold": False,
            "spoiler": False,
        }
        context.user_data["mode"] = "styling"

        await update.message.reply_text(
            render(context),
            parse_mode=ParseMode.HTML,
            reply_markup=style_keyboard(context),
        )
        return

    await update.message.reply_text(
        "Message banane ke liye /compose bhejo."
    )


async def callback(update, context):
    q = update.callback_query
    uid = update.effective_user.id
    data = q.data

    if data == "dismiss":
        context.user_data.clear()
        await q.answer()
        await q.edit_message_text("Cancelled. /compose se dobara shuru karo.")
        return

    if data.startswith("admin:"):
        if uid != OWNER_ID:
            await q.answer("Owner only.", show_alert=True)
            return
        await q.answer()
        context.user_data["mode"] = data
        await q.message.reply_text(
            ADMIN_ACTIONS[data.split(":")[1]][1]
        )
        return

    if data == "buy":
        ensure_user(uid)
        if allowed(uid):
            await q.answer("Access already active hai.", show_alert=True)
            return

        price = setting("unlockprice")
        days = setting("duration")
        with db:
            changed = db.execute(
                "UPDATE users SET coins=coins-? WHERE id=? AND coins>=?",
                (price, uid, price),
            ).rowcount
            if changed:
                db.execute(
                    "UPDATE users SET access_until=? WHERE id=?",
                    (extend_access(user(uid)[2], days), uid),
                )

        if not changed:
            await q.answer("Coins kam hain. /referral use karo.", show_alert=True)
            return

        await q.answer()
        await q.edit_message_text("✅ Access unlocked! Ab /compose bhejo.")
        return

    if not allowed(uid):
        await q.answer("Pehle /unlock karo.", show_alert=True)
        return

    if "draft" not in context.user_data:
        await q.answer("Naya draft banao: /compose", show_alert=True)
        return

    if data == "done":
        await q.answer()
        await q.message.reply_text(
            render(context), parse_mode=ParseMode.HTML
        )
        await q.edit_message_reply_markup(reply_markup=None)
        context.user_data.clear()
        return

    if data.startswith("font:"):
        font = data.split(":")[1]
        if font not in {"normal", "bold", "italic", "mono"}:
            await q.answer()
            return
        if context.user_data["draft"]["font"] == font:
            await q.answer("Already selected.")
            return
        context.user_data["draft"]["font"] = font

    elif data.startswith("toggle:"):
        key = data.split(":")[1]
        if key not in {"quote", "border", "bold", "spoiler"}:
            await q.answer()
            return
        d = context.user_data["draft"]
        d[key] = not d[key]
    else:
        await q.answer()
        return

    await q.answer()
    await q.edit_message_text(
        render(context),
        parse_mode=ParseMode.HTML,
        reply_markup=style_keyboard(context),
    )


async def cancel(update, context):
    context.user_data.clear()
    await update.message.reply_text("✅ Cancelled.")


def main():
    app = Application.builder().token(TOKEN).build()

    for name, handler in {
        "start": start,
        "myid": myid,
        "balance": balance,
        "referral": referral,
        "unlock": unlock,
        "compose": compose,
        "cancel": cancel,
        "admincommnds": admin_panel,
        "admincommands": admin_panel,
    }.items():
        app.add_handler(CommandHandler(name, handler))

    for name in ADMIN_ACTIONS:
        app.add_handler(CommandHandler(name, admin_command))

    app.add_handler(CallbackQueryHandler(callback))
    app.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND, text_message
    ))

    app.run_polling()


if __name__ == "__main__":
    main()