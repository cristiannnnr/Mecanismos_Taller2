"""
Bot de Telegram para compartir ubicación — Taller 2 Mecanismos de Seguridad
Universidad Distrital FJDC

El usuario debe iniciar el bot y dar consentimiento explícito.
El bot NO rastraea automáticamente; solo registra la ubicación cuando el usuario
la comparte voluntariamente mediante el botón interactivo.
"""
import logging
import os
import httpx
from dotenv import load_dotenv
from telegram import (
    Update,
    KeyboardButton,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "REEMPLAZAR_CON_TOKEN_DE_BOTFATHER")
API_BASE = os.getenv("API_BASE", "http://localhost:8000")

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Estados de conversación
WAITING_PHONE, WAITING_OTP, TRACKING = range(3)

# Almacenamiento temporal de sesión por chat_id (en producción usar Redis/DB)
sessions: dict[int, dict] = {}


CONSENT_TEXT = (
    "⚠️ *Aviso de privacidad*\n\n"
    "Este bot registrará tu ubicación *únicamente* cuando tú la compartas "
    "usando el botón de localización. No existe rastreo automático sin tu acción.\n\n"
    "Los datos se almacenan en el servidor académico del laboratorio "
    "y pueden eliminarse en cualquier momento con /revocar.\n\n"
    "¿Aceptas los términos y deseas continuar?\n"
    "Responde /aceptar para continuar o /cancelar para salir."
)


# ── /start ────────────────────────────────────────────────────────────────────
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(CONSENT_TEXT, parse_mode="Markdown")
    return WAITING_PHONE


# ── /aceptar → pide número ───────────────────────────────────────────────────
async def cmd_accept(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    btn = KeyboardButton("📱 Compartir mi número", request_contact=True)
    markup = ReplyKeyboardMarkup([[btn]], one_time_keyboard=True, resize_keyboard=True)
    await update.message.reply_text(
        "Perfecto. Comparte tu número de teléfono para registrarte:",
        reply_markup=markup,
    )
    return WAITING_PHONE


# ── Recibe contacto → llama a /auth/register ─────────────────────────────────
async def received_contact(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    contact = update.message.contact
    phone = contact.phone_number
    if not phone.startswith("+"):
        phone = "+" + phone

    chat_id = update.message.chat_id
    sessions[chat_id] = {"phone": phone, "token": None}

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{API_BASE}/auth/register",
            json={"phone": phone, "consent_accepted": True},
        )

    if resp.status_code == 200:
        data = resp.json()
        await update.message.reply_text(
            f"✅ Número registrado: `{phone}`\n\n"
            f"Te enviamos un código OTP. Escríbelo aquí:\n"
            f"_(Demo académica: `{data.get('otp_demo', '------')}`)_",
            parse_mode="Markdown",
            reply_markup=ReplyKeyboardRemove(),
        )
        return WAITING_OTP
    else:
        await update.message.reply_text(
            "❌ Error al registrar. Intenta con /start de nuevo.",
            reply_markup=ReplyKeyboardRemove(),
        )
        return ConversationHandler.END


# ── Recibe OTP ────────────────────────────────────────────────────────────────
async def received_otp(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    otp = update.message.text.strip()
    chat_id = update.message.chat_id
    session = sessions.get(chat_id)

    if not session:
        await update.message.reply_text("Sesión expirada. Usa /start.")
        return ConversationHandler.END

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{API_BASE}/auth/verify",
            json={"phone": session["phone"], "otp": otp},
        )

    if resp.status_code == 200:
        data = resp.json()
        sessions[chat_id]["token"] = data["access_token"]

        btn_location = KeyboardButton("📍 Compartir mi ubicación", request_location=True)
        btn_history = KeyboardButton("📋 Ver historial")
        btn_stop = KeyboardButton("⛔ Detener rastreo")
        markup = ReplyKeyboardMarkup(
            [[btn_location], [btn_history, btn_stop]],
            resize_keyboard=True,
        )
        await update.message.reply_text(
            "🎉 ¡Verificado! Puedes compartir tu ubicación cuando quieras.\n"
            "Usa los botones de abajo. Recuerda: sólo se registra cuando tú la envías.",
            reply_markup=markup,
        )
        return TRACKING
    else:
        await update.message.reply_text("❌ OTP inválido. Intenta de nuevo:")
        return WAITING_OTP


# ── Recibe ubicación ──────────────────────────────────────────────────────────
async def received_location(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.message.chat_id
    session = sessions.get(chat_id)

    if not session or not session.get("token"):
        await update.message.reply_text("Sesión expirada. Usa /start.")
        return ConversationHandler.END

    loc = update.message.location
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{API_BASE}/location/update",
            json={
                "latitude": loc.latitude,
                "longitude": loc.longitude,
                "accuracy_meters": None,
                "source": "telegram_bot",
            },
            headers={"Authorization": f"Bearer {session['token']}"},
        )

    if resp.status_code == 200:
        await update.message.reply_text(
            f"✅ Ubicación registrada:\n"
            f"`{loc.latitude:.6f}, {loc.longitude:.6f}`\n\n"
            f"Envía otra cuando quieras o usa /revocar para borrar tus datos.",
            parse_mode="Markdown",
        )
    else:
        await update.message.reply_text("❌ Error al registrar la ubicación.")

    return TRACKING


# ── Ver historial ─────────────────────────────────────────────────────────────
async def show_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.message.chat_id
    session = sessions.get(chat_id)

    if not session or not session.get("token"):
        await update.message.reply_text("Sesión expirada. Usa /start.")
        return ConversationHandler.END

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{API_BASE}/location/history/{session['phone']}?limit=5",
            headers={"Authorization": f"Bearer {session['token']}"},
        )

    if resp.status_code == 200:
        data = resp.json()
        if data["total"] == 0:
            await update.message.reply_text("No tienes ubicaciones registradas aún.")
        else:
            lines = [f"📋 *Últimas {len(data['records'])} de {data['total']} ubicaciones:*\n"]
            for r in data["records"]:
                lines.append(f"• `{r['latitude']:.5f}, {r['longitude']:.5f}` — {r['recorded_at'][:16]}")
            await update.message.reply_text("\n".join(lines), parse_mode="Markdown")
    else:
        await update.message.reply_text("Error al obtener el historial.")

    return TRACKING


# ── /revocar ──────────────────────────────────────────────────────────────────
async def cmd_revoke(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    chat_id = update.message.chat_id
    session = sessions.get(chat_id)

    if not session or not session.get("token"):
        await update.message.reply_text("No hay sesión activa.")
        return ConversationHandler.END

    async with httpx.AsyncClient() as client:
        await client.delete(
            f"{API_BASE}/auth/revoke",
            headers={"Authorization": f"Bearer {session['token']}"},
        )

    sessions.pop(chat_id, None)
    await update.message.reply_text(
        "✅ Consentimiento revocado. Todos tus datos de ubicación han sido eliminados.\n"
        "Usa /start si deseas registrarte de nuevo.",
        reply_markup=ReplyKeyboardRemove(),
    )
    return ConversationHandler.END


# ── /cancelar ─────────────────────────────────────────────────────────────────
async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        "Operación cancelada.", reply_markup=ReplyKeyboardRemove()
    )
    return ConversationHandler.END


# ── /help ─────────────────────────────────────────────────────────────────────
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "*Comandos disponibles:*\n\n"
        "/start — Iniciar registro y dar consentimiento\n"
        "/revocar — Eliminar todos tus datos y revocar consentimiento\n"
        "/cancelar — Cancelar operación actual\n"
        "/help — Esta ayuda\n\n"
        "_Recuerda: tu ubicación solo se registra cuando tú la envías._",
        parse_mode="Markdown",
    )


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    app = Application.builder().token(BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[CommandHandler("start", cmd_start)],
        states={
            WAITING_PHONE: [
                CommandHandler("aceptar", cmd_accept),
                CommandHandler("cancelar", cmd_cancel),
                MessageHandler(filters.CONTACT, received_contact),
            ],
            WAITING_OTP: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, received_otp),
                CommandHandler("cancelar", cmd_cancel),
            ],
            TRACKING: [
                MessageHandler(filters.LOCATION, received_location),
                MessageHandler(
                    filters.Regex("^📋 Ver historial$"), show_history
                ),
                CommandHandler("revocar", cmd_revoke),
                CommandHandler("cancelar", cmd_cancel),
            ],
        },
        fallbacks=[CommandHandler("cancelar", cmd_cancel)],
    )

    app.add_handler(conv)
    app.add_handler(CommandHandler("revocar", cmd_revoke))
    app.add_handler(CommandHandler("help", cmd_help))

    logger.info("Bot iniciado. Esperando mensajes...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
