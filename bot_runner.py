"""CortenBots runner sidecar — spawned by server.js (Node) per Telegram bot.

Usage:  python3 -I bot_runner.py <token> <templateId> <botId>

It imports bot_engine (aiogram dispatchers for support/shop/quiz/sub) and runs
long-polling for ONE bot. The Node app spawns this on /api/cb-create and on
toggle-on, and kills it on toggle-off / delete. Trial/expiry is controlled by
the Node app (it only spawns the runner while the bot is active & not expired),
so we patch bot_engine.check_trial to always pass here. If `aiogram` is not
installed, this exits non-zero and the bot simply stays in status-only mode
(the cortencloud management UI still works).
"""
import asyncio
import hashlib
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
log = logging.getLogger("cb-runner")

# cortencloud template ids -> bot_engine template keys (support/shop/quiz/sub)
TPL_MAP = {"cafe": "shop", "shop": "shop", "quiz": "quiz", "help": "support",
           "support": "support", "sub": "sub", "subscribe": "sub"}


def main():
    if len(sys.argv) < 4:
        print("usage: bot_runner.py <token> <templateId> <botId>", file=sys.stderr)
        sys.exit(2)
    token, template_raw, bot_id = sys.argv[1], sys.argv[2], sys.argv[3]
    template = TPL_MAP.get(template_raw, template_raw)
    if template not in {"support", "shop", "quiz", "sub"}:
        print(f"unknown template: {template_raw}", file=sys.stderr)
        sys.exit(2)

    from aiogram import Bot
    from db import init_db
    import bot_engine

    init_db()  # ensure SQLite tables exist for shop/orders/tickets/quiz data

    # trial/expiry is enforced by the Node app; the bot just runs while alive here
    async def _trial_ok(message, td):
        return True
    bot_engine.check_trial = _trial_ok

    async def run():
        bot = Bot(token=token)
        await bot.delete_webhook(drop_pending_updates=True)
        td = hashlib.sha256(token.encode("utf-8")).hexdigest()
        dp = build_dispatcher_safe(bot_engine, token, template, bot_id, td)
        log.info("cortenbot started: bot_id=%s template=%s", bot_id, template)
        await dp.start_polling(bot, handle_signals=False, close_bot_session=True)

    asyncio.run(run())


def build_dispatcher_safe(be, token, template, bot_id, td):
    """Wrap build_dispatcher so a failure in one handler never crashes polling."""
    dp = be.build_dispatcher(token, template, int(bot_id), td)
    return dp


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except ModuleNotFoundError as e:
        print(f"missing dependency: {e.name} (pip install aiogram)", file=sys.stderr)
        sys.exit(3)
