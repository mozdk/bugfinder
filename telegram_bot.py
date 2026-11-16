"""
Telegram Bot for Cybersecurity Website Scanning
"""
import os
import re
import sys
import logging
import asyncio
from typing import Optional, List

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes
from telegram.ext.filters import TEXT, COMMAND

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analysis.full_site_scanner import FullSiteScanner

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

class CyberSecurityTelegramBot:
    def __init__(self, token: str, scanner: Optional[FullSiteScanner] = None):
        self.token = token
        self.scanner = scanner or FullSiteScanner()
        self.is_scanning = False
        self.Filters = type('Filters', (), {'TEXT': TEXT, 'COMMAND': COMMAND})()

    def extract_url(self, text: str) -> Optional[str]:
        url_pattern = r'(https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[\w\-._~:/?#[\]@!$&()*+,;=]+)'
        match = re.search(url_pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
        domain_pattern = r'(?:^|\s)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)(?:$|\s|/)'
        match = re.search(domain_pattern, text, re.IGNORECASE)
        if match:
            return f"https://{match.group(1)}"
        return None

    def normalize_domain(self, url: str) -> str:
        url = url.strip()
        if not url.startswith('http://') and not url.startswith('https://'):
            url = f'https://{url}'
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain

    def format_report_for_telegram(self, report: str, max_length: int = 4000) -> List[str]:
        chunks = []
        lines = report.split('\n')
        current_chunk = ""
        for line in lines:
            if len(current_chunk) + len(line) + 1 <= max_length:
                current_chunk = f"{current_chunk}\n{line}" if current_chunk else line
            else:
                if current_chunk:
                    chunks.append(current_chunk)
                current_chunk = line
        if current_chunk:
            chunks.append(current_chunk)
        return chunks

    def generate_summary(self, scan_result) -> str:
        high_count = len([v for v in scan_result.vulnerabilities if v.severity == "HIGH"])
        medium_count = len([v for v in scan_result.vulnerabilities if v.severity == "MEDIUM"])
        low_count = len([v for v in scan_result.vulnerabilities if v.severity == "LOW"])
        alive_subdomains = len([s for s in scan_result.subdomains if s.is_alive])
        return f"""📋 *Scan Summary*
🎯 Target: {scan_result.target_domain}
⏱️ Duration: {(scan_result.scan_end - scan_result.scan_start).total_seconds():.2f}s
📊 Results:
• Vulnerabilities: {len(scan_result.vulnerabilities)} (🔴{high_count} 🟡{medium_count} 🟢{low_count})
• Subdomains: {alive_subdomains} alive
• Endpoints: {len(scan_result.endpoints)}
• Technologies: {len(scan_result.technologies)}"""

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text("""🔒 *Cybersecurity Scanner Bot*
I'm your website security analyst!
Send me a URL to scan (e.g., https://example.com)""", parse_mode='Markdown')

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.message.reply_text("""📖 *Help*
/start - Start the bot
/help - Show help
Send a URL - Scan a website""", parse_mode='Markdown')

    async def scan_website(self, update: Update, context: ContextTypes.DEFAULT_TYPE, url: str) -> None:
        domain = self.normalize_domain(url)
        msg = await update.message.reply_text(f"🔍 Scanning {domain}...", parse_mode='Markdown')
        self.is_scanning = True
        try:
            loop = asyncio.get_event_loop()
            scan_result = await loop.run_in_executor(None, lambda: self.scanner.scan(domain, deep=True))
            report = self.scanner.generate_report(scan_result, output_format="text")
            chunks = self.format_report_for_telegram(report)
            for i, chunk in enumerate(chunks):
                if i == 0:
                    try:
                        await context.bot.edit_message_text(chat_id=update.effective_chat.id, message_id=msg.message_id, text=chunk, parse_mode='Markdown')
                    except:
                        await update.message.reply_text(chunk, parse_mode='Markdown')
                else:
                    await update.message.reply_text(chunk, parse_mode='Markdown')
            summary = self.generate_summary(scan_result)
            await update.message.reply_text(summary, parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Error: {e}")
            await update.message.reply_text(f"❌ Scan failed: {str(e)}", parse_mode='Markdown')
        finally:
            self.is_scanning = False

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if self.is_scanning:
            await update.message.reply_text("⏳ Please wait, scan in progress...", parse_mode='Markdown')
            return
        if not update.message or not update.message.text:
            return
        text = update.message.text.strip()
        if text.startswith('/'):
            return
        url = self.extract_url(text)
        if url:
            await update.message.reply_text(f"🎯 Scanning: {url}", parse_mode='Markdown')
            await self.scan_website(update, context, url)
        else:
            await update.message.reply_text("❌ Please send a valid URL", parse_mode='Markdown')

    def run(self):
        app = Application.builder().token(self.token).build()
        app.add_handler(CommandHandler("start", self.start))
        app.add_handler(CommandHandler("help", self.help_command))
        app.add_handler(MessageHandler(self.Filters.TEXT & ~self.Filters.COMMAND, self.handle_message))
        logger.info("Starting bot...")
        app.run_polling()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Telegram Cybersecurity Scanner Bot')
    parser.add_argument('--token', type=str, required=True, help='Telegram bot token')
    args = parser.parse_args()
    bot = CyberSecurityTelegramBot(args.token)
    bot.run()

if __name__ == '__main__':
    main()
