import os
import json
import logging
import asyncio
import subprocess
import tempfile
import time
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv
from groq import Groq, APIError
import requests
import dns.resolver
from ddgs import DDGS
from fpdf import FPDF
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

load_dotenv()

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
GROQ_API_KEY = os.environ["GROQ_API_KEY"]
MODEL = "llama-3.3-70b-versatile"
MAX_HISTORY = 20

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

client = Groq(api_key=GROQ_API_KEY)

conversation_history: dict[int, list[dict]] = defaultdict(list)

SYSTEM_PROMPT = (
    "You are KABOOS, an expert cybersecurity analyst and OSINT specialist. "
    "Help with cybersecurity questions, OSINT investigations, and general queries. Be concise and clear."
)

WELCOME_MSG = (
    "Hello World I'm KABOOS Cybersecurity Analyst\n\n"
    "Just type any target to start a full OSINT investigation:\n\n"
    "  Person name  →  John Doe\n"
    "  Email        →  john@example.com\n"
    "  Username     →  @johndoe\n"
    "  IP address   →  8.8.8.8\n"
    "  Domain       →  example.com\n"
    "  Phone        →  +1234567890\n\n"
    "I'll run Google dorks, username search, DNS/WHOIS, "
    "and deliver a full PDF intelligence report.\n\n"
    "/clear — reset conversation"
)


# ── Intent Detection ──────────────────────────────────────────────────────────

def detect_intent(text: str) -> dict:
    try:
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=150,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an OSINT intent classifier. "
                        "Decide if the user wants to investigate a target. "
                        "Return ONLY valid JSON: "
                        '{"is_osint": true/false, "target": "...", "type": "person_name|email|ip|domain|username|phone"} '
                        "Set is_osint=false for general questions, greetings, or chat. "
                        "Set is_osint=true when the user submits a name, email, IP, domain, phone, or username to investigate."
                    ),
                },
                {"role": "user", "content": text},
            ],
        )
        raw = response.choices[0].message.content.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:-1])
        return json.loads(raw)
    except Exception as e:
        logger.error("Intent detection failed: %s", e)
        return {"is_osint": False, "target": "", "type": ""}


# ── OSINT Modules ─────────────────────────────────────────────────────────────

def ddg_search(query: str, max_results: int = 5) -> list[dict]:
    try:
        with DDGS() as ddgs:
            return list(ddgs.text(query, max_results=max_results))
    except Exception as e:
        logger.warning("DDG error for '%s': %s", query, e)
        return []


def build_dorks(target: str, target_type: str) -> dict[str, str]:
    name = f'"{target}"'
    if target_type == "person_name":
        return {
            "General":        name,
            "LinkedIn":       f'{name} site:linkedin.com',
            "Social Media":   f'{name} site:facebook.com OR site:twitter.com OR site:instagram.com',
            "GitHub":         f'{name} site:github.com',
            "Email/Phone":    f'{name} email OR phone OR mobile',
            "Documents":      f'{name} filetype:pdf OR filetype:doc',
            "Pastes/Leaks":   f'{name} site:pastebin.com OR leak OR breach',
        }
    elif target_type == "email":
        return {
            "General":   name,
            "LinkedIn":  f'{name} site:linkedin.com',
            "Breaches":  f'{name} breach OR leak OR dump',
            "Social":    f'{name} site:facebook.com OR site:twitter.com',
        }
    elif target_type in ("domain", "ip"):
        return {
            "General":         name,
            "Subdomains":      f'site:{target}',
            "Vulnerabilities": f'{name} vulnerability OR CVE OR exploit',
            "Admin panels":    f'site:{target} inurl:admin OR inurl:login',
        }
    elif target_type in ("username", "phone"):
        return {
            "General": name,
            "Social":  f'{name} site:twitter.com OR site:instagram.com OR site:facebook.com',
            "GitHub":  f'{name} site:github.com',
            "Forums":  f'{name} forum OR profile OR reddit',
        }
    return {"General": name}


async def run_dork_search(target: str, target_type: str) -> dict[str, list[dict]]:
    loop = asyncio.get_event_loop()
    dorks = build_dorks(target, target_type)

    async def fetch_one(label: str, query: str) -> tuple[str, list[dict]]:
        result = await loop.run_in_executor(None, ddg_search, query, 4)
        return label, result

    tasks = [fetch_one(label, query) for label, query in dorks.items()]
    pairs = await asyncio.gather(*tasks)
    return dict(pairs)


async def sherlock_search(target: str) -> list[str]:
    # Pick the single most likely username variant only
    if " " in target:
        parts = target.lower().split()
        variant = f"{parts[0]}{parts[-1]}"
    else:
        variant = target.lstrip("@").lower()

    try:
        proc = await asyncio.create_subprocess_exec(
            "sherlock", variant, "--print-found", "--timeout", "8",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=40)
        return [l.strip() for l in stdout.decode(errors="replace").splitlines() if "[+]" in l]
    except Exception as e:
        logger.warning("Sherlock error for '%s': %s", variant, e)
    return []


def get_ip_info(ip: str) -> dict:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=10)
        return r.json()
    except Exception:
        return {}


def get_whois(target: str) -> str:
    try:
        result = subprocess.run(
            ["whois", target], capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().splitlines()
        important = [
            l for l in lines if any(k in l.lower() for k in [
                "registrar", "creation", "expir", "updated", "name server",
                "registrant", "status", "country", "email", "organisation", "org",
            ])
        ]
        return "\n".join(important[:40]) if important else result.stdout[:1500]
    except Exception as e:
        return str(e)


def get_dns(target: str) -> dict[str, list[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = resolver.resolve(target, rtype)
            records[rtype] = [r.to_text() for r in answers]
        except Exception:
            pass
    return records


def ai_analyze(target: str, target_type: str, findings: dict) -> str:
    snippet = json.dumps(
        {k: v for k, v in findings.items() if k != "analysis"},
        indent=2, default=str
    )[:5000]
    try:
        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=1200,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are KABOOS, an expert OSINT analyst. "
                        "Write a professional intelligence report based on the findings. "
                        "Structure it with: Executive Summary, Key Findings, "
                        "Online Presence Analysis, Risk Assessment, Recommendations. "
                        "Be factual, professional, and concise."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Target: {target}\nType: {target_type}\n\nFindings:\n{snippet}",
                },
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI analysis unavailable: {e}"


# ── PDF Builder ───────────────────────────────────────────────────────────────

def safe(text: str) -> str:
    _unicode_map = {
        '—': '-', '–': '-', '‒': '-',
        '‘': "'", '’': "'",
        '“': '"', '”': '"',
        '•': '*', '…': '...', '·': '.',
        '→': '->', '←': '<-', '•': '-',
        'é': 'e', 'è': 'e', 'ê': 'e',
        'à': 'a', 'â': 'a', 'ô': 'o',
        'ü': 'u', 'ñ': 'n',
    }
    for ch, rep in _unicode_map.items():
        text = text.replace(ch, rep)
    return text.encode("latin-1", errors="replace").decode("latin-1")


class OSINTReport(FPDF):
    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self.set_margins(15, 22, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_fill_color(15, 15, 35)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(0, 210, 110)
        self.set_y(4)
        self.cell(0, 10, "KABOOS  |  OSINT INTELLIGENCE REPORT  |  CONFIDENTIAL", align="C")
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(
            0, 10,
            f"Target: {safe(self.target)}  |  "
            f"{datetime.now().strftime('%Y-%m-%d')}  |  Page {self.page_no()}",
            align="C",
        )
        self.set_text_color(0, 0, 0)

    def cover(self, target_type: str):
        self.add_page()
        # dark background
        self.set_fill_color(8, 8, 22)
        self.rect(0, 0, 210, 297, "F")

        # green accent bar
        self.set_fill_color(0, 200, 100)
        self.rect(0, 100, 210, 3, "F")
        self.rect(0, 200, 210, 3, "F")

        self.set_y(55)
        self.set_font("Helvetica", "B", 36)
        self.set_text_color(0, 210, 110)
        self.cell(0, 18, "OSINT", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 18, "INTELLIGENCE REPORT", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(12)
        self.set_font("Helvetica", "B", 20)
        self.set_text_color(255, 255, 255)
        self.cell(0, 12, safe(self.target), align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 13)
        self.set_text_color(140, 140, 160)
        self.cell(0, 8, f"Target Type: {target_type.replace('_', ' ').title()}", align="C", new_x="LMARGIN", new_y="NEXT")

        self.ln(55)
        self.set_font("Helvetica", "", 11)
        self.set_text_color(100, 210, 155)
        self.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 8, "Analyst: KABOOS  |  Cybersecurity Division", align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_y(245)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(200, 50, 50)
        self.cell(0, 10, "[  CONFIDENTIAL  ]", align="C")
        self.set_text_color(0, 0, 0)

    def section(self, title: str):
        self.ln(4)
        self.set_fill_color(15, 15, 35)
        self.set_text_color(0, 210, 110)
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 9, f"  {safe(title)}", fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def body(self, text: str):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5, safe(text))
        self.ln(1)

    def subsection(self, title: str):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(0, 80, 180)
        self.cell(0, 7, f">> {safe(title)}", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)

    def add_analysis(self, text: str):
        self.section("AI INTELLIGENCE ANALYSIS")
        self.body(text)

    def add_dorks(self, results: dict[str, list[dict]]):
        self.section("WEB PRESENCE & DORK RESULTS")
        for label, hits in results.items():
            self.subsection(label)
            if not hits:
                self.body("  No results found.")
            else:
                for h in hits:
                    title = h.get("title", "N/A")[:90]
                    url   = h.get("href", h.get("url", "N/A"))[:110]
                    body  = h.get("body", "")[:180]
                    self.body(f"  Title : {title}\n  URL   : {url}\n  Snippet: {body}\n")

    def add_sherlock(self, found: list[str]):
        self.section("USERNAME SEARCH - SHERLOCK")
        if not found:
            self.body("No accounts found on any platform.")
        else:
            self.body(f"Found {len(found)} account(s):\n")
            for line in found:
                self.body(f"  {line}")

    def add_ip(self, data: dict):
        self.section("IP INTELLIGENCE")
        if not data or data.get("status") == "fail":
            self.body("No data returned.")
            return
        self.body(
            f"IP Address : {data.get('query', 'N/A')}\n"
            f"Country    : {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})\n"
            f"Region     : {data.get('regionName', 'N/A')}\n"
            f"City       : {data.get('city', 'N/A')}\n"
            f"ZIP        : {data.get('zip', 'N/A')}\n"
            f"Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}\n"
            f"ISP        : {data.get('isp', 'N/A')}\n"
            f"Org        : {data.get('org', 'N/A')}\n"
            f"AS         : {data.get('as', 'N/A')}\n"
            f"Timezone   : {data.get('timezone', 'N/A')}\n"
            f"Mobile     : {data.get('mobile', False)}\n"
            f"Proxy/VPN  : {data.get('proxy', False)}\n"
            f"Hosting    : {data.get('hosting', False)}\n"
        )

    def add_whois(self, text: str):
        self.section("WHOIS RECORD")
        self.body(text or "No data available.")

    def add_dns(self, records: dict):
        self.section("DNS RECORDS")
        if not records:
            self.body("No records found.")
            return
        for rtype, values in records.items():
            self.body(f"{rtype}:\n" + "\n".join(f"  {v}" for v in values) + "\n")


def build_pdf(target: str, target_type: str, findings: dict) -> str:
    pdf = OSINTReport(target)
    pdf.cover(target_type)

    pdf.add_page()
    if findings.get("analysis"):
        pdf.add_analysis(findings["analysis"])

    if findings.get("dorks"):
        pdf.add_page()
        pdf.add_dorks(findings["dorks"])

    if findings.get("sherlock"):
        pdf.add_page()
        pdf.add_sherlock(findings["sherlock"])

    if findings.get("ip"):
        pdf.add_page()
        pdf.add_ip(findings["ip"])

    if findings.get("whois"):
        pdf.add_page()
        pdf.add_whois(findings["whois"])

    if findings.get("dns"):
        pdf.add_page()
        pdf.add_dns(findings["dns"])

    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    pdf.output(tmp.name)
    return tmp.name


# ── OSINT Orchestrator ────────────────────────────────────────────────────────

async def run_osint(update: Update, target: str, target_type: str) -> None:
    loop = asyncio.get_event_loop()
    status = await update.message.reply_text(
        f"Target locked: {target}\nRunning all OSINT modules in parallel..."
    )
    pdf_path = None
    try:
        # ── Step 1: run all data-gathering modules in parallel ──────────────
        async def do_dorks():
            try:
                return await run_dork_search(target, target_type)
            except Exception as e:
                logger.error("Dorks failed: %s", e)
                return {}

        async def do_sherlock():
            try:
                if target_type in ("person_name", "username"):
                    return await sherlock_search(target)
            except Exception as e:
                logger.error("Sherlock failed: %s", e)
            return []

        async def do_ip():
            try:
                if target_type == "ip":
                    return await loop.run_in_executor(None, get_ip_info, target)
            except Exception as e:
                logger.error("IP lookup failed: %s", e)
            return {}

        async def do_whois():
            try:
                if target_type in ("domain", "ip"):
                    return await loop.run_in_executor(None, get_whois, target)
            except Exception as e:
                logger.error("WHOIS failed: %s", e)
            return ""

        async def do_dns():
            try:
                if target_type in ("domain", "ip"):
                    return await loop.run_in_executor(None, get_dns, target)
            except Exception as e:
                logger.error("DNS failed: %s", e)
            return {}

        dorks, sherlock, ip, whois, dns = await asyncio.gather(
            do_dorks(), do_sherlock(), do_ip(), do_whois(), do_dns()
        )

        findings = {
            "dorks": dorks,
            "sherlock": sherlock,
            "ip": ip,
            "whois": whois,
            "dns": dns,
        }

        # ── Step 2: AI analysis ──────────────────────────────────────────────
        await status.edit_text("Analysing findings with AI...")
        try:
            findings["analysis"] = await asyncio.wait_for(
                loop.run_in_executor(None, ai_analyze, target, target_type, findings),
                timeout=30,
            )
        except Exception as e:
            logger.error("AI analysis failed: %s", e)
            findings["analysis"] = "AI analysis unavailable."

        # ── Step 3: build PDF ────────────────────────────────────────────────
        await status.edit_text("Building PDF report...")
        pdf_path = await loop.run_in_executor(None, build_pdf, target, target_type, findings)

        # ── Step 4: send PDF ─────────────────────────────────────────────────
        await status.edit_text("Sending report...")
        fname = f"KABOOS_OSINT_{target.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        with open(pdf_path, "rb") as f:
            await update.message.reply_document(
                document=f,
                filename=fname,
                caption=(
                    f"KABOOS OSINT Report\n"
                    f"Target: {target}\n"
                    f"Type: {target_type.replace('_', ' ').title()}\n"
                    f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                ),
            )

    except Exception as e:
        logger.error("OSINT pipeline error: %s", e, exc_info=True)
        await status.edit_text(f"Error during OSINT: {e}")
    finally:
        if pdf_path and os.path.exists(pdf_path):
            os.unlink(pdf_path)
        try:
            await status.delete()
        except Exception:
            pass


# ── Handlers ──────────────────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(WELCOME_MSG)


async def clear(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    conversation_history[update.effective_user.id].clear()
    await update.message.reply_text("Conversation history cleared.")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id  = update.effective_user.id
    user_text = update.message.text.strip()

    # Detect intent
    intent = await asyncio.get_event_loop().run_in_executor(None, detect_intent, user_text)

    if intent.get("is_osint") and intent.get("target"):
        await run_osint(update, intent["target"], intent.get("type", "person_name"))
        return

    # Regular AI chat
    history = conversation_history[user_id]
    history.append({"role": "user", "content": user_text})
    if len(history) > MAX_HISTORY:
        conversation_history[user_id] = history[-MAX_HISTORY:]

    await update.message.chat.send_action("typing")
    try:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}] + conversation_history[user_id]
        response = client.chat.completions.create(
            model=MODEL, max_tokens=1024, messages=messages
        )
        reply = response.choices[0].message.content
        history.append({"role": "assistant", "content": reply})
        for chunk in [reply[i : i + 4096] for i in range(0, len(reply), 4096)]:
            await update.message.reply_text(chunk)
    except APIError as e:
        logger.error("DeepSeek error: %s", e)
        await update.message.reply_text("Sorry, I ran into an error. Please try again.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    app = (
        ApplicationBuilder()
        .token(TELEGRAM_BOT_TOKEN)
        .connect_timeout(30)
        .read_timeout(30)
        .write_timeout(60)
        .build()
    )
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("clear", clear))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Bot started.")
    app.run_polling()


if __name__ == "__main__":
    main()
