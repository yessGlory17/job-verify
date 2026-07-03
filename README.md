<!-- mcp-name: io.github.yessGlory17/jobverify -->

<p align="center">
  <img src="assets/logo/jobverify-banner.png" alt="JobVerify" width="100%">
</p>

<p align="center">
  <b>Check whether a recruiter or job offer is real — before you reply.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/type-MCP%20server-22c55e" alt="MCP server">
  <img src="https://img.shields.io/badge/API%20keys-none-16a34a" alt="No API keys">
  <img src="https://img.shields.io/badge/data-free%20OSINT-0ea5e9" alt="Free OSINT">
  <img src="https://img.shields.io/badge/works%20with-Claude-8b5cf6" alt="Works with Claude">
  <img src="https://img.shields.io/badge/setup-none%20·%20runs%20from%20GitHub-16a34a" alt="No setup — runs from GitHub">
</p>

---

You get a message: *"We loved your profile and want to offer you a great remote job."*
It sounds real. The company has a logo. The recruiter has a photo. But something feels off.

**JobVerify helps you find out — in seconds — whether it's genuine or a scam.**

You paste the recruiter's message (or a company name, a link, or an email) and ask your AI assistant.
JobVerify quietly runs the same background checks a professional investigator would, then gives you a
plain-English answer: **looks legit**, **be careful**, or **this is almost certainly a scam** — and *why*.

---

## ❌ Without JobVerify

Fake recruiter and job-offer scams are everywhere, and they're convincing. On your own, you're left guessing:

- ❌ Is this company real, or a name someone invented last week?
- ❌ Is this "recruiter" a real person, or a stolen photo and a throwaway account?
- ❌ Is that application link safe, or a look-alike site built to steal your data?
- ❌ Why are they asking me to pay for equipment, or move the chat to WhatsApp/Telegram?

By the time you notice, your time, your personal details — or your money — may already be gone.

## ✅ With JobVerify

JobVerify cross-checks the offer against dozens of **free, public information sources** and combines the
clues into one clear verdict:

- ✅ Tells you if the company is a **registered, real business** — or nowhere to be found
- ✅ Spots **classic scam scripts** (upfront fees, fake "task" jobs, crypto, "let's move off-platform")
- ✅ Flags **suspicious links, look-alike domains, and brand-new websites** made to look official
- ✅ Checks whether the **email, phone, and photos** actually belong to who they claim
- ✅ Explains its reasoning in **everyday language**, so you can decide with confidence

No account, no sign-up, and none of your data is sold or stored. It simply helps you not get fooled.

---

## 🕵️ How it works

You don't need to learn anything technical. It's a three-step conversation:

1. **Paste it.** Drop the recruiter's message, a company name, a job link, or an email into your AI chat.
2. **It investigates.** JobVerify pulls out every detail — the company, links, email, phone, wallet
   addresses — and quietly checks each one against public records, scam databases, and website history.
3. **You get a verdict.** A short, honest summary: how risky it looks, which signals are reassuring,
   which are red flags, and what to do next.

> [!NOTE]
> JobVerify **never logs into or scrapes LinkedIn**. It only looks at information that is already
> public, and reads website history through the **Internet Archive** — the safe, legal way to check
> how long a profile or company page has *really* existed (scammers rely on brand-new throwaway accounts).

---

## 🔎 What it looks at

Think of it as a checklist a careful friend — who happens to be a fraud investigator — would run for you:

| Area | The question it answers |
|------|-------------------------|
| **The message** | Does this match known scam playbooks (advance fees, fake tasks, crypto, urgency)? |
| **The company** | Is it a real, registered business? Any recent scam reports? Is the office address real? |
| **The person** | Is the email real and deliverable? Is the phone valid? Are the photos/usernames reused elsewhere? |
| **The links** | Is the domain brand-new? A look-alike of a real brand? On any phishing/malware blocklist? |
| **The money** | Is the crypto wallet they gave you already flagged in scam databases? |
| **The history** | How long has this profile or website *actually* been online? |

---

## 💬 Example

Ask your assistant something as simple as:

```txt
Is this recruiter legit?

"Hi! I'm a talent partner at Example Corp. We loved your profile and
want to offer you a remote role at $45/hr. To get started, please purchase
$200 of onboarding equipment through this link — you'll be fully reimbursed
on day one. Let's continue on Telegram: @examplecorp_hr"
```

JobVerify will pick out **Example Corp**, the **link**, and the **Telegram hand-off**, check each
one, and reply with something like: *"⚠️ High risk — the company has no public registration, the link
was registered 4 days ago, and asking you to pay upfront and move to Telegram are textbook scam signals."*

---

## 🚀 Getting started

**No cloning. No virtualenv. No manual install.** JobVerify runs **straight from GitHub** — you only
paste a few lines into your AI assistant's config, and it fetches and launches itself on demand.

> [!NOTE]
> The only thing you need once is [**uv**](https://docs.astral.sh/uv/) — a tiny, free helper that runs
> the tool for you:
> - **macOS / Linux:** `curl -LsSf https://astral.sh/uv/install.sh | sh`
> - **Windows:** `powershell -c "irm https://astral.sh/uv/install.ps1 | iex"`

### Claude Desktop

Add this to your `claude_desktop_config.json`, then restart Claude:

```json
{
  "mcpServers": {
    "jobverify": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/yessGlory17/job-verify", "jobverify-mcp"]
    }
  }
}
```

### Claude Code

One line in your terminal:

```bash
claude mcp add jobverify -- uvx --from git+https://github.com/yessGlory17/job-verify jobverify-mcp
```

> The first run takes a few seconds while it downloads the tool; after that it's instant.

### Use it

Paste a suspicious message and ask *"Is this offer legit?"* — or run the built-in **`analyze`** prompt.
That's it.

---

## 🔐 Privacy & honesty

- **Your data stays yours.** No sign-up, no tracking, nothing you paste is stored or sold.
- **No API keys or costs.** Every source is free and open — public business registries, DNS records,
  scam blocklists, the Internet Archive, and more.
- **Signals, not certainty.** JobVerify gives you strong decision support, not a courtroom verdict.
  Treat the result as informed guidance about a *message* — never as a final judgment about a real person.

---

<details>
<summary><b>For the curious: the full toolbox</b></summary>

<br>

Under the hood, the AI assistant orchestrates these individual checks (all free, no keys):

| Tool | What it checks |
|------|----------------|
| `extract_entities` | Pulls emails, links, phones, wallets, and profile URLs out of a message |
| `check_scam_patterns` | Matches text against known scam tactics |
| `check_email` / `check_email_footprint` | Email deliverability + linked social accounts |
| `check_domain` / `check_domain_auth` | Domain age, registrar, and whether it can be spoofed |
| `check_typosquatting` / `find_lookalike_domains` | Look-alike / imposter domains |
| `check_url` / `check_ip` | Phishing & malware blocklists |
| `check_certificate_transparency` | A site's certificate & subdomain history |
| `parse_email_headers` | Origin, SPF/DKIM/DMARC, and mismatches in raw email headers |
| `check_phone` | Phone number validity and region |
| `check_crypto_address` | Known-scam crypto wallet databases |
| `verify_company` / `search_company_news` / `verify_address` | Business registration, press, and real address |
| `check_github_org` / `check_username` | Whether an org/username really exists and how old it is |
| `check_wayback` / `fetch_archived_page` | Internet Archive history & content (the legal way to read a page) |

There's also a single **`analyze`** prompt that runs the whole extract → check → verdict flow for you.

</details>

---

## ⚠️ Disclaimer

JobVerify is a decision-support tool. Its signals are probabilistic and may be incomplete or wrong.
Always use your own judgment, and never treat a result as a definitive statement about any individual
or organization.

## License

MIT — use it, share it, and help people stay safe.
