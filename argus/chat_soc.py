#!/usr/bin/env python3
"""Chat-SOC ARGUS - Interface web pour l'analyste. Pose une question en
français, le backend interroge ELK via le serveur MCP local, puis Groq
formule la reponse. Aucun secret dans ce fichier.
"""
import os
import re
import json
import hmac
import asyncio
import threading
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from mcp import Client

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")
MCP_URL = os.environ.get("MCP_URL", "http://127.0.0.1:8700/mcp")
CHAT_PORT = int(os.environ.get("CHAT_PORT", "8001"))
CHAT_HOST = os.environ.get("CHAT_HOST", "0.0.0.0")
CHAT_USER = os.environ.get("CHAT_USER", "analyste")
CHAT_PASS = os.environ.get("CHAT_PASS", "")

PAGE = r"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARGUS — Console de l'analyste</title>
<style>
  :root{
    --bg:#ece3f4; --panel:#f7f2fb; --border:#d5c6e3;
    --txt:#2e2438; --muted:#6f6082;
    --accent:#a34d86; --accent2:#7a63c9;
    --crit:#d64545; --high:#e0883a; --med:#d6b341; --low:#5a9bd5;
    --font:"Segoe UI","Ubuntu","Noto Sans",sans-serif;
    --mono:"JetBrains Mono","DejaVu Sans Mono",monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0;}
  html,body{height:100%;}
  body{background:var(--bg);color:var(--txt);font-family:var(--font);font-size:15px;line-height:1.55;display:flex;flex-direction:column;}
  code,pre,.mono,.body table,.tools,.meta .t{font-family:var(--mono);}
  header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 18px;background:var(--panel);border-bottom:1px solid var(--border);}
  header h1{font-size:15px;font-weight:600;letter-spacing:.2px;}
  .statusbar{display:flex;gap:16px;align-items:center;}
  .status{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--accent2);}
  .dot{width:8px;height:8px;border-radius:50%;background:#b9aec8;box-shadow:0 0 0 1px var(--border);}
  .dot.on{background:#57b46a;box-shadow:0 0 6px rgba(87,180,106,.6);}
  #messages{flex:1;overflow-y:auto;padding:20px 16px 28px;}
  .stream{max-width:960px;margin:0 auto;display:flex;flex-direction:column;gap:14px;}
  .msg{max-width:85%;padding:11px 15px;border-radius:14px;border:1px solid var(--border);}
  .msg.user{align-self:flex-end;background:#e6d5f0;border-color:var(--accent);}
  .msg.bot{align-self:flex-start;background:var(--panel);}
  .meta{display:flex;gap:8px;align-items:baseline;font-size:11.5px;color:var(--muted);margin-bottom:5px;}
  .meta .who{font-weight:600;color:var(--accent);}
  .msg.bot .meta .who{color:var(--accent2);}
  .meta .t{font-size:11px;}
  .body{word-wrap:break-word;overflow-wrap:anywhere;}
  .body p{margin:0 0 8px;} .body p:last-child{margin-bottom:0;}
  .body ul,.body ol{margin:4px 0 8px 22px;} .body li{margin:2px 0;}
  .body pre{background:#f2ebf8;border:1px solid var(--border);border-radius:8px;padding:10px 12px;overflow-x:auto;margin:8px 0;font-size:13.5px;}
  .body code{background:#f2ebf8;border:1px solid var(--border);border-radius:5px;padding:1px 5px;font-size:13.5px;}
  .body pre code{border:0;background:none;padding:0;}
  .body table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12.5px;}
  .body th,.body td{border:1px solid var(--border);padding:5px 8px;text-align:left;vertical-align:top;}
  .body th{background:#e7daf1;color:var(--accent);font-weight:600;}
  .body a{color:var(--accent2);text-decoration:none;} .body a:hover{text-decoration:underline;}
  .body strong{color:#1c1424;}
  .sev{display:inline-block;padding:0 8px;border-radius:999px;font-family:var(--mono);font-size:11.5px;line-height:18px;border:1px solid currentColor;}
  .sev-critique{color:var(--crit);} .sev-eleve{color:var(--high);} .sev-moyen{color:var(--med);} .sev-faible{color:var(--low);}
  .tools{margin-top:7px;font-size:11px;color:var(--muted);}
  #suggestions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px;}
  #suggestions button{font-family:var(--font);font-size:12.5px;color:var(--txt);background:transparent;border:1px solid var(--border);border-radius:999px;padding:5px 12px;cursor:pointer;}
  #suggestions button:hover{border-color:var(--accent);color:var(--accent);}
  .typing{display:inline-flex;gap:5px;align-items:center;color:var(--muted);font-size:13px;}
  .typing i{width:5px;height:5px;border-radius:50%;background:var(--accent2);display:inline-block;animation:bl 1.2s infinite;}
  .typing i:nth-child(2){animation-delay:.2s;} .typing i:nth-child(3){animation-delay:.4s;}
  @keyframes bl{0%,80%,100%{opacity:.25}40%{opacity:1}}
  footer{border-top:1px solid var(--border);background:var(--panel);padding:12px 16px;}
  form#composer{max-width:960px;margin:0 auto;display:flex;gap:10px;align-items:flex-end;}
  #input{flex:1 1 auto;min-width:0;min-height:66px;background:#ffffff;color:var(--txt);border:1px solid var(--border);border-radius:10px;padding:10px 12px;font-family:var(--font);font-size:15px;line-height:1.5;resize:none;overflow-y:auto;max-height:180px;}
  #input:focus{outline:none;border-color:var(--accent);}
  #send{flex:0 0 auto;background:var(--accent);color:#ffffff;border:none;border-radius:10px;padding:10px 20px;font-family:var(--font);font-size:14px;font-weight:700;cursor:pointer;}
  #send:disabled{opacity:.5;cursor:default;}
</style>
</head>
<body>
<header>
  <h1>ARGUS — Console de l'analyste</h1>
  <div class="statusbar">
    <span class="status"><span class="dot" id="dot-es"></span>Elastic connectée</span>
    <span class="status"><span class="dot" id="dot-mcp"></span>MCP connecté</span>
  </div>
</header>
<div id="messages"><div class="stream" id="stream"></div></div>
<footer>
  <form id="composer">
    <textarea id="input" rows="3" placeholder="Posez votre question… (Entrée = envoyer, Maj+Entrée = nouvelle ligne)" autocomplete="off"></textarea>
    <button id="send" type="submit">Envoyer</button>
  </form>
</footer>
<script>
const stream = document.getElementById('stream');
const input = document.getElementById('input');
const send = document.getElementById('send');
const composer = document.getElementById('composer');
const scroller = document.getElementById('messages');
const dotES = document.getElementById('dot-es');
const dotMCP = document.getElementById('dot-mcp');

function scrollBottom(){ scroller.scrollTop = scroller.scrollHeight; }
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sevClass(w){ w = w.toLowerCase(); if (w === 'critique') return 'critique'; if (w === 'élevée' || w === 'élevé' || w === 'elevee' || w === 'eleve') return 'eleve'; if (w === 'moyenne') return 'moyen'; return 'faible'; }
function inline(t){
  t = esc(t);
  t = t.replace(/(^|[\s(>«"'])(critique|élevée|élevé|elevee|eleve|moyenne|faible)(?=$|[\s.,;:!?)<»"'])/gi,
    function(m, pre, w){ return pre + '<span class="sev sev-' + sevClass(w) + '">' + w + '</span>'; });
  t = t.replace(/`([^`]+)`/g, '<code>$1</code>');
  t = t.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  t = t.replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>');
  t = t.replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  return t;
}
function md(src){
  src = String(src || '').replace(/\r/g, '');
  const blocks = [];
  src = src.replace(/```([\s\S]*?)```/g, function(m, code){
    code = code.replace(/^[a-zA-Z0-9_+-]*\n/, '');
    blocks.push(code);
    return '\u0000CB' + (blocks.length - 1) + '\u0000';
  });
  const lines = src.split('\n');
  let html = '', i = 0;
  const isTable = function(n){ return n + 1 < lines.length && lines[n].indexOf('|') !== -1 && /^\s*\|?[\s:|-]+\|/.test(lines[n+1]); };
  while (i < lines.length){
    let line = lines[i];
    if (/^\s*$/.test(line)){ i++; continue; }
    const pc = line.match(/^\u0000CB(\d+)\u0000$/);
    if (pc){ html += '<pre><code>' + esc(blocks[+pc[1]]) + '</code></pre>'; i++; continue; }
    if (/^#{1,6}\s+/.test(line)){
      const lvl = line.match(/^#+/)[0].length;
      html += '<h' + lvl + '>' + inline(line.replace(/^#+\s+/, '')) + '</h' + lvl + '>'; i++; continue;
    }
    if (isTable(i)){
      const cells = function(l){ return l.split('|').map(function(c){ return c.trim(); })
        .filter(function(c, idx, arr){ return !(idx === 0 && c === '') && !(idx === arr.length - 1 && c === ''); }); };
      html += '<table><thead><tr>' + cells(line).map(function(c){ return '<th>' + inline(c) + '</th>'; }).join('') + '</tr></thead><tbody>';
      i += 2;
      while (i < lines.length && lines[i].indexOf('|') !== -1 && lines[i].trim() !== ''){
        html += '<tr>' + cells(lines[i]).map(function(c){ return '<td>' + inline(c) + '</td>'; }).join('') + '</tr>'; i++;
      }
      html += '</tbody></table>'; continue;
    }
    if (/^\s*[-*+]\s+/.test(line)){
      html += '<ul>';
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])){ html += '<li>' + inline(lines[i].replace(/^\s*[-*+]\s+/, '')) + '</li>'; i++; }
      html += '</ul>'; continue;
    }
    if (/^\s*\d+[.)]\s+/.test(line)){
      html += '<ol>';
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])){ html += '<li>' + inline(lines[i].replace(/^\s*\d+[.)]\s+/, '')) + '</li>'; i++; }
      html += '</ol>'; continue;
    }
    const para = [line]; i++;
    while (i < lines.length && !/^\s*$/.test(lines[i]) && lines[i].indexOf('\u0000CB') !== 0
           && !/^\s*[-*+]\s+/.test(lines[i]) && !/^\s*\d+[.)]\s+/.test(lines[i]) && !/^#{1,6}\s+/.test(lines[i]) && !isTable(i)){
      para.push(lines[i]); i++;
    }
    html += '<p>' + para.map(inline).join('<br>') + '</p>';
  }
  return html.replace(/\u0000CB(\d+)\u0000/g, function(m, n){ return '<pre><code>' + esc(blocks[+n]) + '</code></pre>'; });
}
function nowHHMM(){ return new Date().toLocaleTimeString('fr-FR', {hour:'2-digit', minute:'2-digit'}); }
function addMessage(who, content, toolsText){
  const div = document.createElement('div');
  div.className = 'msg ' + (who === 'user' ? 'user' : 'bot');
  const meta = document.createElement('div');
  meta.className = 'meta';
  meta.innerHTML = '<span class="who">' + (who === 'user' ? 'Analyste' : 'ARGUS') + '</span><span class="t">' + nowHHMM() + '</span>';
  const body = document.createElement('div');
  body.className = 'body';
  if (who === 'user'){ body.textContent = content; } else { body.innerHTML = content; }
  div.appendChild(meta); div.appendChild(body);
  if (toolsText){ const t = document.createElement('div'); t.className = 'tools'; t.textContent = toolsText; div.appendChild(t); }
  stream.appendChild(div); scrollBottom();
  return div;
}
function setHealth(ok){ dotES.classList.toggle('on', !!ok); dotMCP.classList.toggle('on', !!ok); }

const greet = addMessage('bot', md("Bonjour, analyste. Je suis ARGUS, prête à vous aider. Posez-moi une question sur la sécurité :"));
const sug = document.createElement('div');
sug.id = 'suggestions';
["Dernières alertes", "État du cluster", "Quel hôte a émis le scan ?", "Résumé des alertes critiques"].forEach(function(q){
  const b = document.createElement('button');
  b.type = 'button'; b.textContent = q;
  b.addEventListener('click', function(){ input.value = q; grow(); input.focus(); });
  sug.appendChild(b);
});
greet.appendChild(sug);

function grow(){
  input.style.height = 'auto';
  input.style.height = Math.min(Math.max(input.scrollHeight, 66), 180) + 'px';
}
input.addEventListener('input', grow);
input.addEventListener('keydown', function(e){
  if (e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); composer.requestSubmit(); }
});

composer.addEventListener('submit', async function(e){
  e.preventDefault();
  const q = input.value.trim();
  if (!q) return;
  input.value = ''; grow();
  addMessage('user', q);
  send.disabled = true;
  const bot = addMessage('bot', '<span class="typing">ARGUS analyse<i></i><i></i><i></i></span>');
  const bodyEl = bot.querySelector('.body');
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: q})
    });
    const data = await res.json();
    const ans = data.answer || data.error || 'Pas de réponse.';
    bodyEl.innerHTML = md(ans);
    if (data.tools && data.tools.length){
      const t = document.createElement('div');
      t.className = 'tools';
      t.textContent = 'Outils MCP : ' + data.tools.join(' → ');
      bot.appendChild(t);
      setHealth(true);
    }
    if (data.error){ setHealth(false); }
  } catch (err) {
    bodyEl.textContent = 'Erreur : ' + err;
    setHealth(false);
  }
  send.disabled = false;
  input.focus();
  scrollBottom();
});
</script>
</body>
</html>
"""


def chat_groq(system, user_msg, temperature=0.2, max_tokens=2000):
    if not GROQ_API_KEY:
        return "Erreur : GROQ_API_KEY non définie dans l'environnement."
    url = "https://api.groq.com/openai/v1/chat/completions"
    data = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "temperature": temperature,
        "max_completion_tokens": max_tokens,
    }
    r = requests.post(url, headers={
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"}, json=data, timeout=120)
    r.raise_for_status()
    message = r.json()["choices"][0]["message"]
    return (message.get("content") or message.get("reasoning") or "").strip()


STRICT_SYSTEM = (
    "Tu es ARGUS, assistant SOC du CHIC (établissement hospitalier). "
    "REGLES STRICTES :\n"
    "1. Base-toi UNIQUEMENT sur les données reçues. N'invente JAMAIS de chiffre, capacité, "
    "adresse, ou configuration.\n"
    "2. Si la question demande une information absente des données, réponds explicitement : "
    "« Cette information n'est pas disponible dans le SIEM du lab » et propose la donnée la "
    "plus proche réellement présente.\n"
    "3. Distingue toujours « observation (donnée reçue) » et « interprétation »."
)


def classify(message):
    """Demande au modèle de décider si la question nécessite ELK, et quoi."""
    system = (
        "Classifie la question en un seul de ces trois mots et retourne UNIQUEMENT "
        'l objet JSON correspondant, rien d autre :\n'
        '- {"tool":"statistiques"} quand la question concerne la santé, la capacité, '
        'les performances, les statistiques du cluster ou du stockage (mémoire, CPU, volume).\n'
        '- {"tool":"alertes"} quand la question concerne des alertes, incidents, scans, '
        'attaques ou événements de sécurité.\n'
        '- {"tool":"statut"} quand elle concerne la connexion au SIEM ou le compteur de logs.\n'
        '- {"tool":"general"} dans tout autre cas (salutation, présentation, capacité, conseil).\n'
        'Exemple : "donne moi les alertes" -> {"tool":"alertes"}'
    )
    raw = chat_groq(system, message, temperature=0.0, max_tokens=256)
    m = re.search(r'\{[^}]*\}', raw)
    if not m:
        return "general"
    try:
        return json.loads(m.group(0)).get("tool", "general")
    except Exception:
        return "general"


async def mcp_call(tool, args):
    async with Client(MCP_URL) as client:
        result = await client.call_tool(tool, args or {})
        return "".join(getattr(c, "text", "") or "" for c in getattr(result, "content", []))


def run_mcp_call(tool, args):
    return asyncio.run(mcp_call(tool, args))


def answer(message):
    intent = classify(message)
    tools_used = []

    # Pré-routage : questions de conseil/architecture/évolutivité -> discussion
    # générale SANS requête ELK (aucune métrique réelle de montée en charge n'existe)
    if re.search(r"capacit|volutiv|mont[eé]e en charge|recommandation|architecture|mémoire|cpu|ram|ssd|tb|go ram", message.lower()):
        return tools_used, chat_groq(
            "Tu es ARGUS, assistant SOC du CHIC (établissement hospitalier), expert "
            "Elastic SIEM. L'analyste te demande un avis d'architecture ou de capacité. "
            "N'invoque AUCUNE métrique réelle du lab ni aucun chiffre présenté comme un "
            "fait : réponds en conseil méthodologique général (principes de dimensionnement "
            "ILM, hot-warm-cold, surveillance heap/GC, etc.), en rappelant que le dimensionnement "
            "se décide selon les données réelles et les tests de charge. Sinon, propose "
            "d'interroger les statistiques réelles du cluster si l'analyste le souhaite.",
            message)

    if intent == "statistiques":
        tools_used.append("recuperer_statistiques_cluster")
        data = run_mcp_call("recuperer_statistiques_cluster", {})
        prompt = (
            f"Question de l'analyste :\n{message}\n\n"
            f"Resultats ELK (via MCP - statistiques reelles du cluster) :\n{data}\n\n"
            "Reponds en français, de façon synthétique et technique. N'invente aucun chiffre "
            "absent des données reçues."
        )
        return tools_used, chat_groq(
            STRICT_SYSTEM, prompt)

    if intent == "statut":
        tools_used.append("verifier_status_elastic")
        data = run_mcp_call("verifier_status_elastic", {})
        prompt = (
            f"Question de l'analyste :\n{message}\n\n"
            f"Resultats ELK (via MCP) :\n{data}\n\n"
            "Reponds en français, de façon synthétique et technique."
        )
        return tools_used, chat_groq(
            STRICT_SYSTEM, prompt)

    if intent == "alertes":
        tools_used.append("recuperer_alertes_siem")
        data = run_mcp_call("recuperer_alertes_siem", {"limit": 5})
        prompt = (
            f"Question de l'analyste :\n{message}\n\n"
            f"Resultats ELK (via MCP) :\n{data}\n\n"
            "Reponds en français, de façon synthétique et technique."
        )
        return tools_used, chat_groq(
            STRICT_SYSTEM, prompt)

    # intention "general" -> discussion directe, AUCUNE requête ELK
    return tools_used, chat_groq(
        "Tu es ARGUS, assistant SOC du CHIC (établissement hospitalier), spécialiste "
        "Elastic SIEM. Réponds de façon concise et utile à l'analyste. N'appelle aucun "
        "outil, ne cite aucune métrique : réponds de mémoire (connaissances générales).",
        message)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencieux
        pass

    def _check_auth(self, header=""):
        if not CHAT_PASS:
            return True
        if not header:
            return False
        expected = "Basic " + base64.b64encode(f"{CHAT_USER}:{CHAT_PASS}".encode()).decode()
        return hmac.compare_digest(header.strip(), expected)

    def _deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Chat-SOC ARGUS"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.wfile.write(b"")

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            if not self._check_auth(self.headers.get("Authorization", "")):
                return self._deny()
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self._check_auth(self.headers.get("Authorization", "")):
            return self._deny()
        if self.path != "/api/chat":
            self._json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
            message = (payload.get("message") or "").strip()
        except Exception:
            self._json({"error": "bad request"}, 400)
            return
        if not message:
            self._json({"error": "message vide"}, 400)
            return
        try:
            tools, ans = answer(message)
            self._json({"answer": ans, "tools": tools})
        except Exception as e:
            import traceback
            traceback.print_exc()
            self._json({"error": f"{e}", "answer": f"Erreur interne : {e}"}, 500)


def main():
    print(f"Chat-SOC ARGUS : http://{CHAT_HOST}:{CHAT_PORT}")
    print(f"  MCP   : {MCP_URL}")
    print(f"  Modèle: {GROQ_MODEL}")
    ThreadingHTTPServer((CHAT_HOST, CHAT_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()