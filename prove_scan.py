#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PROVE — Varredura de Proveniência de Código
D'Souza Advocacia Empresarial · OAB/DF 71.124

Roda na máquina do cliente. Lê apenas arquivos de manifesto (package.json,
requirements.txt, go.mod…), metadados de licença de pacotes de terceiros, o
histórico de autoria do Git e os NOMES de arquivos de configuração de
ferramentas de IA. Não lê os arquivos de código-fonte da aplicação e não envia
nada a ninguém: o cliente decide o que compartilhar (o relatório gerado).

Uso rápido:
    python3 prove_scan.py [caminho-do-projeto]

Opções principais (python3 prove_scan.py --ajuda mostra todas):
    --distribuicao saas|instalado|mobile|biblioteca|interno
    --gerar-modelo-contratos contratos.csv   cria a planilha já com os autores
    --contratos contratos.csv                cruza autores x contratos de cessão
    --ferramentas-autorizadas claude,copilot --politica-ia-desde 2025-01-01
    --online                                 consulta licenças em registros públicos
    --sbom arquivo.json                      importa SBOM CycloneDX/SPDX
    --anonimizar                             troca nomes por códigos (LGPD)
    --inpi                                   prepara pacote e hash para registro no INPI
    --verificar pasta-ou-json                confere se a saída foi alterada

Saída: prove_relatorio.md, prove_dados.json, prove_sbom.cdx.json e
prove_hashes.sha256. Requisitos: Python 3.8+, Git recomendado, nenhuma
dependência externa.
"""

import argparse
import csv
import glob
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

try:  # Python 3.11+
    import tomllib as _toml
except ImportError:  # pragma: no cover - depende da versão do Python
    try:
        import tomli as _toml
    except ImportError:
        _toml = None

VERSAO = "2.0.0"

ESCRITORIO = "D'Souza Advocacia Empresarial"
RESPONSAVEL = "Dr. Daniel de Souza · OAB/DF 71.124"
CONTATO = "danielssouza.com | (61) 98379-0033"

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

PROVEDORES_PESSOAIS = {
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.com.br", "outlook.com",
    "outlook.com.br", "live.com", "live.com.br", "msn.com", "yahoo.com", "yahoo.com.br",
    "icloud.com", "me.com", "mac.com", "aol.com", "bol.com.br", "uol.com.br",
    "terra.com.br", "ig.com.br", "globo.com", "r7.com", "proton.me", "protonmail.com",
    "pm.me", "tutanota.com", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
    "yandex.ru", "qq.com", "163.com", "126.com", "hey.com", "fastmail.com",
}
DOMINIOS_OCULTOS = ("users.noreply.github.com", "noreply.github.com",
                    "users.noreply.gitlab.com", "noreply.gitlab.com")

IGNORAR_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", "env",
    "__pycache__", ".next", ".nuxt", "bower_components", "Pods", ".gradle", "out",
    ".tox", ".mypy_cache", ".pytest_cache", "coverage", "site-packages", "testdata",
    "fixtures", "__fixtures__", ".terraform", ".idea", ".vscode",
}
# Arquivos que inflam a contagem de linhas sem representar autoria
ARQUIVOS_SEM_AUTORIA = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "poetry.lock",
    "uv.lock", "pdm.lock", "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock",
    "go.sum", "pubspec.lock", "packages.lock.json",
}

NOMES_GENERICOS = {"root", "admin", "administrator", "user", "ubuntu", "unknown", "dev",
                   "developer", "git", "test", "usuario", "jenkins", "ci", "build", "deploy",
                   "server", "local", "default", "github", "gitlab"}

RE_BOT = re.compile(r"\[bot\]|^dependabot|^renovate|github-actions|^greenkeeper|snyk-bot|"
                    r"semantic-release|^allcontributors|pre-commit-ci|^mergify|^imgbot|"
                    r"^codecov|^web-flow$|^github$", re.I)

# Identidades (e-mail) que indicam ferramenta de IA como autora ou coautora
IA_EMAIL = [
    (r"@anthropic\.com$|^(\d+\+)?claude\[bot\]@", "Claude (Anthropic)"),
    (r"copilot", "GitHub Copilot"),
    (r"cursoragent@cursor\.com|@cursor\.(com|sh)$", "Cursor"),
    (r"devin-ai-integration|@cognition(-labs)?\.(ai|com)$", "Devin"),
    (r"@openai\.com$|chatgpt-codex|codex\[bot\]", "OpenAI Codex/ChatGPT"),
    (r"google-labs-jules|gemini-code-assist", "Google Gemini/Jules"),
    (r"amazon-q-developer|amazonq", "Amazon Q"),
    (r"@codeium\.com$|@windsurf\.(com|ai)$", "Windsurf/Codeium"),
    (r"lovable-dev|@lovable\.dev$", "Lovable"),
    (r"sweep-ai", "Sweep"),
    (r"@aider\.chat$", "Aider"),
]
IA_NOMES = {
    "claude": "Claude (Anthropic)", "claude code": "Claude (Anthropic)",
    "github copilot": "GitHub Copilot", "copilot": "GitHub Copilot",
    "cursor": "Cursor", "cursor agent": "Cursor", "devin": "Devin", "devin ai": "Devin",
    "chatgpt": "OpenAI Codex/ChatGPT", "codex": "OpenAI Codex/ChatGPT",
    "openai codex": "OpenAI Codex/ChatGPT", "gemini": "Google Gemini/Jules",
    "jules": "Google Gemini/Jules", "amazon q": "Amazon Q", "windsurf": "Windsurf/Codeium",
    "codeium": "Windsurf/Codeium", "aider": "Aider", "cline": "Cline/Roo",
    "lovable": "Lovable",
}
RE_MARCA_IA = re.compile(
    r"generated\s+(?:with|by|using)\s+\[?(claude\s+code|claude|github\s+copilot|copilot|"
    r"cursor|chatgpt|codex|gemini|aider|devin|windsurf|amazon\s+q|jules)", re.I)
RE_COAUTOR = re.compile(r"^[ \t]*co-authored-by:[ \t]*(.*?)[ \t]*<([^>]*)>", re.I | re.M)

# Nomes de arquivos/pastas de configuração de ferramentas de IA (só o nome é lido)
IA_ARQUIVOS = {
    ".cursorrules": "Cursor", ".cursor": "Cursor", ".cursorignore": "Cursor",
    "CLAUDE.md": "Claude (Anthropic)", "CLAUDE.local.md": "Claude (Anthropic)",
    ".claude": "Claude (Anthropic)",
    ".github/copilot-instructions.md": "GitHub Copilot",
    ".github/instructions": "GitHub Copilot", ".github/prompts": "GitHub Copilot",
    ".aider.conf.yml": "Aider", ".aiderignore": "Aider",
    ".aider.chat.history.md": "Aider", ".aider.input.history": "Aider",
    ".windsurfrules": "Windsurf/Codeium", ".windsurf": "Windsurf/Codeium",
    ".codeium": "Windsurf/Codeium",
    "GEMINI.md": "Google Gemini/Jules", ".gemini": "Google Gemini/Jules",
    ".clinerules": "Cline/Roo", ".roo": "Cline/Roo", ".roomodes": "Cline/Roo",
    ".continue": "Continue", ".continuerc.json": "Continue",
    ".amazonq": "Amazon Q", ".tabnine": "Tabnine", ".junie": "JetBrains Junie",
    ".kiro": "Kiro", ".codex": "OpenAI Codex/ChatGPT",
    "AGENTS.md": "Agentes de IA (genérico)",
}
IGNORAR_IA = {".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
              ".tox", ".mypy_cache", ".pytest_cache", ".next", ".nuxt", ".gradle",
              "dist", "build", "target", "site-packages"}

CLASSES = {
    "copyleft_rede": "Copyleft de rede (AGPL, SSPL)",
    "copyleft_forte": "Copyleft forte (GPL)",
    "restritiva": "Restritiva / comercial (UNLICENSED, BUSL, Elastic, NC)",
    "copyleft_fraco": "Copyleft fraco (LGPL, MPL, EPL)",
    "nao_declarada": "Não declarada pelo mantenedor",
    "outra": "Outra / não reconhecida",
    "permissiva": "Permissiva (MIT, Apache, BSD…)",
    "nao_verificada": "Não verificada nesta varredura",
}
RANK = {"permissiva": 0, "copyleft_fraco": 1, "outra": 2, "nao_declarada": 2,
        "copyleft_forte": 3, "copyleft_rede": 4, "restritiva": 5}

DISTRIBUICOES = {
    "saas": "SaaS / acesso pela rede, sem entrega de software ao cliente",
    "instalado": "Software instalado, on-premise ou entregue ao cliente",
    "mobile": "Aplicativo móvel distribuído em lojas",
    "biblioteca": "Biblioteca ou SDK distribuído a terceiros",
    "interno": "Uso exclusivamente interno",
    "nao_informado": "Não informado (análise conservadora)",
}

ROT = {"vermelho": "🔴 VERMELHO", "amarelo": "🟡 AMARELO", "info": "⚪ INFORMATIVO",
       "verde": "🟢 VERDE"}
ORDEM_COR = {"vermelho": 0, "amarelo": 1, "info": 2, "verde": 3}
PRIORIDADE_ESCOPO = {"producao": 0, "opcional": 1, "desenvolvimento": 2}

LINGUAGENS = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".rb": "Ruby",
    ".php": "PHP", ".cs": "C#", ".fs": "F#", ".vb": "Visual Basic", ".rs": "Rust",
    ".c": "C", ".h": "C/C++", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".swift": "Swift", ".m": "Objective-C", ".dart": "Dart", ".ex": "Elixir",
    ".exs": "Elixir", ".erl": "Erlang", ".clj": "Clojure", ".hs": "Haskell",
    ".lua": "Lua", ".r": "R", ".sql": "SQL", ".sh": "Shell", ".ps1": "PowerShell",
    ".vue": "Vue", ".svelte": "Svelte", ".html": "HTML", ".css": "CSS", ".scss": "CSS",
    ".tf": "Terraform", ".sol": "Solidity", ".abap": "ABAP", ".cob": "COBOL",
    ".pas": "Pascal/Delphi", ".dpr": "Pascal/Delphi",
}


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def sh(args, cwd, timeout=600):
    """Executa um comando e devolve a saída (texto) ou "" em caso de falha."""
    try:
        r = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout)
        if r.returncode != 0:
            return ""
        return r.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def ler_texto(caminho, limite=None):
    try:
        with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(limite) if limite else f.read()
    except Exception:
        return None


def ler_json(caminho):
    t = ler_texto(caminho)
    if t is None:
        return None
    try:
        return json.loads(t)
    except Exception:
        return None


def ler_toml(caminho):
    t = ler_texto(caminho)
    if t is None:
        return None
    if _toml is not None:
        try:
            return _toml.loads(t)
        except Exception:
            pass
    return toml_simples(t)


def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def sem_acento(s):
    return unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode()


def norm_pessoa(s):
    return re.sub(r"[^a-z0-9]+", " ", sem_acento(s).lower()).strip()


def md(s):
    """Escapa texto para tabelas Markdown."""
    return str(s if s is not None else "—").replace("|", "\\|").replace("\n", " ")


def mascarar_email(e):
    if "@" not in e:
        return "***"
    local, dom = e.rsplit("@", 1)
    return (local[:1] or "") + "***@" + dom


# ---------------------------------------------------------------------------
# Leitor TOML mínimo (usado só quando o Python é anterior ao 3.11)
# ---------------------------------------------------------------------------

def _sem_comentario(linha):
    saida, aspas = [], None
    for ch in linha:
        if aspas:
            if ch == aspas:
                aspas = None
        elif ch in "\"'":
            aspas = ch
        elif ch == "#":
            break
        saida.append(ch)
    return "".join(saida)


def _chaves_toml(s):
    partes = []
    for a, b, c in re.findall(r'"([^"]*)"|\'([^\']*)\'|([^.\s]+)', s):
        partes.append(a or b or c)
    return partes


def _valor_toml(v):
    v = v.strip()
    if v[:1] in "\"'":
        return v[1:].split(v[0], 1)[0]
    if v.startswith("["):
        return [a or b for a, b in re.findall(r'"([^"]*)"|\'([^\']*)\'', v)]
    if v.startswith("{"):
        d = {}
        for k, val in re.findall(r'([\w\-.]+)\s*=\s*("[^"]*"|\'[^\']*\'|[^,}]+)', v):
            val = val.strip()
            d[k] = val[1:-1] if val[:1] in "\"'" else val
        return d
    return v


def toml_simples(texto):
    raiz = {}
    atual = raiz
    linhas = texto.splitlines()
    i = 0
    while i < len(linhas):
        s = _sem_comentario(linhas[i]).strip()
        i += 1
        if not s:
            continue
        m = re.match(r"^\[\[(.+)\]\]$", s)
        if m:
            partes = _chaves_toml(m.group(1))
            pai = raiz
            for p in partes[:-1]:
                pai = pai.setdefault(p, {})
                if isinstance(pai, list):
                    pai = pai[-1]
            lista = pai.setdefault(partes[-1], [])
            novo = {}
            lista.append(novo)
            atual = novo
            continue
        m = re.match(r"^\[(.+)\]$", s)
        if m:
            atual = raiz
            for p in _chaves_toml(m.group(1)):
                prox = atual.setdefault(p, {})
                if isinstance(prox, list):
                    prox = prox[-1]
                atual = prox
            continue
        m = re.match(r"^([A-Za-z0-9_\-.\"']+)\s*=\s*(.*)$", s)
        if not m:
            continue
        chave, valor = m.group(1), m.group(2)
        while (valor.startswith("[") and valor.count("[") > valor.count("]")) or \
              (valor.startswith("{") and valor.count("{") > valor.count("}")):
            if i >= len(linhas):
                break
            valor += " " + _sem_comentario(linhas[i]).strip()
            i += 1
        partes = _chaves_toml(chave)
        alvo = atual
        for p in partes[:-1]:
            alvo = alvo.setdefault(p, {})
        alvo[partes[-1]] = _valor_toml(valor)
    return raiz


# ---------------------------------------------------------------------------
# Licenças
# ---------------------------------------------------------------------------

_RE_PERMISSIVA = re.compile(
    r"(?<![A-Z0-9])(MIT|X11|ISC|0BSD|BSD|APACHE|ZLIB|CC0|WTFPL|PSF|PYTHON|BOOST|BSL-1\.0|"
    r"ARTISTIC|BLUEOAK|PUBLIC[\s-]?DOMAIN|HPND|UPL|NCSA|POSTGRESQL|OFL|CURL|UNICODE|W3C|"
    r"CC-?BY|UNLICENSE|PHP|RUBY|MS-PL|MSPL)(?![A-Z])")


def _classe_atomo(atomo):
    up = atomo.upper().strip()
    t = re.sub(r"[^A-Z0-9]", "", up)
    if not t or t in ("UNKNOWN", "NONE", "NOASSERTION", "UNDEFINED", "NULL", "NA"):
        return "nao_declarada"
    if t.startswith("UNLICENSED") or "PROPRIETAR" in t or t.startswith("COMMERCIAL") \
            or "ALLRIGHTSRESERVED" in t:
        return "restritiva"
    if t.startswith(("SEELICENSEIN", "SEELICENCEIN", "LICENSEREF")):
        return "outra"
    if "BUSL" in t or "BUSINESSSOURCE" in t or t.startswith("ELASTIC") \
            or "COMMONSCLAUSE" in t or "NONCOMMERCIAL" in t or re.search(r"CCBY(SA)?NC", t) \
            or "POLYFORM" in t:
        return "restritiva"
    if "LGPL" in t or "LESSERGENERALPUBLIC" in t or "LIBRARYGENERALPUBLIC" in t:
        return "copyleft_fraco"
    if "AGPL" in t or "AFFERO" in t or "SSPL" in t or "SERVERSIDEPUBLIC" in t:
        return "copyleft_rede"
    if "GPL" in t or "GENERALPUBLICLICENSE" in t or "EUPL" in t or t.startswith("OSL") \
            or "OPENSOFTWARELICENSE" in t:
        if "EXCEPTION" in t and "GPL" in t:
            return "copyleft_fraco"   # ex.: GPL com Classpath/GCC exception
        return "copyleft_forte"
    if any(x in t for x in ("MPL", "MOZILLA", "EPL", "ECLIPSE", "CDDL", "CPL", "CCBYSA", "ODBL")):
        return "copyleft_fraco"
    if _RE_PERMISSIVA.search(up):
        return "permissiva"
    return "outra"


def _classe_url(u):
    t = u.lower()
    m = re.search(r"licenses\.nuget\.org/([^/?#]+)", t)
    if m:
        return classificar_licenca(urllib.parse.unquote(m.group(1)))
    regras = (
        (r"agpl", "copyleft_rede"), (r"lgpl", "copyleft_fraco"),
        (r"gnu\.org/licenses/(old-licenses/)?gpl|/gpl-?[23]", "copyleft_forte"),
        (r"mozilla\.org/mpl|/mpl-?2", "copyleft_fraco"),
        (r"eclipse\.org/legal/epl|/epl-", "copyleft_fraco"),
        (r"apache\.org/licenses|/apache-?2", "permissiva"),
        (r"opensource\.org/licenses?/(mit|bsd|isc|0bsd|zlib)", "permissiva"),
        (r"/licenses/mit\b|mit-license", "permissiva"),
    )
    for padrao, classe in regras:
        if re.search(padrao, t):
            return classe
    return "outra"


_RE_OPS = re.compile(r"(\(|\)|\s+(?:AND|OR|WITH)\s+)", re.I)


def _tokens(expr):
    saida = []
    for parte in _RE_OPS.split(expr):
        if parte is None:
            continue
        p = parte.strip()
        if not p:
            continue
        up = p.upper()
        saida.append(up if up in ("AND", "OR", "WITH", "(", ")") else p)
    return saida


def _avaliar_expr(toks):
    pos = [0]

    def ver():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def tomar():
        t = ver()
        pos[0] += 1
        return t

    def atomo():
        t = tomar()
        if t is None or t in ("AND", "OR", "WITH", ")"):
            return "outra"
        if t == "(":
            r = ou()
            if ver() == ")":
                tomar()
            return r
        return _classe_atomo(t)

    def com_excecao():
        r = atomo()
        while ver() == "WITH":
            tomar()
            tomar()
            if r == "copyleft_forte":
                r = "copyleft_fraco"
        return r

    def e():
        r = com_excecao()
        while ver() is not None and ver() not in ("OR", ")"):
            if ver() == "AND":
                tomar()
            outro = com_excecao()
            r = r if RANK[r] >= RANK[outro] else outro       # AND: a mais restritiva
        return r

    def ou():
        r = e()
        while ver() == "OR":
            tomar()
            outro = e()
            r = r if RANK[r] <= RANK[outro] else outro       # OR: a menos restritiva
        return r

    return ou()


ASSINATURAS_TEXTO = [
    ("AGPL-3.0", ("GNU AFFERO GENERAL PUBLIC LICENSE",)),
    ("SSPL-1.0", ("SERVER SIDE PUBLIC LICENSE",)),
    ("BUSL-1.1", ("BUSINESS SOURCE LICENSE",)),
    ("Elastic-2.0", ("ELASTIC LICENSE",)),
    ("LGPL", ("GNU LESSER GENERAL PUBLIC LICENSE", "GNU LIBRARY GENERAL PUBLIC LICENSE")),
    ("GPL", ("GNU GENERAL PUBLIC LICENSE",)),
    ("MPL-2.0", ("MOZILLA PUBLIC LICENSE",)),
    ("EPL", ("ECLIPSE PUBLIC LICENSE",)),
    ("EUPL-1.2", ("EUROPEAN UNION PUBLIC LICEN",)),
    ("Apache-2.0", ("APACHE LICENSE",)),
    ("Unlicense", ("THIS IS FREE AND UNENCUMBERED SOFTWARE",)),
    ("ISC", ("PERMISSION TO USE, COPY, MODIFY, AND/OR DISTRIBUTE THIS SOFTWARE FOR ANY PURPOSE",)),
    ("MIT", ("PERMISSION IS HEREBY GRANTED, FREE OF CHARGE",)),
    ("BSD", ("REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS",)),
    ("CC0-1.0", ("CC0 1.0 UNIVERSAL",)),
    ("Zlib", ("THIS SOFTWARE IS PROVIDED 'AS-IS', WITHOUT ANY EXPRESS OR IMPLIED",)),
]


def identificar_texto(txt):
    """Identifica a licença a partir do texto de um arquivo LICENSE de terceiro."""
    if not txt:
        return None
    t = re.sub(r"\s+", " ", txt[:40000].upper())
    for spdx, frases in ASSINATURAS_TEXTO:
        if any(f in t for f in frases):
            return spdx
    return None


def normalizar_licenca_valor(v):
    if v is None:
        return None
    if isinstance(v, dict):
        v = v.get("type") or v.get("name") or v.get("id") or v.get("expression") or v.get("spdx")
    if isinstance(v, (list, tuple)):
        itens = [x for x in (normalizar_licenca_valor(i) for i in v) if x]
        if not itens:
            return None
        if len(itens) == 1:
            return itens[0]
        return " OR ".join("(%s)" % x if " " in x else x for x in itens)
    s = str(v).strip()
    return s or None


def classificar_licenca(lic):
    """Classe de risco de uma licença declarada (aceita expressões SPDX e texto livre)."""
    s = normalizar_licenca_valor(lic)
    if not s:
        return "nao_declarada"
    if len(s) > 200 or "\n" in s:
        spdx = identificar_texto(s)
        return classificar_licenca(spdx) if spdx else "outra"
    if "://" in s:
        return _classe_url(s)
    s = re.sub(r"\s+or\s+(?:any\s+)?(?:later|newer)(?:\s+version)?", "-or-later", s, flags=re.I)
    if re.fullmatch(r"[A-Za-z0-9.+\-]+(\s*/\s*[A-Za-z0-9.+\-]+)+", s):   # "MIT/Apache-2.0"
        s = re.sub(r"\s*/\s*", " OR ", s)
    return _avaliar_expr(_tokens(s))


RE_ARQ_LICENCA = re.compile(r"^(licen[cs]e|copying|unlicense)([-_.].*)?$", re.I)


def licenca_de_diretorio(d):
    """None = pasta inexistente; "" = pasta sem arquivo de licença; senão, a licença."""
    try:
        nomes = sorted(os.listdir(d))
    except OSError:
        return None
    achadas, tem_arquivo = [], False
    for n in nomes:
        p = os.path.join(d, n)
        if RE_ARQ_LICENCA.match(n) and os.path.isfile(p):
            tem_arquivo = True
            spdx = identificar_texto(ler_texto(p, 40000) or "")
            if spdx and spdx not in achadas:
                achadas.append(spdx)
    if achadas:
        return achadas[0] if len(achadas) == 1 else " OR ".join(achadas)
    return "LicenseRef-arquivo-nao-identificado" if tem_arquivo else ""


def parece_spdx(lic):
    s = re.sub(r"[()]", " ", lic or "")
    return bool(re.fullmatch(r"\s*[A-Za-z0-9.\-+]+(\s+(AND|OR|WITH)\s+[A-Za-z0-9.\-+]+)*\s*", s))


# ---------------------------------------------------------------------------
# Coleta de dependências
# ---------------------------------------------------------------------------

def norm_nome(eco, nome):
    n = nome.strip().lower()
    if eco == "pypi":
        n = re.sub(r"[-_.]+", "-", n)
    return n


def versao_exata(v):
    v = (v or "").strip()
    if v.startswith("=="):
        v = v[2:]
    elif v.startswith("="):
        v = v[1:]
    v = v.strip()
    if v.startswith("v"):
        v = v[1:]
    return v if re.fullmatch(r"\d+(\.\d+)*([\-+][0-9A-Za-z.\-+]*)?", v) else None


class Coleta(object):
    def __init__(self, raiz):
        self.raiz = raiz
        self.deps = {}
        self.manifestos = []
        self.licenca_projeto = None          # {"valor":…, "arquivo":…}
        self.internos = defaultdict(set)     # ecossistema -> nomes do próprio projeto
        self.prefixos = defaultdict(set)     # ecossistema -> prefixos/escopos próprios
        self.dirs_npm = set()

    def manifesto(self, rel, eco, analisado, obs=None):
        m = {"arquivo": rel, "ecossistema": eco, "analisado": analisado}
        if obs:
            m["obs"] = obs
        self.manifestos.append(m)

    def definir_licenca_projeto(self, valor, rel):
        valor = normalizar_licenca_valor(valor)
        if not valor:
            return
        raiz_rel = "/" not in rel
        if self.licenca_projeto is None or (raiz_rel and "/" in self.licenca_projeto["arquivo"]):
            self.licenca_projeto = {"valor": valor, "arquivo": rel}

    def add(self, eco, nome, versao="", escopo="producao", direta=True, manifesto=None,
            licenca=None, fonte=None, origem=None):
        nome = (nome or "").strip()
        if not nome:
            return None
        chave = (eco, norm_nome(eco, nome))
        versao = str(versao or "").strip()
        d = self.deps.get(chave)
        if d is None:
            d = {"nome": nome, "ecossistema": eco, "versao": versao, "escopo": escopo,
                 "direta": bool(direta), "licenca": None, "fonte_licenca": None,
                 "origem": origem or "terceiro", "manifestos": []}
            self.deps[chave] = d
        else:
            if escopo != "indeterminado":
                if d["escopo"] == "indeterminado" or \
                        PRIORIDADE_ESCOPO[escopo] < PRIORIDADE_ESCOPO[d["escopo"]]:
                    d["escopo"] = escopo
            d["direta"] = d["direta"] or bool(direta)
            if versao and (not d["versao"] or (versao_exata(versao) and not versao_exata(d["versao"]))):
                d["versao"] = versao
            if origem and d["origem"] == "terceiro":
                d["origem"] = origem
        if manifesto and manifesto not in d["manifestos"]:
            d["manifestos"].append(manifesto)
        if licenca:
            definir_licenca(d, licenca, fonte or "manifesto")
        return d


def definir_licenca(d, lic, fonte):
    """lic = None: nada a fazer; "" = a fonte confirma que não há licença declarada."""
    if lic is None or d.get("licenca"):
        return
    lic = normalizar_licenca_valor(lic) if lic != "" else ""
    if lic:
        d["licenca"] = lic
        d["fonte_licenca"] = fonte
    elif not d.get("licenca_ausente_em"):
        d["licenca_ausente_em"] = fonte


def _escopo_por_nome(nome_arquivo_ou_grupo, padrao="producao"):
    if re.search(r"(dev|test|lint|doc|type|check|ci|bench)", nome_arquivo_ou_grupo, re.I):
        return "desenvolvimento"
    return padrao


def _pep508(s):
    s = (s or "").split(";")[0].strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*(.*)$", s)
    if not m:
        return None, None, None
    resto = m.group(3).strip().strip("()")
    origem = None
    if resto.startswith("@"):
        origem = "interna" if re.match(r"@\s*file:", resto) else None
        resto = ""
    return m.group(1), resto, origem


# --- npm -------------------------------------------------------------------

def p_package_json(c, caminho, rel):
    d = ler_json(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "npm", False, "arquivo ilegível")
        return
    c.manifesto(rel, "npm", True)
    c.dirs_npm.add(os.path.dirname(caminho))
    nome = d.get("name")
    if isinstance(nome, str) and nome:
        c.internos["npm"].add(nome)
        if nome.startswith("@") and "/" in nome:
            c.prefixos["npm"].add(nome.split("/")[0] + "/")
    if d.get("license") or d.get("licenses"):
        c.definir_licenca_projeto(d.get("license") or d.get("licenses"), rel)
    for campo, escopo in (("dependencies", "producao"), ("devDependencies", "desenvolvimento"),
                          ("optionalDependencies", "opcional"), ("peerDependencies", "opcional")):
        sec = d.get(campo)
        if not isinstance(sec, dict):
            continue
        for n, v in sec.items():
            v = str(v)
            origem = "interna" if v.startswith(("workspace:", "file:", "link:", "portal:")) else None
            c.add("npm", n, v, escopo, True, rel, origem=origem)


def _origem_npm(resolved):
    if resolved and resolved.startswith("http") and not re.search(
            r"registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com", resolved):
        return "registro_privado"
    return None


def p_package_lock(c, caminho, rel):
    d = ler_json(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "npm", False, "arquivo ilegível")
        return
    c.manifesto(rel, "npm", True)
    pk = d.get("packages")
    if isinstance(pk, dict):
        for k, v in pk.items():
            if not isinstance(v, dict) or not k:
                continue
            if "node_modules/" not in k:
                if v.get("name"):
                    c.internos["npm"].add(v["name"])
                continue
            nome = v.get("name") or k.rsplit("node_modules/", 1)[1]
            if v.get("link"):
                c.internos["npm"].add(nome)
                continue
            if v.get("dev") or v.get("devOptional"):
                escopo = "desenvolvimento"
            elif v.get("optional"):
                escopo = "opcional"
            else:
                escopo = "producao"
            lic = v.get("license") or v.get("licenses")
            c.add("npm", nome, v.get("version", ""), escopo, False, rel,
                  licenca=lic, fonte="lockfile", origem=_origem_npm(v.get("resolved", "")))
        return

    def varrer(deps):
        for nome, v in (deps or {}).items():
            if not isinstance(v, dict):
                continue
            escopo = "desenvolvimento" if v.get("dev") else ("opcional" if v.get("optional") else "producao")
            c.add("npm", nome, v.get("version", ""), escopo, False, rel,
                  origem=_origem_npm(v.get("resolved", "")))
            varrer(v.get("dependencies"))
    varrer(d.get("dependencies"))


def p_yarn_lock(c, caminho, rel):
    t = ler_texto(caminho) or ""
    c.manifesto(rel, "npm", True)
    atual, interno = None, False
    for linha in t.splitlines():
        if not linha.strip() or linha.lstrip().startswith("#"):
            continue
        if not linha.startswith(" ") and linha.rstrip().endswith(":"):
            spec = linha.rstrip()[:-1].split(",")[0].strip().strip('"')
            if spec == "__metadata":
                atual = None
                continue
            i = spec.rfind("@")
            atual = spec[:i] if i > 0 else spec
            interno = bool(re.search(r"@(workspace|link|file|portal):", spec))
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', linha)
        if atual and m:
            c.add("npm", atual, m.group(1), "indeterminado", False, rel,
                  origem="interna" if interno else None)
            atual = None


def p_pnpm_lock(c, caminho, rel):
    t = ler_texto(caminho) or ""
    c.manifesto(rel, "npm", True)
    em, atual = False, None
    for linha in t.splitlines():
        if re.match(r"^\S", linha):
            em = linha.startswith("packages:")
            atual = None
            continue
        if not em:
            continue
        m = re.match(r"^  '?/?((?:@[^/@\s']+/)?[^@\s'/(]+)[@/]([^:'(\s]+)", linha)
        if m:
            atual = c.add("npm", m.group(1), m.group(2), "indeterminado", False, rel)
            continue
        if atual is not None and atual["escopo"] == "indeterminado":
            if re.match(r"^\s{4}dev:\s*true", linha):
                atual["escopo"] = "desenvolvimento"
            elif re.match(r"^\s{4}dev:\s*false", linha):
                atual["escopo"] = "producao"


# --- Python ----------------------------------------------------------------

def p_requirements(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "pypi", False, "arquivo ilegível")
        return
    c.manifesto(rel, "pypi", True)
    escopo = _escopo_por_nome(os.path.basename(caminho))
    for linha in t.splitlines():
        s = re.split(r"\s+#", linha)[0].strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith(("-e", "--editable")):
            m = re.search(r"#egg=([A-Za-z0-9_.\-]+)", s)
            if m:
                c.add("pypi", m.group(1), "", escopo, True, rel,
                      origem=None if "://" in s else "interna")
            continue
        if s.startswith("-"):
            continue
        nome, ver, origem = _pep508(s)
        if nome:
            c.add("pypi", nome, ver, escopo, True, rel, origem=origem)


def p_pyproject(c, caminho, rel):
    d = ler_toml(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "pypi", False, "arquivo ilegível")
        return
    c.manifesto(rel, "pypi", True)
    proj = d.get("project") or {}
    if proj.get("name"):
        c.internos["pypi"].add(norm_nome("pypi", proj["name"]))
    lic = proj.get("license")
    if isinstance(lic, dict):
        if lic.get("text"):
            lic = lic["text"]
        elif lic.get("file"):
            lic = identificar_texto(ler_texto(os.path.join(os.path.dirname(caminho), lic["file"]), 40000) or "")
        else:
            lic = None
    if lic:
        c.definir_licenca_projeto(lic, rel)

    def adicionar(lista, escopo):
        for s in lista or []:
            if isinstance(s, str):
                n, v, o = _pep508(s)
                if n:
                    c.add("pypi", n, v, escopo, True, rel, origem=o)

    adicionar(proj.get("dependencies"), "producao")
    for grupo, lst in (proj.get("optional-dependencies") or {}).items():
        adicionar(lst, _escopo_por_nome(grupo, "opcional"))
    for grupo, lst in (d.get("dependency-groups") or {}).items():
        adicionar(lst, "desenvolvimento")
    tool = d.get("tool") or {}
    adicionar((tool.get("uv") or {}).get("dev-dependencies"), "desenvolvimento")
    for grupo, lst in ((tool.get("pdm") or {}).get("dev-dependencies") or {}).items():
        adicionar(lst, "desenvolvimento")

    poetry = tool.get("poetry") or {}
    if poetry.get("name"):
        c.internos["pypi"].add(norm_nome("pypi", poetry["name"]))
    if poetry.get("license"):
        c.definir_licenca_projeto(poetry["license"], rel)

    def poetry_deps(tab, escopo):
        for n, v in (tab or {}).items():
            if n.lower() == "python":
                continue
            origem, esc = None, escopo
            if isinstance(v, dict):
                if "path" in v:
                    origem = "interna"
                if str(v.get("optional", "")).lower() == "true" and escopo == "producao":
                    esc = "opcional"
                v = v.get("version", "")
            c.add("pypi", n, v, esc, True, rel, origem=origem)

    poetry_deps(poetry.get("dependencies"), "producao")
    poetry_deps(poetry.get("dev-dependencies"), "desenvolvimento")
    for g, gd in (poetry.get("group") or {}).items():
        if isinstance(gd, dict):
            poetry_deps(gd.get("dependencies"), "producao" if g == "main" else "desenvolvimento")


def p_pipfile(c, caminho, rel):
    d = ler_toml(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "pypi", False, "arquivo ilegível")
        return
    c.manifesto(rel, "pypi", True)
    for sec, escopo in (("packages", "producao"), ("dev-packages", "desenvolvimento")):
        for n, v in (d.get(sec) or {}).items():
            origem = None
            if isinstance(v, dict):
                origem = "interna" if "path" in v else None
                v = v.get("version", "")
            c.add("pypi", n, "" if v == "*" else v, escopo, True, rel, origem=origem)


def p_pipfile_lock(c, caminho, rel):
    d = ler_json(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "pypi", False, "arquivo ilegível")
        return
    c.manifesto(rel, "pypi", True)
    for sec, escopo in (("default", "producao"), ("develop", "desenvolvimento")):
        for n, v in (d.get(sec) or {}).items():
            ver = v.get("version", "") if isinstance(v, dict) else ""
            c.add("pypi", n, ver, escopo, False, rel)


def p_py_lock(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "pypi", False, "arquivo ilegível")
        return
    c.manifesto(rel, "pypi", True)
    for bloco in re.split(r"(?m)^\[\[package\]\]\s*$", t)[1:]:
        corpo = re.split(r"(?m)^\[", bloco)[0]
        mn = re.search(r'(?m)^name\s*=\s*"([^"]+)"', corpo)
        if not mn:
            continue
        mv = re.search(r'(?m)^version\s*=\s*"([^"]+)"', corpo)
        mc = re.search(r'(?m)^category\s*=\s*"([^"]+)"', corpo)
        if re.search(r'(?m)^source\s*=\s*\{[^}]*(editable|virtual|path)\s*=', corpo):
            c.internos["pypi"].add(norm_nome("pypi", mn.group(1)))
            continue
        escopo = "indeterminado"
        if mc:
            escopo = "desenvolvimento" if mc.group(1) == "dev" else "producao"
        c.add("pypi", mn.group(1), mv.group(1) if mv else "", escopo, False, rel)


# --- Go --------------------------------------------------------------------

def p_go_mod(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "go", False, "arquivo ilegível")
        return
    c.manifesto(rel, "go", True)
    dentro = False
    locais = set()
    for linha in t.splitlines():
        s = linha.strip()
        m = re.match(r"^module\s+(\S+)", s)
        if m:
            mod = m.group(1).strip('"')
            c.internos["go"].add(mod)
            partes = mod.split("/")
            if len(partes) >= 3:
                c.prefixos["go"].add("/".join(partes[:2]) + "/")
            continue
        r = re.match(r"^(?:replace\s+)?(\S+)(?:\s+v\S+)?\s+=>\s+(\.{1,2}/\S*|/\S+)", s)
        if r:
            locais.add(r.group(1))
            continue
        if s.startswith("require ("):
            dentro = True
            continue
        if dentro and s.startswith(")"):
            dentro = False
            continue
        mm = re.match(r"^(?:require\s+)?([^\s()]+)\s+(v[^\s]+)(.*)$", s)
        if mm and (dentro or s.startswith("require ")):
            indireta = "// indirect" in mm.group(3)
            c.add("go", mm.group(1), mm.group(2), "indeterminado" if indireta else "producao",
                  not indireta, rel)
    for n in locais:
        d = c.deps.get(("go", norm_nome("go", n)))
        if d:
            d["origem"] = "interna"


# --- Rust ------------------------------------------------------------------

def p_cargo_toml(c, caminho, rel):
    d = ler_toml(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "cargo", False, "arquivo ilegível")
        return
    c.manifesto(rel, "cargo", True)
    pkg = d.get("package") or {}
    if pkg.get("name"):
        c.internos["cargo"].add(pkg["name"])
    if isinstance(pkg.get("license"), str):
        c.definir_licenca_projeto(pkg["license"], rel)

    def secoes(tab):
        return [(tab.get("dependencies"), "producao"), (tab.get("dev-dependencies"), "desenvolvimento"),
                (tab.get("build-dependencies"), "desenvolvimento")]

    todas = secoes(d)
    for tgt in (d.get("target") or {}).values():
        if isinstance(tgt, dict):
            todas += secoes(tgt)
    todas.append(((d.get("workspace") or {}).get("dependencies"), "producao"))
    for sec, escopo in todas:
        if not isinstance(sec, dict):
            continue
        for n, v in sec.items():
            origem, esc, ver = None, escopo, v
            if isinstance(v, dict):
                if v.get("workspace") in (True, "true"):
                    continue
                n = v.get("package", n)
                ver = v.get("version", "")
                if "path" in v:
                    origem = "interna"
                if str(v.get("optional", "")).lower() == "true" and escopo == "producao":
                    esc = "opcional"
            c.add("cargo", n, ver, esc, True, rel, origem=origem)


def p_cargo_lock(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "cargo", False, "arquivo ilegível")
        return
    c.manifesto(rel, "cargo", True)
    for bloco in re.split(r"(?m)^\[\[package\]\]\s*$", t)[1:]:
        mn = re.search(r'(?m)^name\s*=\s*"([^"]+)"', bloco)
        mv = re.search(r'(?m)^version\s*=\s*"([^"]+)"', bloco)
        if not mn:
            continue
        if not re.search(r'(?m)^source\s*=', bloco):
            c.internos["cargo"].add(mn.group(1))
            continue
        c.add("cargo", mn.group(1), mv.group(1) if mv else "", "indeterminado", False, rel)


# --- PHP -------------------------------------------------------------------

def _composer_ignorar(n):
    return n == "php" or n.startswith(("ext-", "lib-")) or n in ("composer-plugin-api", "composer-runtime-api")


def p_composer_json(c, caminho, rel):
    d = ler_json(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "composer", False, "arquivo ilegível")
        return
    c.manifesto(rel, "composer", True)
    if d.get("name"):
        c.internos["composer"].add(d["name"])
    if d.get("license"):
        c.definir_licenca_projeto(d["license"], rel)
    for sec, escopo in (("require", "producao"), ("require-dev", "desenvolvimento")):
        for n, v in (d.get(sec) or {}).items():
            if not _composer_ignorar(n):
                c.add("composer", n, v, escopo, True, rel)


def p_composer_lock(c, caminho, rel):
    d = ler_json(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "composer", False, "arquivo ilegível")
        return
    c.manifesto(rel, "composer", True)
    for sec, escopo in (("packages", "producao"), ("packages-dev", "desenvolvimento")):
        for p in d.get(sec) or []:
            if isinstance(p, dict) and p.get("name"):
                lic = p.get("license")
                c.add("composer", p["name"], p.get("version", ""), escopo, False, rel,
                      licenca=lic if lic else None, fonte="lockfile")
                if lic == []:
                    definir_licenca(c.deps[("composer", norm_nome("composer", p["name"]))], "", "lockfile")


# --- Ruby ------------------------------------------------------------------

def p_gemfile(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "rubygems", False, "arquivo ilegível")
        return
    c.manifesto(rel, "rubygems", True)
    grupo_dev = 0
    for linha in t.splitlines():
        s = linha.strip()
        if re.match(r"^group\b.*\bdo\b", s):
            grupo_dev = 2 if re.search(r":(development|test)", s) else 1
            continue
        if s == "end" and grupo_dev:
            grupo_dev = 0
            continue
        m = re.match(r"""^gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?(.*)$""", s)
        if m:
            escopo = "desenvolvimento" if grupo_dev == 2 or re.search(
                r"group:\s*\[?:?(development|test)", m.group(3) or "") else "producao"
            origem = "interna" if re.search(r"path:", m.group(3) or "") else None
            c.add("rubygems", m.group(1), m.group(2) or "", escopo, True, rel, origem=origem)


def p_gemfile_lock(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "rubygems", False, "arquivo ilegível")
        return
    c.manifesto(rel, "rubygems", True)
    secao = None
    for linha in t.splitlines():
        if re.match(r"^[A-Z]", linha):
            secao = linha.strip()
            continue
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$", linha)
        if m and secao in ("GEM", "GIT", "PATH"):
            c.add("rubygems", m.group(1), m.group(2), "indeterminado", False, rel,
                  origem="interna" if secao == "PATH" else None)


# --- Java / Kotlin ---------------------------------------------------------

def _tag(e):
    return e.tag.split("}")[-1] if isinstance(e.tag, str) else ""


def _filho(e, nome):
    if e is None:
        return None
    for x in e:
        if _tag(x) == nome:
            return x
    return None


def _texto(e, nome):
    x = _filho(e, nome)
    return (x.text or "").strip() if x is not None and x.text else ""


def p_pom(c, caminho, rel):
    try:
        raiz = ET.parse(caminho).getroot()
    except Exception:
        c.manifesto(rel, "maven", False, "arquivo ilegível")
        return
    c.manifesto(rel, "maven", True)
    props = {}
    p = _filho(raiz, "properties")
    if p is not None:
        for x in p:
            props[_tag(x)] = (x.text or "").strip()
    pai = _filho(raiz, "parent")
    g = _texto(raiz, "groupId") or _texto(pai, "groupId")
    a = _texto(raiz, "artifactId")
    props["project.version"] = _texto(raiz, "version") or _texto(pai, "version")
    props["project.groupId"] = g
    if g and a:
        c.internos["maven"].add("%s:%s" % (g, a))
        c.prefixos["maven"].add(g + ":")
    lics = _filho(raiz, "licenses")
    if lics is not None:
        nomes = [_texto(l, "name") for l in lics if _texto(l, "name")]
        if nomes:
            c.definir_licenca_projeto(nomes, rel)
    deps = _filho(raiz, "dependencies")
    for dep in (deps if deps is not None else []):
        gg, aa = _texto(dep, "groupId"), _texto(dep, "artifactId")
        if not gg or not aa:
            continue
        gg = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), gg)
        v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), _texto(dep, "version"))
        scope = _texto(dep, "scope")
        escopo = "desenvolvimento" if scope == "test" else "producao"
        if _texto(dep, "optional") == "true":
            escopo = "opcional"
        c.add("maven", "%s:%s" % (gg, aa), v, escopo, True, rel)


RE_GRADLE = re.compile(
    r"""\b(implementation|api|compile|runtime|compileOnly|runtimeOnly|annotationProcessor|kapt|ksp|"""
    r"""testImplementation|testCompile|testRuntimeOnly|testCompileOnly|androidTestImplementation|"""
    r"""debugImplementation|releaseImplementation|classpath)\s*\(?\s*(?:platform\s*\(\s*)?"""
    r"""["']([^"':\s]+):([^"':\s]+)(?::([^"'\s]+))?["']""")


def p_gradle(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "maven", False, "arquivo ilegível")
        return
    c.manifesto(rel, "maven", True)
    for m in RE_GRADLE.finditer(t):
        conf = m.group(1)
        escopo = "desenvolvimento" if re.match(
            r"(test|androidTest|debug|kapt|ksp|annotationProcessor|compileOnly|classpath)", conf) else "producao"
        c.add("maven", "%s:%s" % (m.group(2), m.group(3)), m.group(4) or "", escopo, True, rel)


def p_gradle_catalogo(c, caminho, rel):
    d = ler_toml(caminho)
    if not isinstance(d, dict):
        c.manifesto(rel, "maven", False, "arquivo ilegível")
        return
    c.manifesto(rel, "maven", True)
    versoes = d.get("versions") or {}
    for _, v in (d.get("libraries") or {}).items():
        ver = ""
        if isinstance(v, str):
            partes = v.split(":")
            if len(partes) < 2:
                continue
            mod, ver = ":".join(partes[:2]), (partes[2] if len(partes) > 2 else "")
        elif isinstance(v, dict):
            mod = v.get("module") or ("%s:%s" % (v.get("group"), v.get("name")) if v.get("group") else None)
            if not mod:
                continue
            vv = v.get("version")
            if isinstance(vv, dict):
                vv = versoes.get(vv.get("ref"), "")
            elif v.get("version.ref"):
                vv = versoes.get(v.get("version.ref"), "")
            ver = vv if isinstance(vv, str) else ""
        else:
            continue
        c.add("maven", mod, ver, "indeterminado", True, rel)


# --- .NET ------------------------------------------------------------------

def p_dotnet(c, caminho, rel):
    try:
        raiz = ET.parse(caminho).getroot()
    except Exception:
        c.manifesto(rel, "nuget", False, "arquivo ilegível")
        return
    c.manifesto(rel, "nuget", True)
    for el in raiz.iter():
        tag = _tag(el)
        if tag in ("PackageReference", "PackageVersion"):
            n = el.get("Include") or el.get("Update")
            v = el.get("Version") or _texto(el, "Version")
            dev = (el.get("PrivateAssets") or _texto(el, "PrivateAssets")).lower() == "all"
            if n:
                c.add("nuget", n, v or "", "desenvolvimento" if dev else "producao", True, rel)
        elif tag == "package" and el.get("id"):
            dev = (el.get("developmentDependency") or "").lower() == "true"
            c.add("nuget", el.get("id"), el.get("version", ""), "desenvolvimento" if dev else "producao", True, rel)


# --- Dart / Flutter --------------------------------------------------------

SDK_FLUTTER = {"flutter", "flutter_test", "flutter_localizations", "integration_test",
               "flutter_driver", "flutter_web_plugins"}


def p_pubspec(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "pub", False, "arquivo ilegível")
        return
    c.manifesto(rel, "pub", True)
    secao = None
    for linha in t.splitlines():
        if re.match(r"^\S", linha):
            m = re.match(r"^(dependencies|dev_dependencies):", linha)
            secao = m.group(1) if m else None
            if re.match(r"^name:\s*(\S+)", linha):
                c.internos["pub"].add(re.match(r"^name:\s*(\S+)", linha).group(1))
            continue
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*(.*)$", linha)
        if secao and m and m.group(1) not in SDK_FLUTTER:
            ver = m.group(2).strip().strip("'\"")
            c.add("pub", m.group(1), ver, "desenvolvimento" if secao == "dev_dependencies" else "producao", True, rel)


def p_pubspec_lock(c, caminho, rel):
    t = ler_texto(caminho)
    if t is None:
        c.manifesto(rel, "pub", False, "arquivo ilegível")
        return
    c.manifesto(rel, "pub", True)
    em, atual, info = False, None, {}

    def gravar():
        if not atual or info.get("source") == "sdk":
            return
        dep = info.get("dependency", "")
        escopo = "desenvolvimento" if "dev" in dep else ("producao" if "main" in dep else "indeterminado")
        c.add("pub", atual, info.get("version", ""), escopo, "direct" in dep, rel,
              origem="interna" if info.get("source") == "path" else None)

    for linha in t.splitlines():
        if re.match(r"^\S", linha):
            if em:
                gravar()
                atual = None
            em = linha.startswith("packages:")
            continue
        if not em:
            continue
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", linha)
        if m:
            gravar()
            atual, info = m.group(1), {}
            continue
        m = re.match(r'^    (dependency|version|source):\s*"?([^"]+?)"?\s*$', linha)
        if m and atual:
            info[m.group(1)] = m.group(2)
    if em:
        gravar()


PARSERS = {
    "package.json": p_package_json, "package-lock.json": p_package_lock,
    "npm-shrinkwrap.json": p_package_lock, "yarn.lock": p_yarn_lock, "pnpm-lock.yaml": p_pnpm_lock,
    "pyproject.toml": p_pyproject, "Pipfile": p_pipfile, "Pipfile.lock": p_pipfile_lock,
    "poetry.lock": p_py_lock, "uv.lock": p_py_lock, "pdm.lock": p_py_lock,
    "go.mod": p_go_mod, "Cargo.toml": p_cargo_toml, "Cargo.lock": p_cargo_lock,
    "composer.json": p_composer_json, "composer.lock": p_composer_lock,
    "Gemfile": p_gemfile, "Gemfile.lock": p_gemfile_lock,
    "pom.xml": p_pom, "build.gradle": p_gradle, "build.gradle.kts": p_gradle,
    "libs.versions.toml": p_gradle_catalogo,
    "packages.config": p_dotnet, "Directory.Packages.props": p_dotnet,
    "pubspec.yaml": p_pubspec, "pubspec.lock": p_pubspec_lock,
}
SUFIXOS = {".csproj": p_dotnet, ".fsproj": p_dotnet, ".vbproj": p_dotnet}
NAO_ANALISADOS = {
    "setup.py": "pypi", "setup.cfg": "pypi", "environment.yml": "conda", "Podfile": "cocoapods",
    "Package.swift": "swift", "mix.exs": "hex", "deps.edn": "clojure", "project.clj": "clojure",
    "build.sbt": "scala", "conanfile.txt": "conan", "conanfile.py": "conan", "vcpkg.json": "vcpkg",
    "rebar.config": "erlang", "stack.yaml": "haskell", "Cartfile": "carthage", "bun.lockb": "npm",
}
ECO_DO_ARQUIVO = {
    "package.json": "npm", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm", "pyproject.toml": "pypi", "Pipfile": "pypi", "Pipfile.lock": "pypi",
    "poetry.lock": "pypi", "uv.lock": "pypi", "pdm.lock": "pypi", "go.mod": "go",
    "Cargo.toml": "cargo", "Cargo.lock": "cargo", "composer.json": "composer", "composer.lock": "composer",
    "Gemfile": "rubygems", "Gemfile.lock": "rubygems", "pom.xml": "maven", "build.gradle": "maven",
    "build.gradle.kts": "maven", "libs.versions.toml": "maven", "packages.config": "nuget",
    "Directory.Packages.props": "nuget", "pubspec.yaml": "pub", "pubspec.lock": "pub",
}


def parser_para(nome):
    if nome in PARSERS:
        return PARSERS[nome]
    for suf, f in SUFIXOS.items():
        if nome.endswith(suf):
            return f
    baixo = nome.lower()
    if "requirements" in baixo and baixo.endswith((".txt", ".in")):
        return p_requirements
    return None


def achar_manifests(raiz):
    achados = []
    for base, dirs, arqs in os.walk(raiz):
        rel_base = os.path.relpath(base, raiz)
        prof = 0 if rel_base == "." else rel_base.count(os.sep) + 1
        dirs[:] = sorted(d for d in dirs if d not in IGNORAR_DIRS and not d.startswith("."))
        if prof >= 6:
            dirs[:] = []
        for a in sorted(arqs):
            if parser_para(a) or a in NAO_ANALISADOS:
                achados.append(os.path.join(base, a))
    return achados


def coletar_manifestos(c):
    for p in achar_manifests(c.raiz):
        a = os.path.basename(p)
        rel = os.path.relpath(p, c.raiz).replace(os.sep, "/")
        f = parser_para(a)
        if f is None:
            c.manifesto(rel, NAO_ANALISADOS.get(a, "outro"), False, "formato ainda não suportado")
            continue
        try:
            f(c, p, rel)
        except Exception as e:  # um manifesto quebrado não pode derrubar a varredura
            c.manifesto(rel, ECO_DO_ARQUIVO.get(a, "?"), False, "erro de leitura: %s" % e.__class__.__name__)


# ---------------------------------------------------------------------------
# Resolução local de licenças (metadados de pacotes já instalados)
# ---------------------------------------------------------------------------

def licencas_npm_instaladas(dirs_projeto):
    mapa = {}

    def ler_pacote(nome, pasta):
        pj = ler_json(os.path.join(pasta, "package.json"))
        if not isinstance(pj, dict):
            return
        lic = normalizar_licenca_valor(pj.get("license") or pj.get("licenses"))
        if not lic:
            lic = licenca_de_diretorio(pasta)
        if nome not in mapa or (not mapa[nome] and lic):
            mapa[nome] = lic if lic is not None else ""

    def varrer(nm, prof):
        try:
            entradas = os.listdir(nm)
        except OSError:
            return
        for e in entradas:
            if e.startswith("."):
                continue
            pastas = []
            if e.startswith("@"):
                try:
                    pastas = [("%s/%s" % (e, x), os.path.join(nm, e, x)) for x in os.listdir(os.path.join(nm, e))]
                except OSError:
                    continue
            else:
                pastas = [(e, os.path.join(nm, e))]
            for nome, pasta in pastas:
                ler_pacote(nome, pasta)
                sub = os.path.join(pasta, "node_modules")
                if prof < 3 and os.path.isdir(sub):
                    varrer(sub, prof + 1)

    for d in dirs_projeto:
        varrer(os.path.join(d, "node_modules"), 0)
    return mapa


def _site_packages(raiz):
    bases = [os.path.join(raiz, v) for v in (".venv", "venv", "env", "virtualenv")]
    for var in ("VIRTUAL_ENV", "CONDA_PREFIX"):
        if os.environ.get(var):
            bases.append(os.environ[var])
    dirs = []
    for b in bases:
        if not os.path.isdir(b):
            continue
        for padrao in (("lib", "python*", "site-packages"), ("lib64", "python*", "site-packages"),
                       ("Lib", "site-packages")):
            dirs += glob.glob(os.path.join(b, *padrao))
    vistos, saida = set(), []
    for d in dirs:
        r = os.path.realpath(d)
        if r not in vistos:
            vistos.add(r)
            saida.append(d)
    return saida


def _licenca_dist_python(pasta):
    meta = None
    for nome in ("METADATA", "PKG-INFO"):
        meta = ler_texto(os.path.join(pasta, nome), 300000)
        if meta:
            break
    if not meta:
        return None, None
    cab = meta.split("\n\n", 1)[0]
    nome_pkg = expr = lic = None
    classif = []
    for l in cab.splitlines():
        if l.startswith("Name:"):
            nome_pkg = l[5:].strip()
        elif l.startswith("License-Expression:"):
            expr = l.split(":", 1)[1].strip()
        elif l.startswith("License:"):
            lic = l.split(":", 1)[1].strip()
        elif l.startswith("Classifier: License ::"):
            ult = l.split("::")[-1].strip()
            if ult and ult != "OSI Approved":
                classif.append(ult)
    if expr:
        return nome_pkg, expr
    if classif:
        return nome_pkg, " OR ".join("(%s)" % x for x in classif) if len(classif) > 1 else classif[0]
    if lic and lic.upper() not in ("UNKNOWN", "NONE") and len(lic) < 200:
        return nome_pkg, lic
    for arq in sorted(glob.glob(os.path.join(pasta, "licenses", "*")) + glob.glob(os.path.join(pasta, "LICEN*"))
                      + glob.glob(os.path.join(pasta, "COPYING*"))):
        if os.path.isfile(arq):
            spdx = identificar_texto(ler_texto(arq, 40000) or "")
            if spdx:
                return nome_pkg, spdx
    if lic and len(lic) >= 200:
        spdx = identificar_texto(lic)
        if spdx:
            return nome_pkg, spdx
    return nome_pkg, ""


def licencas_python_instaladas(raiz):
    mapa = {}
    for sp in _site_packages(raiz):
        for pasta in glob.glob(os.path.join(sp, "*.dist-info")) + glob.glob(os.path.join(sp, "*.egg-info")):
            nome, lic = _licenca_dist_python(pasta)
            if nome:
                chave = norm_nome("pypi", nome)
                if chave not in mapa or (not mapa[chave] and lic):
                    mapa[chave] = lic
    return mapa


def _home(*partes):
    return os.path.join(os.path.expanduser("~"), *partes)


def _go_modcache():
    if os.environ.get("GOMODCACHE"):
        return os.environ["GOMODCACHE"]
    if os.environ.get("GOPATH"):
        return os.path.join(os.environ["GOPATH"].split(os.pathsep)[0], "pkg", "mod")
    return _home("go", "pkg", "mod")


def resolver_licencas_locais(c):
    pend = lambda eco: [d for d in c.deps.values() if d["ecossistema"] == eco and not d["licenca"]]

    if pend("npm"):
        mapa = licencas_npm_instaladas(c.dirs_npm or {c.raiz})
        for d in pend("npm"):
            if d["nome"] in mapa:
                definir_licenca(d, mapa[d["nome"]], "instalado")

    if pend("pypi"):
        mapa = licencas_python_instaladas(c.raiz)
        for d in pend("pypi"):
            k = norm_nome("pypi", d["nome"])
            if k in mapa:
                definir_licenca(d, mapa[k], "instalado")

    if pend("go"):
        cache = _go_modcache()
        for d in pend("go"):
            esc = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), d["nome"])
            for pasta in (os.path.join(c.raiz, "vendor", *d["nome"].split("/")),
                          os.path.join(cache, *("%s@%s" % (esc, d["versao"])).split("/"))):
                lic = licenca_de_diretorio(pasta)
                if lic is not None:
                    definir_licenca(d, lic, "instalado")
                    break

    if pend("cargo"):
        cargo_home = os.environ.get("CARGO_HOME") or _home(".cargo")
        for d in pend("cargo"):
            cands = glob.glob(os.path.join(cargo_home, "registry", "src", "*", "%s-%s" % (d["nome"], d["versao"])))
            cands.append(os.path.join(c.raiz, "vendor", d["nome"]))
            for pasta in cands:
                t = ler_texto(os.path.join(pasta, "Cargo.toml"))
                if t is None:
                    continue
                m = re.search(r'(?m)^license\s*=\s*"([^"]+)"', t)
                lic = m.group(1) if m else licenca_de_diretorio(pasta)
                definir_licenca(d, lic, "instalado")
                break

    if pend("composer"):
        for d in pend("composer"):
            pj = ler_json(os.path.join(c.raiz, "vendor", *d["nome"].split("/"), "composer.json"))
            if isinstance(pj, dict):
                definir_licenca(d, normalizar_licenca_valor(pj.get("license")) or "", "instalado")

    if pend("rubygems"):
        specs = []
        for base in filter(None, [os.environ.get("GEM_HOME"), "/usr/local/bundle"]):
            specs += glob.glob(os.path.join(base, "specifications"))
        specs += glob.glob(_home(".gem", "ruby", "*", "specifications"))
        specs += glob.glob(os.path.join(c.raiz, "vendor", "bundle", "ruby", "*", "specifications"))
        for d in pend("rubygems"):
            for sdir in specs:
                arq = os.path.join(sdir, "%s-%s.gemspec" % (d["nome"], d["versao"]))
                t = ler_texto(arq)
                if t is None:
                    continue
                m = re.search(r"\.licenses?\s*=\s*\[?([^\]\n]+)", t)
                lics = re.findall(r"""["']([^"']+)["']""", m.group(1)) if m else []
                definir_licenca(d, lics if lics else "", "instalado")
                break

    if pend("maven"):
        m2 = _home(".m2", "repository")
        gradle = _home(".gradle", "caches", "modules-2", "files-2.1")
        for d in pend("maven"):
            if ":" not in d["nome"] or not d["versao"] or "$" in d["versao"]:
                continue
            g, a = d["nome"].split(":", 1)
            cands = [os.path.join(m2, *g.split("."), a, d["versao"], "%s-%s.pom" % (a, d["versao"]))]
            cands += glob.glob(os.path.join(gradle, g, a, d["versao"], "*", "%s-%s.pom" % (a, d["versao"])))
            for pom in cands:
                try:
                    r = ET.parse(pom).getroot()
                except Exception:
                    continue
                lics = _filho(r, "licenses")
                nomes = [_texto(l, "name") for l in (lics if lics is not None else []) if _texto(l, "name")]
                if nomes:   # sem <licenses> o pom pode herdar do pai: não concluímos ausência
                    definir_licenca(d, nomes, "instalado")
                break

    if pend("nuget"):
        base = os.environ.get("NUGET_PACKAGES") or _home(".nuget", "packages")
        for d in pend("nuget"):
            pasta = os.path.join(base, d["nome"].lower(), d["versao"].lower())
            arq = os.path.join(pasta, "%s.nuspec" % d["nome"].lower())
            try:
                r = ET.parse(arq).getroot()
            except Exception:
                continue
            meta = _filho(r, "metadata")
            lic_el = _filho(meta, "license")
            lic = None
            if lic_el is not None and lic_el.text:
                if lic_el.get("type") == "file":
                    lic = identificar_texto(ler_texto(os.path.join(pasta, lic_el.text.strip()), 40000) or "") \
                        or "LicenseRef-arquivo-nao-identificado"
                else:
                    lic = lic_el.text.strip()
            elif _texto(meta, "licenseUrl"):
                lic = _texto(meta, "licenseUrl")
            definir_licenca(d, lic if lic else "", "instalado")

    if pend("pub"):
        base = os.environ.get("PUB_CACHE") or _home(".pub-cache")
        for d in pend("pub"):
            lic = licenca_de_diretorio(os.path.join(base, "hosted", "pub.dev", "%s-%s" % (d["nome"], d["versao"])))
            if lic is not None:
                definir_licenca(d, lic, "instalado")


# ---------------------------------------------------------------------------
# SBOM: importação (CycloneDX / SPDX) e exportação (CycloneDX 1.5)
# ---------------------------------------------------------------------------

PURL_ECO = {"npm": "npm", "pypi": "pypi", "golang": "go", "maven": "maven", "cargo": "cargo",
            "composer": "composer", "gem": "rubygems", "nuget": "nuget", "pub": "pub"}
ECO_PURL = {v: k for k, v in PURL_ECO.items()}


def de_purl(purl):
    if not purl or not purl.startswith("pkg:"):
        return None, None, None
    s = purl[4:].split("#")[0].split("?")[0]
    tipo, _, resto = s.partition("/")
    eco = PURL_ECO.get(tipo.lower())
    if not eco:
        return None, None, None
    versao = ""
    if "@" in resto:
        resto, versao = resto.rsplit("@", 1)
    partes = [urllib.parse.unquote(p) for p in resto.split("/")]
    if eco == "maven" and len(partes) >= 2:
        nome = "%s:%s" % (partes[0], partes[1])
    else:
        nome = "/".join(partes)
    return eco, nome, urllib.parse.unquote(versao)


def para_purl(d):
    eco, n = d["ecossistema"], d["nome"]
    tipo = ECO_PURL.get(eco)
    if not tipo:
        return None
    v = d["versao"] if (eco == "go" and re.match(r"^v\d", d["versao"] or "")) else versao_exata(d["versao"])
    q = lambda s: urllib.parse.quote(s, safe="")
    if eco == "npm" and n.startswith("@") and "/" in n:
        esc, nome = n.split("/", 1)
        caminho = "%s/%s" % (q(esc), q(nome))
    elif eco == "maven" and ":" in n:
        caminho = "/".join(q(x) for x in n.split(":", 1))
    elif eco in ("go", "composer"):
        caminho = "/".join(q(x) for x in n.split("/"))
    elif eco == "pypi":
        caminho = q(norm_nome("pypi", n))
    else:
        caminho = q(n)
    return "pkg:%s/%s%s" % (tipo, caminho, ("@" + q(v)) if v else "")


def _cdx_licenca(lics):
    itens = []
    for l in lics or []:
        if not isinstance(l, dict):
            continue
        if l.get("expression"):
            itens.append(l["expression"])
        elif isinstance(l.get("license"), dict):
            x = l["license"]
            if x.get("id") or x.get("name"):
                itens.append(x.get("id") or x.get("name"))
    if not itens:
        return None
    return itens[0] if len(itens) == 1 else " OR ".join("(%s)" % x for x in itens)


def importar_sbom(c, caminho):
    j = ler_json(caminho)
    rel = "sbom:" + os.path.basename(caminho)
    if not isinstance(j, dict):
        c.manifesto(rel, "sbom", False, "arquivo ilegível")
        return 0
    n = 0
    if j.get("bomFormat") == "CycloneDX":
        pilha = list(j.get("components") or [])
        while pilha:
            comp = pilha.pop()
            if not isinstance(comp, dict):
                continue
            pilha.extend(comp.get("components") or [])
            eco, nome, ver = de_purl(comp.get("purl"))
            if not eco:
                continue
            escopo = {"excluded": "desenvolvimento", "optional": "opcional"}.get(comp.get("scope"), "indeterminado")
            c.add(eco, nome, comp.get("version") or ver, escopo, False, rel,
                  licenca=_cdx_licenca(comp.get("licenses")), fonte="sbom")
            n += 1
    elif j.get("spdxVersion"):
        for p in j.get("packages") or []:
            purl = None
            for ref in p.get("externalRefs") or []:
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
            eco, nome, ver = de_purl(purl)
            if not eco:
                continue
            lic = None
            for campo in ("licenseConcluded", "licenseDeclared"):
                v = p.get(campo)
                if v and v not in ("NOASSERTION", "NONE"):
                    lic = v
                    break
            d = c.add(eco, nome, p.get("versionInfo") or ver, "indeterminado", False, rel,
                      licenca=lic, fonte="sbom")
            if d is not None and lic is None and p.get("licenseDeclared") == "NONE":
                definir_licenca(d, "", "sbom")
            n += 1
    else:
        c.manifesto(rel, "sbom", False, "formato não reconhecido (esperado CycloneDX ou SPDX JSON)")
        return 0
    c.manifesto(rel, "sbom", True)
    return n


def gerar_cyclonedx(dados):
    comps = []
    for d in dados["dependencias"]:
        comp = {"type": "library", "bom-ref": "%s:%s" % (d["ecossistema"], d["nome"])}
        if d["ecossistema"] == "maven" and ":" in d["nome"]:
            comp["group"], comp["name"] = d["nome"].split(":", 1)
        else:
            comp["name"] = d["nome"]
        v = versao_exata(d["versao"]) if d["ecossistema"] != "go" else d["versao"]
        if v:
            comp["version"] = v
        p = para_purl(d)
        if p:
            comp["purl"] = p
        comp["scope"] = {"desenvolvimento": "excluded", "opcional": "optional"}.get(d["escopo"], "required")
        if d.get("licenca"):
            comp["licenses"] = [{"expression": d["licenca"]}] if parece_spdx(d["licenca"]) \
                else [{"license": {"name": d["licenca"][:200]}}]
        comp["properties"] = [
            {"name": "prove:classe_licenca", "value": d["classe"]},
            {"name": "prove:escopo", "value": d["escopo"]},
            {"name": "prove:direta", "value": "true" if d["direta"] else "false"},
            {"name": "prove:origem", "value": d["origem"]},
        ]
        comps.append(comp)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(), "version": 1,
        "metadata": {
            "timestamp": dados["data"],
            "tools": {"components": [{"type": "application", "name": "PROVE", "version": VERSAO}]},
            "component": {"type": "application", "name": dados["projeto"], "bom-ref": "projeto"},
        },
        "components": comps,
    }


# ---------------------------------------------------------------------------
# Consulta online opcional (só nomes e versões de pacotes públicos)
# ---------------------------------------------------------------------------

DEPSDEV = {"go": "GO", "maven": "MAVEN", "nuget": "NUGET"}


def _get_json(url, timeout=12):
    req = urllib.request.Request(url, headers={"User-Agent": "PROVE/%s (varredura de licencas)" % VERSAO,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def _consulta_online(d):
    eco, n = d["ecossistema"], d["nome"]
    v = d["versao"] if (eco == "go" and re.match(r"^v\d", d["versao"] or "")) else versao_exata(d["versao"])
    q = urllib.parse.quote
    if eco == "npm":
        st, j = _get_json("https://registry.npmjs.org/%s/%s" % (q(n, safe="@"), v or "latest"))
        return st, normalizar_licenca_valor((j or {}).get("license") or (j or {}).get("licenses"))
    if eco == "pypi":
        st, j = _get_json("https://pypi.org/pypi/%s/%sjson" % (q(n), (v + "/") if v else ""))
        info = (j or {}).get("info") or {}
        cls = [x.split("::")[-1].strip() for x in info.get("classifiers") or []
               if x.startswith("License ::") and not x.endswith("OSI Approved")]
        lic = info.get("license_expression") or (" OR ".join("(%s)" % x for x in cls) if len(cls) > 1 else
                                                  (cls[0] if cls else None))
        if not lic and info.get("license") and info["license"].upper() != "UNKNOWN":
            lic = info["license"]
        return st, lic
    if eco == "cargo":
        st, j = _get_json("https://crates.io/api/v1/crates/%s%s" % (q(n), ("/" + v) if v else ""))
        if j and v:
            return st, (j.get("version") or {}).get("license")
        vers = (j or {}).get("versions") or [{}]
        return st, vers[0].get("license")
    if eco == "composer":
        st, j = _get_json("https://repo.packagist.org/p2/%s.json" % n)
        pac = ((j or {}).get("packages") or {}).get(n) or [{}]
        return st, normalizar_licenca_valor(pac[0].get("license"))
    if eco == "rubygems":
        st, j = _get_json("https://rubygems.org/api/v1/gems/%s.json" % q(n))
        return st, normalizar_licenca_valor((j or {}).get("licenses"))
    if eco in DEPSDEV:
        sistema = DEPSDEV[eco]
        if not v:
            st, j = _get_json("https://api.deps.dev/v3/systems/%s/packages/%s" % (sistema, q(n, safe="")))
            for ver in (j or {}).get("versions") or []:
                if ver.get("isDefault"):
                    v = (ver.get("versionKey") or {}).get("version")
            if not v:
                return st, None
        st, j = _get_json("https://api.deps.dev/v3/systems/%s/packages/%s/versions/%s"
                          % (sistema, q(n, safe=""), q(v, safe="")))
        lics = [x for x in (j or {}).get("licenses") or [] if x and x != "non-standard"]
        return st, (" AND ".join("(%s)" % x if " " in x else x for x in lics) if lics else None)
    return None, None


def consultar_online(c, excluir):
    alvos = [d for d in c.deps.values()
             if not d["licenca"] and d["origem"] == "terceiro" and d["ecossistema"] != "pub"
             and not any(d["nome"].startswith(p) for p in excluir)]
    if not alvos:
        return 0
    print("Consulta online: %d pacote(s). Enviados apenas nome e versão de cada pacote a registros "
          "públicos (npm, PyPI, crates.io, Packagist, RubyGems, deps.dev). Nenhum dado do projeto é enviado."
          % len(alvos))

    def tarefa(d):
        try:
            return d, _consulta_online(d)
        except Exception:
            return d, (None, None)

    with ThreadPoolExecutor(max_workers=8) as ex:
        for d, (st, lic) in ex.map(tarefa, alvos):
            if st == 404:
                d["origem"] = "nao_publico"
            elif st == 200:
                definir_licenca(d, lic if lic else "", "online")
    return len(alvos)


# ---------------------------------------------------------------------------
# Git: autoria
# ---------------------------------------------------------------------------

def caminho_sem_autoria(p):
    partes = p.replace("\\", "/").split("/")
    if any(x in IGNORAR_DIRS for x in partes[:-1]):
        return True
    nome = partes[-1]
    return nome in ARQUIVOS_SEM_AUTORIA or nome.endswith((".min.js", ".min.css", ".map", ".snap"))


def tipo_dominio(dom):
    if not dom:
        return "local"
    if dom in PROVEDORES_PESSOAIS:
        return "pessoal"
    if any(dom == x or dom.endswith("." + x) for x in DOMINIOS_OCULTOS):
        return "oculta"
    if dom.endswith((".local", ".localdomain", ".lan", ".internal", ".home")) or "." not in dom:
        return "local"
    return "corporativa"


def ia_de_identidade(nome, email):
    """Ferramenta de IA associada a uma identidade (autor, committer ou coautor), ou None."""
    e = (email or "").strip().lower()
    n = (nome or "").strip()
    for padrao, ferramenta in IA_EMAIL:
        if re.search(padrao, e):
            return ferramenta
    if "(aider)" in n.lower():
        return "Aider"
    chave = norm_pessoa(re.sub(r"\[bot\]", "", n))
    if chave in IA_NOMES and (not e or "noreply" in e or "[bot]" in e or "[bot]" in n.lower()):
        return IA_NOMES[chave]
    return None


def eh_bot(nome, email):
    local = (email or "").split("@")[0]
    return bool(RE_BOT.search(nome or "") or RE_BOT.search(local))


def analisar_git(raiz):
    info = {"disponivel": False}
    if sh(["git", "rev-parse", "--is-inside-work-tree"], raiz).strip() != "true":
        return info
    info["disponivel"] = True
    escopo = ["--", "."] if sh(["git", "rev-parse", "--show-prefix"], raiz).strip() else []
    info["subpasta"] = bool(escopo)
    info["head"] = sh(["git", "rev-parse", "HEAD"], raiz).strip() or None
    info["branch"] = sh(["git", "rev-parse", "--abbrev-ref", "HEAD"], raiz).strip() or None
    remoto = sh(["git", "remote", "get-url", "origin"], raiz).strip()
    info["remoto"] = re.sub(r"//[^@/]+@", "//", remoto) if remoto else None
    info["clone_raso"] = sh(["git", "rev-parse", "--is-shallow-repository"], raiz).strip() == "true"
    status = sh(["git", "status", "--porcelain", "--", "."], raiz)
    info["alteracoes_nao_commitadas"] = len([l for l in status.splitlines() if l.strip()])
    info["merges"] = int((sh(["git", "rev-list", "--count", "--merges", "HEAD"] + escopo, raiz).strip() or "0"))

    log = sh(["git", "-c", "core.quotepath=off", "log", "--use-mailmap", "--no-merges", "--numstat",
              "--no-renames", "--format=%x1e%H%x1f%aN%x1f%aE%x1f%aI"] + escopo, raiz)
    commits = []
    for bloco in log.split("\x1e"):
        if not bloco.strip():
            continue
        cab, _, resto = bloco.partition("\n")
        partes = cab.split("\x1f")
        if len(partes) != 4:
            continue
        h, nome, email, data = partes
        adic = rem = 0
        for l in resto.splitlines():
            m = l.split("\t")
            if len(m) >= 3 and m[0].isdigit() and m[1].isdigit() and not caminho_sem_autoria(m[2]):
                adic += int(m[0])
                rem += int(m[1])
        commits.append({"h": h, "nome": nome.strip(), "email": email.strip().lower(),
                        "data": data[:10], "adic": adic, "rem": rem})

    info["total_commits"] = len(commits)
    if not commits:
        info.update({"identidades": [], "agentes_ia": [], "automacoes": [], "importacoes": []})
        return info

    humanos, agentes, bots = [], defaultdict(list), defaultdict(int)
    for cm in commits:
        f = ia_de_identidade(cm["nome"], cm["email"])
        if f:
            agentes[f].append(cm)
        elif eh_bot(cm["nome"], cm["email"]):
            bots[cm["nome"] or cm["email"]] += 1
        else:
            humanos.append(cm)

    # Agrupa identidades: mesmo nome ou mesmo e-mail = mesma pessoa (salvo nomes genéricos)
    pai = {}

    def achar(x):
        pai.setdefault(x, x)
        while pai[x] != x:
            pai[x] = pai[pai[x]]
            x = pai[x]
        return x

    for cm in humanos:
        ke = "e:" + cm["email"]
        achar(ke)
        nn = norm_pessoa(cm["nome"])
        if nn and nn not in NOMES_GENERICOS:
            pai[achar("n:" + nn)] = achar(ke)

    grupos = defaultdict(list)
    for cm in humanos:
        grupos[achar("e:" + cm["email"])].append(cm)

    total_c = len(humanos) + sum(len(v) for v in agentes.values())
    total_l = sum(c["adic"] for c in humanos) + sum(c["adic"] for v in agentes.values() for c in v)

    dom_peso = Counter()
    for cm in humanos:
        dom = cm["email"].split("@")[-1] if "@" in cm["email"] else ""
        if tipo_dominio(dom) == "corporativa":
            dom_peso[dom] += 1
    principal = dom_peso.most_common(1)[0][0] if dom_peso else None
    info["dominio_principal"] = principal

    pct = lambda x, t: round(100.0 * x / t, 1) if t else 0.0
    idents = []
    for cms in grupos.values():
        nomes = Counter(c["nome"] for c in cms)
        emails = sorted({c["email"] for c in cms})
        doms = sorted({e.split("@")[-1] for e in emails if "@" in e})
        tipos = {tipo_dominio(d) for d in doms} or {"local"}
        if any("@" not in e for e in emails):
            tipos.add("local")
        corp = [d for d in doms if tipo_dominio(d) == "corporativa"]
        fora = bool(principal and corp and principal not in corp)
        if "pessoal" in tipos:
            classe = "pessoal"
        elif "oculta" in tipos:
            classe = "oculta"
        elif fora:
            classe = "externa"
        elif "corporativa" not in tipos:
            classe = "local"
        else:
            classe = "corporativa"
        adic = sum(c["adic"] for c in cms)
        datas = sorted(c["data"] for c in cms)
        idents.append({
            "autor": nomes.most_common(1)[0][0] or emails[0],
            "nomes": sorted(nomes) if len(nomes) > 1 else [],
            "emails_mascarados": [mascarar_email(e) for e in emails],
            "dominios": doms, "classificacao": classe,
            "email_pessoal": "pessoal" in tipos, "identidade_oculta": "oculta" in tipos,
            "fora_do_dominio": fora,
            "commits": len(cms), "pct_commits": pct(len(cms), total_c),
            "linhas_adicionadas": adic, "pct_linhas": pct(adic, total_l),
            "primeiro_commit": datas[0], "ultimo_commit": datas[-1],
            "meses_ativos": len({d[:7] for d in datas}),
            "_emails": emails, "_nomes": {norm_pessoa(n) for n in nomes},
            "_commits": [(c["data"], c["adic"], c["h"]) for c in cms],
        })
    idents.sort(key=lambda x: (-x["linhas_adicionadas"], -x["commits"], x["autor"]))
    por_hash = {}
    for i, x in enumerate(idents, 1):
        x["id"] = "C%02d" % i
        for _, _, h in x["_commits"]:
            por_hash[h] = x["id"]

    info["identidades"] = idents
    info["dominio_principal"] = principal
    info["total_commits_humanos"] = len(humanos)
    info["total_linhas_adicionadas"] = total_l
    info["primeiro_commit"] = min(c["data"] for c in commits)
    info["ultimo_commit"] = max(c["data"] for c in commits)
    info["agentes_ia"] = sorted([{
        "ferramenta": f, "commits": len(v), "pct_commits": pct(len(v), total_c),
        "linhas_adicionadas": sum(c["adic"] for c in v), "pct_linhas": pct(sum(c["adic"] for c in v), total_l),
        "primeiro_commit": min(c["data"] for c in v), "ultimo_commit": max(c["data"] for c in v),
    } for f, v in agentes.items()], key=lambda x: -x["commits"])
    info["automacoes"] = [{"nome": n, "commits": q} for n, q in sorted(bots.items(), key=lambda kv: -kv[1])]

    # Grandes blocos de código que entram de uma vez: origem anterior ao histórico?
    ordenados = sorted(commits, key=lambda c: c["data"])
    imports = []
    for i, cm in enumerate(ordenados):
        if total_l and ((cm["adic"] >= 1000 and cm["adic"] >= 0.25 * total_l) or cm["adic"] >= 20000
                        or (i == 0 and cm["adic"] >= 500 and cm["adic"] >= 0.10 * total_l)):
            f = ia_de_identidade(cm["nome"], cm["email"])
            imports.append({"commit": cm["h"][:10], "data": cm["data"], "linhas": cm["adic"],
                            "pct_linhas": pct(cm["adic"], total_l), "autor_id": por_hash.get(cm["h"]),
                            "agente_ia": f, "primeiro_commit": i == 0})
    info["importacoes"] = sorted(imports, key=lambda x: -x["linhas"])[:10]
    info["_por_hash"] = por_hash

    arquivos = sh(["git", "-c", "core.quotepath=off", "ls-files", "-z", "--", "."], raiz)
    ling = Counter()
    for p in arquivos.split("\x00"):
        if p and not caminho_sem_autoria(p):
            lang = LINGUAGENS.get(os.path.splitext(p)[1].lower())
            if lang:
                ling[lang] += 1
    info["arquivos_versionados"] = len([p for p in arquivos.split("\x00") if p])
    info["linguagens"] = [{"linguagem": k, "arquivos": v} for k, v in ling.most_common(12)]
    return info


# ---------------------------------------------------------------------------
# Uso de IA declarado (não é detecção)
# ---------------------------------------------------------------------------

def arquivos_ia(raiz):
    achados = []
    for base, dirs, arqs in os.walk(raiz):
        rel_base = os.path.relpath(base, raiz).replace(os.sep, "/")
        rel_base = "" if rel_base == "." else rel_base + "/"
        if rel_base.count("/") >= 5:
            dirs[:] = []
        novos = []
        for dn in sorted(dirs):
            if dn in IGNORAR_IA:
                continue
            relp = rel_base + dn
            f = IA_ARQUIVOS.get(dn) if "/" not in dn else None
            if not f:
                f = next((v for k, v in IA_ARQUIVOS.items() if "/" in k and (relp == k or relp.endswith("/" + k))), None)
            if f:
                achados.append({"caminho": relp + "/", "ferramenta": f})
            else:
                novos.append(dn)
        dirs[:] = novos
        for an in sorted(arqs):
            relp = rel_base + an
            f = IA_ARQUIVOS.get(an)
            if not f:
                f = next((v for k, v in IA_ARQUIVOS.items() if "/" in k and (relp == k or relp.endswith("/" + k))), None)
            if f:
                achados.append({"caminho": relp, "ferramenta": f})
    return achados


def analisar_ia(raiz, git):
    ferr = defaultdict(lambda: {"commits": 0, "primeiro": None, "ultimo": None,
                                "evidencias": Counter(), "autores": set()})
    total = com_ia = 0
    por_email = {}
    for x in git.get("identidades") or []:
        for e in x["_emails"]:
            por_email[e] = x["id"]
    if git.get("disponivel") and git.get("total_commits"):
        log = sh(["git", "log", "--use-mailmap", "--format=%x1e%H%x1f%aN%x1f%aE%x1f%cN%x1f%cE%x1f%aI%x1f%B"]
                 + (["--", "."] if git.get("subpasta") else []), raiz)
        for bloco in log.split("\x1e"):
            partes = bloco.split("\x1f", 6)
            if len(partes) < 7:
                continue
            total += 1
            _, an, ae, cn, ce, data, corpo = partes
            achadas = {}
            f = ia_de_identidade(an, ae)
            if f:
                achadas[f] = "autoria"
            f = ia_de_identidade(cn, ce)
            if f and f not in achadas:
                achadas[f] = "committer"
            for nome, email in RE_COAUTOR.findall(corpo):
                f = ia_de_identidade(nome, email)
                if f and f not in achadas:
                    achadas[f] = "coautoria"
            for m in RE_MARCA_IA.finditer(corpo):
                f = IA_NOMES.get(norm_pessoa(m.group(1)))
                if f and f not in achadas:
                    achadas[f] = "mensagem"
            if achadas:
                com_ia += 1
            for f, tipo in achadas.items():
                r = ferr[f]
                r["commits"] += 1
                r["evidencias"][tipo] += 1
                d = data[:10]
                r["primeiro"] = min(r["primeiro"] or d, d)
                r["ultimo"] = max(r["ultimo"] or d, d)
                aid = por_email.get(ae.strip().lower())
                if aid:
                    r["autores"].add(aid)

    arqs = arquivos_ia(raiz)
    for a in arqs:
        datas = sh(["git", "log", "--diff-filter=A", "--format=%aI", "--", a["caminho"].rstrip("/")], raiz) \
            if git.get("disponivel") else ""
        linhas = [l for l in datas.splitlines() if l.strip()]
        a["versionado_desde"] = linhas[-1][:10] if linhas else None

    nomes = set(ferr) | {a["ferramenta"] for a in arqs}
    ferramentas = []
    for f in sorted(nomes):
        r = ferr.get(f) or {"commits": 0, "primeiro": None, "ultimo": None, "evidencias": Counter(), "autores": set()}
        datas_arq = [a["versionado_desde"] for a in arqs if a["ferramenta"] == f and a["versionado_desde"]]
        ferramentas.append({
            "ferramenta": f, "commits": r["commits"],
            "primeiro_registro": min([x for x in [r["primeiro"]] + datas_arq if x] or [None]) if (r["primeiro"] or datas_arq) else None,
            "ultimo_registro": r["ultimo"],
            "evidencias": dict(r["evidencias"]),
            "arquivos": [a["caminho"] for a in arqs if a["ferramenta"] == f],
            "autores_ids": sorted(r["autores"]),
        })
    ferramentas.sort(key=lambda x: (-x["commits"], x["ferramenta"]))
    return {"ferramentas": ferramentas, "arquivos": arqs, "commits_analisados": total,
            "commits_com_registro_de_ia": com_ia,
            "pct_commits_com_ia": round(100.0 * com_ia / total, 1) if total else 0.0}


def chave_ferramenta(s):
    """Normaliza o nome informado em --ferramentas-autorizadas para o nome canônico."""
    n = norm_pessoa(s)
    if n in IA_NOMES:
        return IA_NOMES[n]
    for canon in set(IA_NOMES.values()) | set(IA_ARQUIVOS.values()):
        if n and n in norm_pessoa(canon):
            return canon
    return s.strip()


# ---------------------------------------------------------------------------
# Contratos de cessão
# ---------------------------------------------------------------------------

VINCULOS = {
    "clt": "clt", "empregado": "clt", "celetista": "clt", "pj": "pj", "pessoa juridica": "pj",
    "prestador": "pj", "freelancer": "freelancer", "freela": "freelancer", "autonomo": "freelancer",
    "agencia": "agencia", "fornecedor": "agencia", "software house": "agencia", "socio": "socio",
    "fundador": "socio", "estagio": "estagio", "estagiario": "estagio", "estatutario": "estatutario",
    "servidor": "estatutario", "cooperado": "cooperado", "voluntario": "voluntario", "outro": "outro",
}
ROTULO_VINCULO = {"clt": "CLT", "pj": "PJ", "freelancer": "Freelancer", "agencia": "Agência", "socio": "Sócio",
                  "estagio": "Estágio", "estatutario": "Estatutário", "cooperado": "Cooperado",
                  "voluntario": "Voluntário", "outro": "Outro", "nao_informado": "Não informado"}
ROTULO_CESSAO = {"sim": "Sim", "nao": "Não", "parcial": "Parcial", "nao_informado": "Não informado"}
ROTULO_SITUACAO = {
    "sem_registro": "Sem contrato", "fora_da_vigencia": "Fora da vigência", "coberto": "Coberto",
    "coberto_agencia": "Coberto (verificar cadeia da agência)", "cessao_nao_expressa": "Sem cessão expressa",
    "empregado_sem_cessao_expressa": "Empregado sem cessão expressa", "socio_sem_cessao": "Sócio sem cessão",
    "estagio_sem_cessao": "Estagiário sem cessão", "agencia_sem_cessao": "Agência sem cessão",
    "vinculo_nao_informado": "Vínculo não informado",
}
CAMPOS_CONTRATO = ["identificador", "nome", "vinculo", "inicio", "fim", "cessao", "documento", "observacao"]


def _data_contrato(s, fim=False):
    s = (s or "").strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            pass
    for fmt in ("%m/%Y", "%Y-%m"):
        try:
            dt = datetime.strptime(s, fmt)
            if fim:
                dt = (dt.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            pass
    raise ValueError(s)


def ler_contratos(caminho):
    with open(caminho, "r", encoding="utf-8-sig", errors="replace") as f:
        texto = f.read()
    primeira = texto.splitlines()[0] if texto.strip() else ""
    delim = ";" if primeira.count(";") >= primeira.count(",") else ","
    leitor = csv.DictReader(io.StringIO(texto), delimiter=delim)
    linhas, erros = [], []
    for i, row in enumerate(leitor, 2):
        r = {norm_pessoa(k or "").replace(" ", "_"): (v or "").strip() for k, v in row.items() if k}
        ident = r.get("identificador", "")
        nome = r.get("nome", "")
        if not ident and not nome:
            continue
        try:
            inicio = _data_contrato(r.get("inicio"))
            fim = _data_contrato(r.get("fim"), fim=True)
        except ValueError as e:
            erros.append("linha %d: data inválida '%s'" % (i, e))
            continue
        ces = norm_pessoa(r.get("cessao", ""))
        if ces in ("sim", "s", "yes", "x", "true", "1"):
            ces = "sim"
        elif ces in ("nao", "n", "no", "false", "0"):
            ces = "nao"
        elif ces.startswith("parc"):
            ces = "parcial"
        else:
            ces = "nao_informado"
        vin = VINCULOS.get(norm_pessoa(r.get("vinculo", "")), "nao_informado" if not r.get("vinculo") else "outro")
        partes = [p for p in re.split(r"[|;,\s]+", ident) if p]
        linhas.append({
            "linha": i, "emails": {p.lower() for p in partes if "@" in p},
            "nomes": {norm_pessoa(x) for x in [nome] + ([ident] if "@" not in ident else []) if norm_pessoa(x)},
            "vinculo": vin, "inicio": inicio, "fim": fim, "cessao": ces,
            "documento": r.get("documento", ""), "observacao": r.get("observacao", ""),
        })
    return linhas, erros


def cruzar_contratos(git, contratos):
    total_l = git.get("total_linhas_adicionadas") or 0
    total_c = git.get("total_commits_humanos") or 0
    usadas = set()
    matriz = []
    for x in git.get("identidades") or []:
        regs = [r for r in contratos if (r["emails"] & set(x["_emails"])) or (r["nomes"] & x["_nomes"])]
        for r in regs:
            usadas.add(r["linha"])
        desc = []
        for data, adic, _ in x["_commits"]:
            if not any((r["inicio"] or "0000-00-00") <= data <= (r["fim"] or "9999-12-31") for r in regs):
                desc.append((data, adic))
        linhas_desc = sum(a for _, a in desc)
        item = {"id": x["id"], "commits": x["commits"], "commits_fora_da_vigencia": len(desc),
                "linhas_fora_da_vigencia": linhas_desc,
                "periodo_descoberto": [min(d for d, _ in desc), max(d for d, _ in desc)] if desc else None,
                "vinculos": sorted({r["vinculo"] for r in regs}),
                "cessao": sorted({r["cessao"] for r in regs}),
                "documentos": [r["documento"] for r in regs if r["documento"]],
                "sem_data_inicio": any(not r["inicio"] for r in regs)}
        relevancia = max(x["pct_linhas"], x["pct_commits"])
        if not regs:
            item["situacao"], item["cor"] = "sem_registro", ("vermelho" if relevancia >= 5 else "amarelo")
        elif desc:
            frac = max(100.0 * linhas_desc / total_l if total_l else 0, 100.0 * len(desc) / total_c if total_c else 0)
            item["situacao"], item["cor"] = "fora_da_vigencia", ("vermelho" if frac >= 5 else "amarelo")
        else:
            vin = set(item["vinculos"])
            sim = "sim" in item["cessao"]
            if sim:
                item["situacao"], item["cor"] = ("coberto_agencia", "info") if "agencia" in vin else ("coberto", "verde")
            elif vin & {"clt", "estatutario"} and not (vin - {"clt", "estatutario"}):
                item["situacao"], item["cor"] = "empregado_sem_cessao_expressa", "info"
            elif "socio" in vin:
                item["situacao"], item["cor"] = "socio_sem_cessao", "amarelo"
            elif "estagio" in vin:
                item["situacao"], item["cor"] = "estagio_sem_cessao", "amarelo"
            elif "agencia" in vin:
                item["situacao"], item["cor"] = "agencia_sem_cessao", "amarelo"
            elif vin == {"nao_informado"}:
                item["situacao"], item["cor"] = "vinculo_nao_informado", "amarelo"
            else:
                item["situacao"], item["cor"] = "cessao_nao_expressa", "amarelo"
        matriz.append(item)
    sobras = [r["linha"] for r in contratos if r["linha"] not in usadas]
    return {"matriz": matriz, "linhas_sem_contribuidor": sobras}


def gerar_modelo_contratos(git, destino):
    with open(destino, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(CAMPOS_CONTRATO)
        for x in git.get("identidades") or []:
            w.writerow(["|".join(x["_emails"]), x["autor"], "", "", "", "", "", "%s · %d commits · %s a %s" % (
                x["id"], x["commits"], x["primeiro_commit"], x["ultimo_commit"])])


# ---------------------------------------------------------------------------
# Avaliação: achados com código estável (ver docs/METODOLOGIA.md)
# ---------------------------------------------------------------------------

def cor_licenca(classe, escopo, dist):
    dev = escopo == "desenvolvimento"
    incerto = escopo in ("indeterminado", "opcional")
    if classe == "copyleft_rede":
        if dev:
            return "info"
        if dist == "interno" or incerto:
            return "amarelo"
        return "vermelho"
    if classe == "copyleft_forte":
        if dev or dist == "interno":
            return "info"
        if dist == "saas" or incerto:
            return "amarelo"
        return "vermelho"
    if classe == "copyleft_fraco":
        if dev or dist in ("saas", "interno"):
            return "info"
        return "amarelo"
    if classe == "restritiva":
        return "amarelo" if (dev or incerto) else "vermelho"
    if classe in ("nao_declarada", "outra"):
        return "info" if dev else "amarelo"
    return None


TEXTO_LICENCA = {
    "copyleft_rede": ("LIC-REDE", "Dependência com copyleft de rede (AGPL/SSPL)",
                      "Licença de efeito recíproco que alcança o uso pela rede. Em SaaS ou em produto distribuído, "
                      "pode obrigar a disponibilizar o código-fonte da aplicação aos usuários."),
    "copyleft_forte": ("LIC-FORTE", "Dependência com copyleft forte (GPL)",
                       "Se o produto for distribuído (instalado, aplicativo, entrega de código-fonte, comum em contrato "
                       "público), pode obrigar a licenciar o código derivado sob a mesma licença."),
    "restritiva": ("LIC-RESTRITA", "Dependência com licença restritiva ou sem concessão",
                   "UNLICENSED, BUSL, Elastic, licenças não comerciais e similares: o uso depende de contrato ou de "
                   "termos específicos. Sem esse documento não há direito de uso demonstrável."),
    "copyleft_fraco": ("LIC-FRACO", "Dependência com copyleft fraco (LGPL/MPL/EPL)",
                       "Em geral compatível com produto proprietário, mas impõe avisos, disponibilização das modificações "
                       "do próprio componente e, na LGPL, a possibilidade de substituir a biblioteca. Ponto sensível em "
                       "aplicativos móveis com vinculação estática."),
    "nao_declarada": ("LIC-NAODECL", "Dependência sem licença declarada",
                      "O mantenedor não declarou licença na fonte consultada. Sem licença, a regra é 'todos os direitos "
                      "reservados': não há permissão de uso demonstrável."),
    "outra": ("LIC-OUTRA", "Licença não reconhecida automaticamente",
              "A licença declarada não corresponde a um padrão conhecido e precisa ser lida."),
}


def rotulo_dep(d):
    v = d["versao"] or "?"
    return "%s@%s (%s · %s)" % (d["nome"], v, d.get("licenca") or "sem licença", d["escopo"])


def avaliar(dados, ctx):
    A = []

    def add(cor, cod, titulo, desc, itens=None):
        x = {"cor": cor, "codigo": cod, "titulo": titulo, "descricao": desc}
        if itens:
            x["itens"] = itens
        A.append(x)

    dist = ctx["distribuicao"]
    deps = dados["dependencias"]
    terceiros = [d for d in deps if d["origem"] == "terceiro"]
    for d in deps:
        d["cor"] = cor_licenca(d["classe"], d["escopo"], dist) if d["origem"] == "terceiro" else None

    # Licenças de terceiros
    for classe in ("copyleft_rede", "copyleft_forte", "restritiva", "copyleft_fraco", "nao_declarada", "outra"):
        cod, titulo, texto = TEXTO_LICENCA[classe]
        por_cor = defaultdict(list)
        for d in terceiros:
            if d["classe"] == classe and d["cor"]:
                por_cor[d["cor"]].append(d)
        for cor in ("vermelho", "amarelo", "info"):
            lst = por_cor.get(cor)
            if not lst:
                continue
            desc = "%d dependência(s). %s" % (len(lst), texto)
            if cor == "info":
                desc += (" Classificado como informativo porque são dependências apenas de desenvolvimento ou "
                         "porque, no modelo de distribuição informado, o efeito da licença em regra não é acionado. "
                         "Revisar se o modelo mudar.")
                t = titulo + " — sem efeito no modelo informado"
            else:
                t = titulo
                if classe == "copyleft_forte" and dist == "saas":
                    desc += (" No modelo SaaS informado, em regra não há distribuição; o risco se materializa se o "
                             "produto passar a ser instalado, virar aplicativo ou se o contrato exigir entrega de fontes.")
                if any(d["escopo"] in ("indeterminado", "opcional") for d in lst):
                    desc += (" Parte delas tem escopo não determinado (transitivas sem indicação de produção ou "
                             "desenvolvimento): confirmar se chegam ao produto.")
                if dist == "nao_informado" and classe.startswith("copyleft"):
                    desc += " Modelo de distribuição não informado: análise conservadora (use --distribuicao)."
            add(cor, cod, t, desc, [rotulo_dep(d) for d in sorted(lst, key=lambda d: d["nome"])])

    nao_verif = [d for d in terceiros if d["classe"] == "nao_verificada"]
    if nao_verif:
        por_eco = Counter(d["ecossistema"] for d in nao_verif)
        prod = [d for d in nao_verif if d["escopo"] != "desenvolvimento"]
        add("info", "LIC-NAOVERIF", "Licenças não verificadas nesta varredura",
            "%d dependência(s) não puderam ser verificadas (%s). Isso é limite da varredura, não achado contra o "
            "projeto. Para completar: instale as dependências do projeto, rode com --online ou importe um SBOM com "
            "--sbom.%s" % (len(nao_verif), ", ".join("%s: %d" % kv for kv in por_eco.most_common()),
                           " A análise de licenças está incompleta para a maior parte das dependências de produção."
                           if terceiros and len(prod) > 0.5 * max(1, len([d for d in terceiros if d["escopo"] != "desenvolvimento"])) else ""))
    internas = [d for d in deps if d["origem"] in ("interna", "registro_privado")]
    if internas:
        add("info", "LIC-INTERNA", "Componentes internos ou de registro privado",
            "%d componente(s) parecem ser do próprio projeto ou vir de registro privado. A titularidade deles se prova "
            "pela cadeia de cessão, não por licença." % len(internas), [d["nome"] for d in internas[:30]])
    nao_pub = [d for d in deps if d["origem"] == "nao_publico"]
    if nao_pub:
        add("amarelo", "LIC-PRIVADA", "Dependências não encontradas em registro público",
            "%d dependência(s) não existem nos registros públicos consultados. Podem ser pacotes privados, de "
            "fornecedor ou removidos: confirmar origem, titularidade e contrato de uso." % len(nao_pub),
            [d["nome"] for d in nao_pub[:30]])

    # Licença do próprio projeto
    lp = dados.get("licenca_declarada_do_projeto")
    texto_lic = dados.get("licenca_do_arquivo_do_projeto")
    for valor, origem in ((lp["valor"], lp["arquivo"]) if lp else (None, None), (texto_lic, "arquivo de licença")):
        if not valor:
            continue
        classe = classificar_licenca(valor)
        if classe in ("permissiva", "copyleft_fraco", "copyleft_forte", "copyleft_rede") and dist != "biblioteca":
            extra = (" O valor 'ISC' é o padrão do 'npm init' e costuma estar ali por descuido."
                     if str(valor).upper() == "ISC" and origem.endswith("package.json") else "")
            add("amarelo", "LIC-PROJETO", "O próprio projeto declara licença aberta",
                "O projeto declara '%s' em %s. Se o produto é proprietário, essa declaração pode ser lida como "
                "concessão pública de direitos sobre o código.%s Confirmar se é intencional." % (valor, origem, extra))
            break
    if not dados["arquivos_licenca"] and not lp:
        add("amarelo", "LIC-SEMARQ", "Projeto sem arquivo nem declaração de licença",
            "Não há LICENSE, COPYING ou NOTICE na raiz nem licença declarada nos manifestos. Para produto "
            "proprietário, recomenda-se aviso de titularidade e de regime de uso.")

    nao_anal = [m for m in dados["manifestos"] if not m["analisado"]]
    if nao_anal:
        add("info", "MAN-NAOANAL", "Manifestos encontrados e não analisados",
            "%d arquivo(s) de dependências em formato ainda não suportado ou ilegível. As dependências declaradas "
            "neles não entram neste inventário." % len(nao_anal),
            ["%s (%s)" % (m["arquivo"], m.get("obs", "")) for m in nao_anal[:30]])
    if not dados["manifestos"]:
        add("info", "MAN-NENHUM", "Nenhum manifesto de dependência encontrado",
            "Não foi possível inventariar dependências de terceiros.")

    # Autoria
    g = dados["git"]
    if not g.get("disponivel"):
        add("vermelho", "AUT-SEMGIT", "Sem histórico de versionamento",
            "Não foi encontrado repositório Git. Sem histórico, não há como demonstrar quem escreveu o quê e quando: "
            "a prova de autoria passa a depender inteiramente de documento.")
    elif not g.get("total_commits"):
        add("vermelho", "AUT-VAZIO", "Repositório sem commits", "O repositório não tem histórico para analisar.")
    else:
        ids = g["identidades"]
        if g.get("clone_raso"):
            add("amarelo", "AUT-RASO", "Histórico incompleto (clone raso)",
                "O repositório foi clonado sem o histórico completo. Os dados de autoria abaixo não são confiáveis: "
                "rode a varredura num clone completo.")
        rel = lambda x: max(x["pct_linhas"], x["pct_commits"])
        nome = lambda x: "%s (%s)" % (x["autor"], x["id"])
        pessoais = [x for x in ids if x["email_pessoal"]]
        if pessoais:
            vol = sum(rel(x) for x in pessoais)
            add("vermelho" if vol >= 20 else "amarelo", "AUT-PESSOAL", "Contribuidor com identidade pessoal",
                "%d contribuidor(es) com e-mail de provedor pessoal, somando cerca de %.1f%% da autoria. Cada um "
                "exige vínculo e cessão de direitos patrimoniais vigentes à época da contribuição." % (len(pessoais), vol),
                [nome(x) for x in pessoais[:15]])
        ocultos = [x for x in ids if x["identidade_oculta"] and not x["email_pessoal"]]
        if ocultos:
            add("amarelo", "AUT-OCULTA", "Contribuidor com e-mail oculto (noreply)",
                "%d contribuidor(es) usam e-mail mascarado da plataforma (ex.: users.noreply.github.com), o que impede "
                "identificar o vínculo pelo domínio. Identificar a pessoa e verificar o contrato." % len(ocultos),
                [nome(x) for x in ocultos[:15]])
        fora = [x for x in ids if x["classificacao"] == "externa"]
        if fora:
            add("amarelo", "AUT-EXTERNO", "Contribuidor de domínio externo",
                "%d contribuidor(es) com e-mail fora do domínio principal (%s). Indica terceiro, agência ou fornecedor: "
                "confirmar contrato com cláusula de cessão e a cadeia do próprio fornecedor." % (len(fora), g.get("dominio_principal")),
                [nome(x) for x in fora[:15]])
        locais = [x for x in ids if x["classificacao"] == "local"]
        if locais:
            add("amarelo", "AUT-LOCAL", "Identidade não rastreável",
                "%d identidade(s) com e-mail local ou sem domínio (ex.: usuario@maquina.local). Não é possível "
                "associar a uma pessoa ou empresa sem informação adicional." % len(locais), [nome(x) for x in locais[:15]])
        if len(ids) == 1:
            add("amarelo", "AUT-UNICO", "Autor único",
                "Todo o histórico humano vem de uma só identidade. Verificar se corresponde a pessoa com vínculo e "
                "cessão formalizados, ou a uma conta compartilhada.")
        elif ids and rel(ids[0]) >= 60:
            add("amarelo", "AUT-CONCENTRACAO", "Concentração de autoria",
                "%s responde por %.1f%% das linhas e %.1f%% dos commits. A titularidade do produto depende "
                "criticamente do contrato dessa pessoa." % (nome(ids[0]), ids[0]["pct_linhas"], ids[0]["pct_commits"]))
        if g.get("importacoes"):
            add("amarelo", "AUT-IMPORTACAO", "Código que entrou em bloco",
                "%d commit(s) adicionaram parcela relevante do código de uma só vez. Pode indicar código desenvolvido "
                "fora deste histórico (repositório anterior, fornecedor, template, código gerado). A origem desses "
                "blocos precisa ser documentada." % len(g["importacoes"]),
                ["%s · %s · %d linhas (%.1f%%)%s" % (i["commit"], i["data"], i["linhas"], i["pct_linhas"],
                                                     " · primeiro commit" if i["primeiro_commit"] else "")
                 for i in g["importacoes"]])
        if g.get("alteracoes_nao_commitadas"):
            add("info", "AUT-NAOCOMMIT", "Alterações não commitadas",
                "Há %d arquivo(s) alterados e não commitados. O histórico analisado vai até o commit %s."
                % (g["alteracoes_nao_commitadas"], (g.get("head") or "")[:10]))

    # Contratos
    ces = dados.get("cessao")
    if g.get("disponivel") and g.get("identidades"):
        if not ces:
            add("info", "CES-PENDENTE", "Cruzamento com contratos não realizado",
                "Gere a planilha com --gerar-modelo-contratos, preencha vínculo, vigência e cláusula de cessão de cada "
                "pessoa e rode novamente com --contratos. É esse cruzamento que mostra onde a cadeia de titularidade quebra.")
        else:
            nomes_id = {x["id"]: "%s (%s)" % (x["autor"], x["id"]) for x in g["identidades"]}
            grupos = defaultdict(list)
            for m in ces["matriz"]:
                grupos[m["situacao"]].append(m)
            regras = [
                ("sem_registro", "CES-SEMREG", "Contribuidor sem contrato registrado",
                 "Não há contrato informado para estas pessoas. Sem vínculo formal, a regra é a titularidade do autor."),
                ("fora_da_vigencia", "CES-FORAVIG", "Commits fora da vigência do contrato",
                 "Há contribuições antes do início ou depois do fim dos contratos informados. O que foi produzido fora "
                 "da vigência não é alcançado pelo art. 4º da Lei 9.609/98 e exige cessão específica."),
                ("cessao_nao_expressa", "CES-NAOEXPR", "Prestador sem cláusula de cessão expressa",
                 "Para prestador de serviço, a titularidade da contratante depende de o contrato prever a atividade de "
                 "desenvolvimento (art. 4º da Lei 9.609/98). Cessão expressa elimina a discussão."),
                ("socio_sem_cessao", "CES-SOCIO", "Sócio sem cessão formalizada",
                 "Verificar contrato social ou acordo de sócios quanto à integralização ou cessão da propriedade "
                 "intelectual à sociedade."),
                ("estagio_sem_cessao", "CES-ESTAGIO", "Estagiário sem cessão expressa",
                 "O estagiário não é empregado (Lei 11.788/08) e não se enquadra com segurança no art. 4º da "
                 "Lei 9.609/98. Recomenda-se cessão expressa no termo de compromisso."),
                ("agencia_sem_cessao", "CES-AGENCIA", "Agência ou fornecedor sem cessão expressa",
                 "Exigir cessão da agência e evidência de que ela detém os direitos de quem programou (cadeia do fornecedor)."),
                ("vinculo_nao_informado", "CES-VINCULO", "Vínculo não informado",
                 "Há registro, mas sem o tipo de vínculo. Preencher a coluna 'vinculo' da planilha."),
                ("coberto_agencia", "CES-CADEIA", "Agência com cessão: verificar a cadeia",
                 "A cessão da agência só é eficaz se ela detiver os direitos de quem programou. Pedir os contratos internos do fornecedor."),
                ("empregado_sem_cessao_expressa", "CES-EMPREGADO", "Empregado sem cessão expressa",
                 "Pelo art. 4º da Lei 9.609/98, o programa pertence ao empregador quando a atividade de desenvolvimento "
                 "está prevista no contrato ou decorre da natureza do cargo. Verificar a descrição do cargo; cessão expressa reforça."),
            ]
            for sit, cod, titulo, texto in regras:
                lst = grupos.get(sit)
                if not lst:
                    continue
                cor = "vermelho" if any(m["cor"] == "vermelho" for m in lst) else lst[0]["cor"]
                itens = []
                for m in lst:
                    s = nomes_id.get(m["id"], m["id"])
                    if m["periodo_descoberto"]:
                        s += " · %d commit(s) de %s a %s" % (m["commits_fora_da_vigencia"], m["periodo_descoberto"][0],
                                                            m["periodo_descoberto"][1])
                    itens.append(s)
                add(cor, cod, titulo, texto, itens)
            semdoc = [m for m in ces["matriz"] if m["vinculos"] and not m["documentos"]]
            if semdoc:
                add("info", "CES-SEMDOC", "Registro sem referência ao documento",
                    "%d pessoa(s) com contrato informado mas sem indicar o documento (nome do arquivo, número ou data). "
                    "O laudo precisa apontar o documento." % len(semdoc))
            if ces.get("erros"):
                add("amarelo", "CES-DATAS", "Linhas da planilha de contratos com erro", "Corrigir e rodar novamente.",
                    ces["erros"][:20])
            if ces.get("linhas_sem_contribuidor"):
                add("info", "CES-SOBRA", "Contratos sem contribuidor correspondente",
                    "Linhas da planilha que não casaram com nenhuma identidade do histórico (pode ser e-mail diferente "
                    "do usado nos commits).", ["linha %d" % n for n in ces["linhas_sem_contribuidor"][:30]])

    # Uso de IA declarado
    ia = dados["ia"]
    pol = ctx.get("ferramentas_autorizadas")
    desde = ctx.get("politica_ia_desde")
    if ia["ferramentas"]:
        add("info", "IA-USO", "Uso de IA declarado no repositório",
            "%d ferramenta(s) com registro de uso (coautoria em commits, autoria por agente ou arquivo de "
            "configuração). %.1f%% dos commits têm registro de IA. Isso não é detecção: é o que o próprio histórico "
            "declara. A proteção autoral de trechos produzidos com contribuição humana mínima é juridicamente "
            "incerta; documentar a revisão humana e a política de uso fortalece a titularidade."
            % (len(ia["ferramentas"]), ia["pct_commits_com_ia"]),
            ["%s · %d commit(s)%s" % (f["ferramenta"], f["commits"],
                                      (" · arquivos: " + ", ".join(f["arquivos"][:3])) if f["arquivos"] else "")
             for f in ia["ferramentas"]])
        agentes = g.get("agentes_ia") or []
        if agentes:
            add("info", "IA-AGENTE", "Commits feitos por agente de IA",
                "Há commits cuja identidade de autoria é um agente de IA. Esses commits ficam fora da matriz de "
                "cessão (não há pessoa), mas entram na política de ferramentas.",
                ["%s · %d commit(s) · %.1f%% das linhas" % (a["ferramenta"], a["commits"], a["pct_linhas"]) for a in agentes])
        if pol:
            fora_pol = [f for f in ia["ferramentas"] if f["ferramenta"] not in pol]
            if fora_pol:
                add("amarelo", "IA-NAOAUT", "Ferramenta de IA fora da política",
                    "Há registro de uso de ferramenta não incluída entre as autorizadas (%s). Verificar plano contratado, "
                    "termos de uso (titularidade do resultado, uso de dados, indenização) e se houve envio de código "
                    "confidencial." % ", ".join(sorted(pol)),
                    ["%s · %d commit(s)" % (f["ferramenta"], f["commits"]) for f in fora_pol])
        else:
            add("amarelo", "IA-SEMPOL", "Uso de IA sem política informada",
                "Há registro declarado de uso de IA, mas não foi informada política de ferramentas autorizadas. A "
                "política, e a data em que passou a valer, é a prova que sustenta a titularidade do que foi produzido "
                "com IA. Informe com --ferramentas-autorizadas e --politica-ia-desde.")
        if desde:
            antes = [f for f in ia["ferramentas"] if f["primeiro_registro"] and f["primeiro_registro"] < desde]
            if antes:
                add("amarelo", "IA-ANTERIOR", "Uso de IA anterior à política",
                    "Há registro de uso de IA antes de %s, data informada de início da política." % desde,
                    ["%s · desde %s" % (f["ferramenta"], f["primeiro_registro"]) for f in antes])
        pessoais = {x["id"] for x in g.get("identidades") or [] if x["classificacao"] in ("pessoal", "oculta")}
        cruz = [f for f in ia["ferramentas"] if set(f["autores_ids"]) & pessoais]
        if cruz:
            add("amarelo", "IA-PESSOAL", "Uso de IA associado a identidades pessoais",
                "Commits com registro de IA feitos por contribuidores com e-mail pessoal ou oculto. Indica possível uso "
                "de conta ou plano pessoal da ferramenta, cujos termos (titularidade do resultado, uso de dados para "
                "treino, indenização) costumam diferir do plano corporativo.",
                ["%s · %s" % (f["ferramenta"], ", ".join(sorted(set(f["autores_ids"]) & pessoais))) for f in cruz])
    elif g.get("disponivel"):
        add("info", "IA-NENHUM", "Nenhum registro declarado de uso de IA",
            "Não há coautoria de IA nos commits nem arquivos de configuração de ferramentas. Ausência de registro não "
            "prova ausência de uso: ferramentas de autocompletar normalmente não deixam rastro.")

    if not [x for x in A if x["cor"] in ("vermelho", "amarelo")]:
        add("verde", "OK", "Nenhum achado de risco automático",
            "A varredura não encontrou indicadores de risco. A verificação documental da cadeia de cessão continua necessária.")
    A.sort(key=lambda x: (ORDEM_COR[x["cor"]], x["codigo"]))
    return A


# ---------------------------------------------------------------------------
# Relatório
# ---------------------------------------------------------------------------

def montar_relatorio(dados):
    L = []
    a = L.append
    g = dados["git"]
    deps = dados["dependencias"]
    ach = dados["achados"]
    sev = Counter(x["cor"] for x in ach)
    ids = {x["id"]: x for x in g.get("identidades") or []}
    nome_id = lambda i: "%s (%s)" % (ids[i]["autor"], i) if i in ids else (i or "—")

    a("# PROVE — Varredura de Proveniência de Código\n")
    a("**%s** · %s\n" % (ESCRITORIO, RESPONSAVEL))
    a("- Projeto analisado: `%s`" % dados["projeto"])
    a("- Data da varredura: %s" % dados["data"][:10])
    a("- Versão da ferramenta: PROVE %s" % VERSAO)
    a("- Modelo de distribuição: %s" % DISTRIBUICOES[dados["parametros"]["distribuicao"]])
    if g.get("head"):
        a("- Commit analisado: `%s` (%s)" % (g["head"][:12], g.get("branch") or "—"))
    a("- Hash dos dados (SHA-256): `%s`\n" % dados["integridade"]["hash_dados"])
    a("---\n")
    a("## Resultado preliminar: %s\n" % ROT[dados["semaforo"]])
    a("%d achado(s) crítico(s) · %d ponto(s) de atenção · %d informativo(s)\n"
      % (sev["vermelho"], sev["amarelo"], sev["info"]))
    prod = len([d for d in deps if d["escopo"] != "desenvolvimento"])
    a("- Dependências: **%d** (%d de produção ou escopo incerto, %d de desenvolvimento)"
      % (len(deps), prod, len(deps) - prod))
    if g.get("disponivel") and g.get("total_commits"):
        a("- Contribuidores humanos: **%d** · commits: %d · período: %s a %s"
          % (len(g["identidades"]), g["total_commits"], g["primeiro_commit"], g["ultimo_commit"]))
    a("- Ferramentas de IA com registro: **%d**" % len(dados["ia"]["ferramentas"]))
    a("- Cruzamento com contratos: %s\n" % ("realizado" if dados.get("cessao") else "não realizado"))
    a("> Esta varredura lê apenas manifestos de dependência, metadados de licença de terceiros, o histórico de "
      "autoria do Git e nomes de arquivos de configuração. Nenhum arquivo de código-fonte da aplicação é lido, "
      "copiado ou transmitido.\n")

    a("## Achados\n")
    for x in ach:
        a("**%s · %s** `%s`\n" % (ROT[x["cor"]], x["titulo"], x["codigo"]))
        a("%s\n" % x["descricao"])
        itens = x.get("itens") or []
        for it in itens[:15]:
            a("- %s" % it)
        if len(itens) > 15:
            a("- … e mais %d (lista completa em prove_dados.json)" % (len(itens) - 15))
        if itens:
            a("")

    a("## Matriz de cessão\n")
    if dados.get("cessao"):
        a("| ID | Contribuidor | Vínculo | Cessão | Commits | Fora da vigência | Situação |")
        a("| --- | --- | --- | --- | ---: | ---: | --- |")
        for m in dados["cessao"]["matriz"]:
            a("| %s | %s | %s | %s | %d | %d | %s %s |" % (
                m["id"], md(ids[m["id"]]["autor"] if m["id"] in ids else "—"),
                ", ".join(ROTULO_VINCULO.get(v, v) for v in m["vinculos"]) or "—",
                ", ".join(ROTULO_CESSAO.get(v, v) for v in m["cessao"]) or "—", m["commits"],
                m["commits_fora_da_vigencia"], ROT[m["cor"]].split(" ")[0], ROTULO_SITUACAO.get(m["situacao"], m["situacao"])))
        a("")
    else:
        a("Não realizado. Rode `python3 prove_scan.py --gerar-modelo-contratos contratos.csv`, preencha a planilha "
          "(vínculo, início, fim, cessão, documento) e rode de novo com `--contratos contratos.csv`. A planilha fica "
          "com você; só o resultado do cruzamento entra no relatório.\n")

    a("## Inventário de dependências\n")
    if deps:
        eco = Counter(d["ecossistema"] for d in deps)
        a("Ecossistemas: %s · diretas: %d · transitivas: %d\n" % (
            ", ".join("%s (%d)" % kv for kv in eco.most_common()),
            len([d for d in deps if d["direta"]]), len([d for d in deps if not d["direta"]])))
        a("| Classificação da licença | Produção / incerto | Desenvolvimento |")
        a("| --- | ---: | ---: |")
        for k in ("copyleft_rede", "copyleft_forte", "restritiva", "copyleft_fraco", "nao_declarada", "outra",
                  "permissiva", "nao_verificada"):
            p = len([d for d in deps if d["classe"] == k and d["escopo"] != "desenvolvimento" and d["origem"] == "terceiro"])
            dv = len([d for d in deps if d["classe"] == k and d["escopo"] == "desenvolvimento" and d["origem"] == "terceiro"])
            if p or dv:
                a("| %s | %d | %d |" % (CLASSES[k], p, dv))
        n_int = len([d for d in deps if d["origem"] != "terceiro"])
        if n_int:
            a("| Componentes internos / privados | %d | — |" % n_int)
        a("")
        crit = sorted([d for d in deps if d.get("cor") in ("vermelho", "amarelo")],
                      key=lambda d: (ORDEM_COR[d["cor"]], d["nome"]))
        if crit:
            a("### Dependências que exigem verificação\n")
            a("| Pacote | Versão | Ecossistema | Escopo | Licença | Classificação | Fonte |")
            a("| --- | --- | --- | --- | --- | --- | --- |")
            for d in crit[:60]:
                a("| %s %s | %s | %s | %s | %s | %s | %s |" % (
                    ROT[d["cor"]].split(" ")[0], md(d["nome"]), md(d["versao"] or "—"), d["ecossistema"], d["escopo"],
                    md((d.get("licenca") or "—")[:60]), CLASSES[d["classe"]], d.get("fonte_licenca") or d.get("licenca_ausente_em") or "—"))
            if len(crit) > 60:
                a("\n… e mais %d em prove_dados.json." % (len(crit) - 60))
            a("")
    else:
        a("Nenhuma dependência identificada.\n")
    if dados["manifestos"]:
        a("<details><summary>Manifestos lidos (%d)</summary>\n" % len(dados["manifestos"]))
        for m in dados["manifestos"]:
            a("- `%s` · %s · %s" % (m["arquivo"], m["ecossistema"], "analisado" if m["analisado"] else
                                    "não analisado (%s)" % m.get("obs", "")))
        a("\n</details>\n")

    a("## Autoria\n")
    if g.get("disponivel") and g.get("total_commits"):
        a("Commits: **%d** (sem merges; %d merges à parte) · contribuidores humanos: **%d** · período: %s a %s · "
          "domínio principal: %s\n" % (g["total_commits"], g.get("merges", 0), len(g["identidades"]),
                                       g["primeiro_commit"], g["ultimo_commit"], g.get("dominio_principal") or "—"))
        if g.get("linguagens"):
            a("Linguagens (arquivos versionados): %s\n" % ", ".join(
                "%s (%d)" % (x["linguagem"], x["arquivos"]) for x in g["linguagens"]))
        a("| ID | Contribuidor | Commits | % commits | % linhas | Identidade | Domínios | Período |")
        a("| --- | --- | ---: | ---: | ---: | --- | --- | --- |")
        for x in g["identidades"][:40]:
            a("| %s | %s | %d | %.1f%% | %.1f%% | %s | %s | %s → %s |" % (
                x["id"], md(x["autor"]), x["commits"], x["pct_commits"], x["pct_linhas"], x["classificacao"],
                md(", ".join(x["dominios"]) or "—"), x["primeiro_commit"], x["ultimo_commit"]))
        if len(g["identidades"]) > 40:
            a("\n… e mais %d em prove_dados.json." % (len(g["identidades"]) - 40))
        a("")
        if g.get("agentes_ia"):
            a("Commits com autoria de agente de IA: " + "; ".join(
                "%s (%d commits, %.1f%% das linhas)" % (x["ferramenta"], x["commits"], x["pct_linhas"])
                for x in g["agentes_ia"]) + "\n")
        if g.get("automacoes"):
            a("Automações excluídas da autoria: " + ", ".join(
                "%s (%d)" % (md(x["nome"]), x["commits"]) for x in g["automacoes"][:10]) + "\n")
        if g.get("importacoes"):
            a("### Código que entrou em bloco\n")
            a("| Commit | Data | Linhas | % do total | Autor |")
            a("| --- | --- | ---: | ---: | --- |")
            for i in g["importacoes"]:
                a("| `%s` | %s | %d | %.1f%% | %s |" % (i["commit"], i["data"], i["linhas"], i["pct_linhas"],
                                                     md(i["agente_ia"] or nome_id(i["autor_id"]))))
            a("")
    elif g.get("disponivel"):
        a("Repositório sem commits.\n")
    else:
        a("Repositório Git não encontrado: análise de autoria indisponível.\n")

    a("## Uso de IA declarado\n")
    ia = dados["ia"]
    if ia["ferramentas"]:
        a("| Ferramenta | Commits com registro | Primeiro registro | Último registro | Evidência | Arquivos |")
        a("| --- | ---: | --- | --- | --- | --- |")
        for f in ia["ferramentas"]:
            a("| %s | %d | %s | %s | %s | %s |" % (
                f["ferramenta"], f["commits"], f["primeiro_registro"] or "—", f["ultimo_registro"] or "—",
                ", ".join("%s (%d)" % kv for kv in f["evidencias"].items()) or "—",
                md(", ".join(f["arquivos"][:4]) or "—")))
        a("")
    else:
        a("Nenhum registro declarado.\n")
    pol = dados["parametros"].get("ferramentas_autorizadas")
    a("Política informada: %s%s\n" % (", ".join(pol) if pol else "não informada",
                                      (" · vigente desde %s" % dados["parametros"]["politica_ia_desde"])
                                      if dados["parametros"].get("politica_ia_desde") else ""))

    if dados.get("inpi"):
        x = dados["inpi"]
        a("## Dossiê para registro de programa de computador (INPI)\n")
        a("- Arquivo gerado: `%s` (fica com o titular; não deve ser alterado)" % x["arquivo"])
        a("- Resumo digital (SHA-512): `%s`" % x["sha512"])
        a("- Commit: `%s` · data de criação (primeiro commit): %s" % (x["commit"][:12], x["data_criacao"]))
        a("- Linguagens: %s" % (", ".join(x["linguagens"]) or "—"))
        a("- Autores (conforme histórico): %s" % ", ".join(x["autores"]))
        a("- Titular: preencher com o titular dos direitos patrimoniais\n")
        a("> Conferir os requisitos vigentes do INPI (e-Software) antes do depósito, inclusive o algoritmo de hash aceito.\n")

    a("## Integridade e reprodutibilidade\n")
    integ = dados["integridade"]
    a("- Commit: `%s` · branch: %s · remoto: %s" % (g.get("head") or "—", g.get("branch") or "—", g.get("remoto") or "—"))
    a("- Alterações não commitadas no momento da varredura: %s" % g.get("alteracoes_nao_commitadas", "—"))
    a("- Clone raso: %s" % ("sim" if g.get("clone_raso") else "não"))
    a("- SHA-256 da ferramenta: `%s`" % integ["ferramenta_sha256"])
    a("- SHA-256 dos dados: `%s`" % integ["hash_dados"])
    a("- Verificar: `python3 prove_scan.py --verificar <pasta-da-saida>`\n")
    a("> A verificação mostra se a saída foi alterada depois de gerada. Ela não prova que a varredura rodou sobre o "
      "repositório real: para isso, a varredura pode ser feita em sessão acompanhada ou na integração contínua do cliente.\n")

    a("## Limitações desta varredura\n")
    for t in (
        "A ferramenta **não** detecta código gerado por inteligência artificial. Não existe método confiável para isso. "
        "O que ela inventaria é o uso **declarado** (coautoria em commits, agentes, arquivos de configuração).",
        "Licenças são lidas conforme declaradas pelos mantenedores. Declaração incorreta do mantenedor não é detectável aqui.",
        "A identidade do commit reflete a configuração do Git de quem commitou, que pode não corresponder à pessoa real.",
        "Percentual de linhas e de commits mede volume, não autoria intelectual. Squash e rebase atribuem a autoria a "
        "quem integrou o código, não necessariamente a quem o escreveu.",
        "O cruzamento com contratos usa a planilha informada pelo cliente; a ferramenta não lê nem valida os contratos.",
        "A varredura não substitui a análise documental da cadeia de cessão, que é a prova que importa em uma transação.",
    ):
        a("- %s" % t)
    a("")
    a("## Próximo passo\n")
    a("Os achados indicam onde a cadeia de titularidade precisa ser verificada em documento: contrato de cessão de "
      "direitos patrimoniais de cada contribuidor, vigência à época da contribuição, política de uso de IA e "
      "compatibilidade das licenças com o modelo de distribuição do produto.\n")
    a("**Laudo de Proveniência**: análise documental, parecer e laudo assinado para apresentação a investidor, "
      "comprador ou contratante. %s\n" % CONTATO)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Integridade, anonimização, INPI
# ---------------------------------------------------------------------------

def limpar_privados(obj):
    if isinstance(obj, dict):
        return {k: limpar_privados(v) for k, v in obj.items() if not str(k).startswith("_")}
    if isinstance(obj, (list, tuple)):
        return [limpar_privados(v) for v in obj]
    if isinstance(obj, set):
        return sorted(limpar_privados(v) for v in obj)
    return obj


def hash_dados(dados):
    d = json.loads(json.dumps(dados, ensure_ascii=False))
    (d.get("integridade") or {}).pop("hash_dados", None)
    canon = json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def anonimizar(git):
    for x in git.get("identidades") or []:
        x["autor"] = "Contribuidor %s" % x["id"]
        x["nomes"] = []
        x["emails_mascarados"] = ["***@" + e.split("@")[-1] for e in x["_emails"]]


def gerar_inpi(raiz, saida, git):
    if not git.get("head"):
        return None
    destino = os.path.join(saida, "prove_inpi_fonte.zip")
    try:
        r = subprocess.run(["git", "archive", "--format=zip", "-o", destino, "HEAD", "--", "."],
                           cwd=raiz, capture_output=True, timeout=600)
        if r.returncode != 0:
            return None
    except Exception:
        return None
    h = hashlib.sha512()
    with open(destino, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return {"arquivo": os.path.basename(destino), "sha512": h.hexdigest(), "commit": git["head"],
            "data_criacao": git.get("primeiro_commit"),
            "linguagens": [x["linguagem"] for x in git.get("linguagens") or []],
            "autores": [x["autor"] for x in git.get("identidades") or []]}


def verificar(alvo):
    ok = True
    pasta = alvo if os.path.isdir(alvo) else os.path.dirname(os.path.abspath(alvo))
    jpath = os.path.join(alvo, "prove_dados.json") if os.path.isdir(alvo) else alvo
    dados = ler_json(jpath)
    if not isinstance(dados, dict) or "integridade" not in dados:
        print("ALTERADO OU INVÁLIDO: %s não é uma saída do PROVE." % jpath)
        return 1
    if hash_dados(dados) == dados["integridade"].get("hash_dados"):
        print("OK        prove_dados.json (hash interno confere)")
    else:
        print("ALTERADO  prove_dados.json (hash interno não confere)")
        ok = False
    lista = os.path.join(pasta, "prove_hashes.sha256")
    if os.path.isfile(lista):
        for linha in (ler_texto(lista) or "").splitlines():
            if "  " not in linha:
                continue
            esperado, nome = linha.split("  ", 1)
            p = os.path.join(pasta, nome.strip())
            if not os.path.isfile(p):
                print("AUSENTE   %s" % nome)
                ok = False
            elif sha256_arquivo(p) != esperado:
                print("ALTERADO  %s" % nome)
                ok = False
            else:
                print("OK        %s" % nome)
    else:
        print("AVISO     prove_hashes.sha256 não encontrado; só o JSON foi verificado.")
    print("Resultado: %s" % ("íntegro" if ok else "ALTERADO"))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------

def argumentos(argv):
    p = argparse.ArgumentParser(
        prog="prove_scan.py", add_help=False,
        description="PROVE — varredura de proveniência de código. Roda localmente e não transmite código.")
    p.add_argument("-h", "--ajuda", action="help", help="mostra esta ajuda")
    p.add_argument("caminho", nargs="?", default=".", help="pasta do projeto (padrão: pasta atual)")
    p.add_argument("--saida", default=".", help="pasta onde gravar os resultados (padrão: pasta atual)")
    p.add_argument("--distribuicao", choices=sorted(DISTRIBUICOES), default="nao_informado",
                   help="como o produto chega ao cliente; muda a gravidade das licenças copyleft")
    p.add_argument("--contratos", metavar="CSV", help="planilha de contratos para cruzar com os autores")
    p.add_argument("--gerar-modelo-contratos", metavar="CSV",
                   help="cria a planilha de contratos já preenchida com os autores do histórico e sai")
    p.add_argument("--ferramentas-autorizadas", metavar="LISTA",
                   help="ferramentas de IA autorizadas pela política, separadas por vírgula (ex.: claude,copilot)")
    p.add_argument("--politica-ia-desde", metavar="AAAA-MM-DD", help="data de início da política de uso de IA")
    p.add_argument("--online", action="store_true",
                   help="consulta licenças em registros públicos (envia só nomes e versões de pacotes)")
    p.add_argument("--online-excluir", metavar="PREFIXOS", default="",
                   help="prefixos de pacotes que não devem ser consultados online (ex.: @minhaempresa/,minhaempresa-)")
    p.add_argument("--sbom", metavar="JSON", action="append", help="importa SBOM CycloneDX ou SPDX (pode repetir)")
    p.add_argument("--anonimizar", action="store_true", help="substitui nomes de pessoas por códigos no relatório")
    p.add_argument("--inpi", action="store_true", help="gera pacote zip do código e hash SHA-512 para registro no INPI")
    p.add_argument("--falhar-em", choices=("vermelho", "amarelo"),
                   help="retorna código 2 se o resultado for desta cor ou pior (uso em integração contínua)")
    p.add_argument("--verificar", metavar="PASTA_OU_JSON", help="confere se uma saída do PROVE foi alterada e sai")
    p.add_argument("--versao", action="version", version="PROVE %s" % VERSAO)
    return p.parse_args(argv)


def main(argv=None):
    args = argumentos(sys.argv[1:] if argv is None else argv)
    if args.verificar:
        return verificar(args.verificar)

    raiz = os.path.abspath(args.caminho)
    if not os.path.isdir(raiz):
        print("Diretório não encontrado: %s" % raiz)
        return 1
    saida = os.path.abspath(args.saida)
    print("PROVE %s — varrendo %s" % (VERSAO, raiz))

    git = analisar_git(raiz)

    if args.gerar_modelo_contratos:
        if not git.get("identidades"):
            print("Sem histórico Git com autores: não há o que pré-preencher.")
            return 1
        gerar_modelo_contratos(git, args.gerar_modelo_contratos)
        print("Planilha criada: %s (%d contribuidores). Preencha vínculo, início, fim, cessão e documento e rode "
              "de novo com --contratos." % (args.gerar_modelo_contratos, len(git["identidades"])))
        print("A planilha contém e-mails completos: ela fica com você e não precisa ser enviada.")
        return 0

    autorizadas = sorted({chave_ferramenta(x) for x in (args.ferramentas_autorizadas or "").split(",") if x.strip()})
    if args.politica_ia_desde:
        try:
            args.politica_ia_desde = _data_contrato(args.politica_ia_desde)
        except ValueError:
            print("Data inválida em --politica-ia-desde: %s" % args.politica_ia_desde)
            return 1

    c = Coleta(raiz)
    coletar_manifestos(c)
    for s in args.sbom or []:
        importar_sbom(c, s)
    resolver_licencas_locais(c)
    if args.online:
        consultar_online(c, [x.strip() for x in args.online_excluir.split(",") if x.strip()])

    for d in c.deps.values():
        if d["origem"] in ("terceiro", "registro_privado"):
            n = d["nome"]
            if n in c.internos.get(d["ecossistema"], ()) or norm_nome(d["ecossistema"], n) in c.internos.get(d["ecossistema"], ()) \
                    or any(n.startswith(p) for p in c.prefixos.get(d["ecossistema"], ())):
                d["origem"] = "interna"
        if d["licenca"]:
            d["classe"] = classificar_licenca(d["licenca"])
        elif d.get("licenca_ausente_em"):
            d["classe"] = "nao_declarada"
        else:
            d["classe"] = "nao_verificada"
    deps = sorted(c.deps.values(), key=lambda d: (d["ecossistema"], d["nome"].lower()))

    arquivos_lic = sorted({a for a in os.listdir(raiz) if re.match(r"^(licen[cs]e|copying|notice)(\.(md|txt|rst))?$", a, re.I)})
    texto_lic = None
    for a in arquivos_lic:
        if not a.lower().startswith("notice"):
            texto_lic = texto_lic or identificar_texto(ler_texto(os.path.join(raiz, a), 40000) or "")

    ia = analisar_ia(raiz, git)

    cessao = None
    if args.contratos:
        try:
            contratos, erros = ler_contratos(args.contratos)
        except OSError as e:
            print("Não foi possível ler a planilha de contratos: %s" % e)
            return 1
        cessao = cruzar_contratos(git, contratos)
        cessao["erros"] = erros
        cessao["linhas_lidas"] = len(contratos)

    if args.anonimizar:
        anonimizar(git)

    dados = {
        "ferramenta": "PROVE", "versao": VERSAO,
        "data": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "projeto": os.path.basename(raiz.rstrip(os.sep)) or raiz,
        "parametros": {
            "distribuicao": args.distribuicao, "ferramentas_autorizadas": autorizadas,
            "politica_ia_desde": args.politica_ia_desde, "consulta_online": bool(args.online),
            "sbom_importado": [os.path.basename(s) for s in args.sbom or []],
            "contratos_cruzados": bool(cessao), "anonimizado": bool(args.anonimizar),
        },
        "licenca_declarada_do_projeto": c.licenca_projeto,
        "licenca_do_arquivo_do_projeto": texto_lic,
        "arquivos_licenca": arquivos_lic,
        "manifestos": c.manifestos,
        "dependencias": deps,
        "git": git,
        "ia": ia,
        "cessao": cessao,
    }
    ctx = {"distribuicao": args.distribuicao, "ferramentas_autorizadas": set(autorizadas),
           "politica_ia_desde": args.politica_ia_desde}
    dados["achados"] = avaliar(dados, ctx)
    sev = Counter(x["cor"] for x in dados["achados"])
    dados["semaforo"] = "vermelho" if sev["vermelho"] else ("amarelo" if sev["amarelo"] else "verde")

    os.makedirs(saida, exist_ok=True)
    if args.inpi:
        dados["inpi"] = gerar_inpi(raiz, saida, git)
        if not dados["inpi"]:
            print("Aviso: não foi possível gerar o pacote do INPI (é preciso Git com ao menos um commit).")

    dados = limpar_privados(dados)
    dados["integridade"] = {"algoritmo": "sha256", "ferramenta_sha256": sha256_arquivo(os.path.abspath(__file__))}
    dados["integridade"]["hash_dados"] = hash_dados(dados)

    saidas = {
        "prove_dados.json": json.dumps(dados, ensure_ascii=False, indent=2),
        "prove_relatorio.md": montar_relatorio(dados),
        "prove_sbom.cdx.json": json.dumps(gerar_cyclonedx(dados), ensure_ascii=False, indent=2),
    }
    linhas_hash = []
    for nome, conteudo in saidas.items():
        p = os.path.join(saida, nome)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(conteudo)
        linhas_hash.append("%s  %s" % (sha256_arquivo(p), nome))
    if dados.get("inpi"):
        linhas_hash.append("%s  %s" % (sha256_arquivo(os.path.join(saida, dados["inpi"]["arquivo"])), dados["inpi"]["arquivo"]))
    with open(os.path.join(saida, "prove_hashes.sha256"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(linhas_hash) + "\n")

    print("Dependências: %d · Contribuidores humanos: %s · Ferramentas de IA com registro: %d" % (
        len(deps), len(git.get("identidades") or []) if git.get("disponivel") else "—", len(ia["ferramentas"])))
    print("Resultado: %s · %d crítico(s), %d atenção, %d informativo(s)" % (
        dados["semaforo"].upper(), sev["vermelho"], sev["amarelo"], sev["info"]))
    print("Gerados em %s: %s, prove_hashes.sha256" % (saida, ", ".join(saidas)))
    if saida == raiz or saida.startswith(raiz + os.sep):
        print("Atenção: a saída está dentro do repositório analisado. Não faça commit desses arquivos.")

    if args.falhar_em and ORDEM_COR[dados["semaforo"]] <= ORDEM_COR[args.falhar_em]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
