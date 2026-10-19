#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gera um repositório fictício com os problemas mais comuns e roda o PROVE sobre ele.
O resultado (exemplos/relatorio_exemplo.md) serve para mostrar a ferramenta a clientes
sem expor dados de ninguém.

Uso:  python3 exemplos/gerar_exemplo.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(AQUI))
import prove_scan  # noqa: E402

ENV = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)


def git(repo, *args, **env):
    e = dict(ENV)
    e.update(env)
    subprocess.run(["git", "-c", "commit.gpgsign=false"] + list(args), cwd=repo, env=e, check=True,
                   capture_output=True)


def escrever(repo, caminho, conteudo):
    p = os.path.join(repo, caminho)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(conteudo)


def commit(repo, nome, email, data, arquivos, msg="alteração"):
    for c, t in arquivos.items():
        escrever(repo, c, t)
    git(repo, "add", "-A")
    quando = data + "T14:00:00-03:00"
    git(repo, "commit", "-q", "-m", msg, GIT_AUTHOR_NAME=nome, GIT_AUTHOR_EMAIL=email, GIT_AUTHOR_DATE=quando,
        GIT_COMMITTER_NAME=nome, GIT_COMMITTER_EMAIL=email, GIT_COMMITTER_DATE=quando)


def codigo(n, nome):
    return "".join("def %s_%d():\n    return %d\n\n" % (nome, i, i) for i in range(n))


def main():
    base = tempfile.mkdtemp(prefix="prove_exemplo_")
    repo = os.path.join(base, "acme-pagamentos")
    os.makedirs(repo)
    git(repo, "init", "-q", "-b", "main")

    escrever(repo, "package.json", json.dumps({
        "name": "@acme/pagamentos", "version": "1.0.0", "license": "ISC",
        "dependencies": {"express": "^4.18.2", "pdf-gerador": "^2.1.0", "@acme/ui": "^1.0.0"},
        "devDependencies": {"jest": "^29.0.0"}}, indent=2))
    escrever(repo, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "@acme/pagamentos"},
        "node_modules/express": {"version": "4.18.2", "license": "MIT"},
        "node_modules/pdf-gerador": {"version": "2.1.0", "license": "AGPL-3.0"},
        "node_modules/graficos-pro": {"version": "3.0.0", "license": "UNLICENSED"},
        "node_modules/leitor-xml": {"version": "1.4.0", "license": "GPL-2.0"},
        "node_modules/jest": {"version": "29.7.0", "license": "MIT", "dev": True},
        "node_modules/@acme/ui": {"version": "1.0.0", "resolved": "https://npm.acme.com.br/ui-1.0.0.tgz"},
    }}, indent=2))

    commit(repo, "Marina Costa", "marina@acme.com.br", "2023-03-01",
           {"src/legado.py": codigo(900, "legado")}, "importa código da versão anterior")
    commit(repo, "Marina Costa", "marina@acme.com.br", "2023-04-12", {"src/api.py": codigo(120, "api")})
    commit(repo, "Rafa Dev", "rafa.dev@gmail.com", "2023-05-20", {"src/cobranca.py": codigo(260, "cobranca")})
    commit(repo, "Rafa Dev", "rafa.dev@gmail.com", "2023-09-02", {"src/boleto.py": codigo(180, "boleto")})
    commit(repo, "Equipe Pixel", "dev@pixelagencia.com.br", "2023-10-15", {"web/app.js": "x\n" * 900})
    commit(repo, "João Pereira", "joao@acme.com.br", "2024-02-01", {"src/pix.py": codigo(150, "pix")},
           "feat: pix\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
    commit(repo, "Rafa Dev", "rafa.dev@gmail.com", "2024-03-05", {"src/conciliacao.py": codigo(90, "conc"),
                                                                   ".cursorrules": "regras\n"},
           "feat: conciliação\n\nCo-authored-by: Cursor Agent <cursoragent@cursor.com>")
    commit(repo, "João Pereira", "joao@acme.com.br", "2024-06-10", {"src/relatorios.py": codigo(110, "rel"),
                                                                     "CLAUDE.md": "contexto\n"},
           "feat: relatórios\n\nCo-Authored-By: Claude <noreply@anthropic.com>")

    contratos = os.path.join(base, "contratos.csv")
    with open(contratos, "w", encoding="utf-8-sig") as f:
        f.write("identificador;nome;vinculo;inicio;fim;cessao;documento;observacao\n"
                "marina@acme.com.br;Marina Costa;socio;01/01/2023;;nao;contrato social 2023;\n"
                "rafa.dev@gmail.com;Rafa Dev;pj;01/08/2023;;nao;contrato PJ ago/2023;\n"
                "joao@acme.com.br;João Pereira;clt;10/01/2024;;sim;contrato de trabalho + aditivo PI;\n")

    saida = os.path.join(base, "saida")
    prove_scan.main([repo, "--saida", saida, "--distribuicao", "saas", "--contratos", contratos,
                     "--ferramentas-autorizadas", "claude", "--politica-ia-desde", "2024-01-01"])
    destino = os.path.join(AQUI, "relatorio_exemplo.md")
    shutil.copy(os.path.join(saida, "prove_relatorio.md"), destino)
    shutil.rmtree(base, ignore_errors=True)
    print("Relatório de exemplo salvo em %s" % destino)


if __name__ == "__main__":
    main()
