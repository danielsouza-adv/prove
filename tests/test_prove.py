# -*- coding: utf-8 -*-
"""Testes do PROVE. Rodar com:  python3 -m unittest discover -s tests -v"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
sys.path.insert(0, RAIZ)

import prove_scan as p  # noqa: E402

GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


class Repo(object):
    """Repositório Git temporário com commits de autores e datas controlados."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="prove_teste_")
        self.git("init", "-q", "-b", "main")

    def git(self, *args, **kw):
        env = dict(os.environ, **GIT_ENV)
        env.update(kw.get("env") or {})
        return subprocess.run(["git", "-c", "commit.gpgsign=false"] + list(args), cwd=self.dir,
                              env=env, check=True, capture_output=True)

    def escrever(self, caminho, conteudo):
        p_ = os.path.join(self.dir, caminho)
        os.makedirs(os.path.dirname(p_), exist_ok=True)
        with open(p_, "w", encoding="utf-8") as f:
            f.write(conteudo)

    def commit(self, nome, email, data, arquivos=None, msg="alteração"):
        for c, t in (arquivos or {}).items():
            self.escrever(c, t)
        self.git("add", "-A")
        quando = data + "T12:00:00+00:00"
        self.git("commit", "-q", "--allow-empty", "-m", msg, env={
            "GIT_AUTHOR_NAME": nome, "GIT_AUTHOR_EMAIL": email, "GIT_AUTHOR_DATE": quando,
            "GIT_COMMITTER_NAME": nome, "GIT_COMMITTER_EMAIL": email, "GIT_COMMITTER_DATE": quando})

    def limpar(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def linhas(n, prefixo="linha"):
    return "\n".join("%s %d" % (prefixo, i) for i in range(n)) + "\n"


def rodar(repo_dir, *extra):
    saida = tempfile.mkdtemp(prefix="prove_saida_")
    cod = p.main([repo_dir, "--saida", saida] + list(extra))
    with open(os.path.join(saida, "prove_dados.json"), encoding="utf-8") as f:
        dados = json.load(f)
    with open(os.path.join(saida, "prove_relatorio.md"), encoding="utf-8") as f:
        md = f.read()
    return cod, dados, md, saida


def codigos(dados, cor=None):
    return {a["codigo"] for a in dados["achados"] if cor is None or a["cor"] == cor}


class TestLicencas(unittest.TestCase):
    CASOS = {
        "MIT": "permissiva", "Apache-2.0": "permissiva", "BSD-3-Clause": "permissiva",
        "UNLICENSED": "restritiva", "Unlicense": "permissiva", "UNKNOWN": "nao_declarada",
        "MIT OR GPL-3.0": "permissiva", "MIT AND GPL-2.0": "copyleft_forte",
        "(MIT AND Apache-2.0)": "permissiva", "GPL-2.0 WITH Classpath-exception-2.0": "copyleft_fraco",
        "GPL-2.0-with-classpath-exception": "copyleft_fraco", "MIT/Apache-2.0": "permissiva",
        "GNU General Public License v2 or later (GPLv2+)": "copyleft_forte",
        "GNU Library or Lesser General Public License (LGPL)": "copyleft_fraco",
        "LGPL-2.1-or-later": "copyleft_fraco", "AGPL-3.0-only": "copyleft_rede", "SSPL-1.0": "copyleft_rede",
        "MPL-2.0": "copyleft_fraco", "BUSL-1.1": "restritiva", "Elastic-2.0": "restritiva",
        "CC-BY-NC-4.0": "restritiva", "Other/Proprietary License": "restritiva",
        "SEE LICENSE IN LICENSE.txt": "outra", "Apache Software License": "permissiva",
        "Python Software Foundation License": "permissiva",
        "https://opensource.org/licenses/MIT": "permissiva",
        "https://github.com/smith/projeto/blob/main/LICENSE": "outra",
        "https://licenses.nuget.org/MIT": "permissiva", "UNLIMITED USE": "outra",
    }

    def test_classificacao(self):
        for lic, esperado in self.CASOS.items():
            with self.subTest(lic=lic):
                self.assertEqual(p.classificar_licenca(lic), esperado)

    def test_formatos_estruturados(self):
        self.assertEqual(p.classificar_licenca(["MIT", "GPL-3.0"]), "permissiva")
        self.assertEqual(p.classificar_licenca({"type": "GPL-3.0"}), "copyleft_forte")
        self.assertEqual(p.classificar_licenca(None), "nao_declarada")

    def test_texto_de_licenca(self):
        mit = "Permission is hereby granted, free of charge, to any person obtaining a copy"
        self.assertEqual(p.identificar_texto(mit), "MIT")
        lgpl = ("GNU LESSER GENERAL PUBLIC LICENSE Version 3 ... incorporates the terms of version 3 of the "
                "GNU General Public License")
        self.assertEqual(p.identificar_texto(lgpl), "LGPL")
        self.assertEqual(p.classificar_licenca("x" * 300 + " GNU AFFERO GENERAL PUBLIC LICENSE"), "copyleft_rede")


class TestTomlSimples(unittest.TestCase):
    def test_fallback(self):
        t = '''
[project]
name = "app"  # comentário
dependencies = [
  "requests>=2",
  'flask',
]
[tool.poetry.dependencies]
python = "^3.10"
django = { version = "^4.2", optional = true }
[[package]]
name = "a"
version = "1"
'''
        d = p.toml_simples(t)
        self.assertEqual(d["project"]["dependencies"], ["requests>=2", "flask"])
        self.assertEqual(d["tool"]["poetry"]["dependencies"]["django"]["version"], "^4.2")
        self.assertEqual(d["package"][0]["name"], "a")


class TestCenarios(unittest.TestCase):
    def setUp(self):
        self.repo = Repo()

    def tearDown(self):
        self.repo.limpar()

    def test_python_limpo_nao_fica_vermelho(self):
        """Falso positivo da v1: projeto Python sem licenças resolvidas virava VERMELHO."""
        r = self.repo
        r.escrever("requirements.txt", "requests==2.31.0\nflask>=2\n")
        r.escrever("LICENSE", "Copyright (c) Empresa. Todos os direitos reservados.\n")
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"app.py": linhas(200)})
        r.commit("Ana", "ana@empresa.com.br", "2024-02-10", {"app.py": linhas(260)})
        r.commit("Bia", "bia@empresa.com.br", "2024-03-10", {"util.py": linhas(150)})
        cod, dados, md, _ = rodar(r.dir, "--distribuicao", "saas")
        self.assertNotEqual(dados["semaforo"], "vermelho")
        self.assertIn("LIC-NAOVERIF", codigos(dados, "info"))
        self.assertNotIn("LIC-NAODECL", codigos(dados))

    def test_licenca_python_instalada(self):
        r = self.repo
        r.escrever("requirements.txt", "requests==2.31.0\nsecreto==1.0\n")
        sp = ".venv/lib/python3.12/site-packages/"
        r.escrever(sp + "requests-2.31.0.dist-info/METADATA",
                   "Metadata-Version: 2.1\nName: requests\nLicense: Apache 2.0\n"
                   "Classifier: License :: OSI Approved :: Apache Software License\n\ncorpo")
        r.escrever(sp + "secreto-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: secreto\n\ncorpo")
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"app.py": linhas(10)})
        _, dados, _, _ = rodar(r.dir)
        por_nome = {d["nome"]: d for d in dados["dependencias"]}
        self.assertEqual(por_nome["requests"]["classe"], "permissiva")
        self.assertEqual(por_nome["requests"]["fonte_licenca"], "instalado")
        self.assertEqual(por_nome["secreto"]["classe"], "nao_declarada")

    def test_bots_e_noreply(self):
        r = self.repo
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"a.py": linhas(100)})
        r.commit("Bruno", "123+bruno@users.noreply.github.com", "2024-01-11", {"b.py": linhas(50)})
        r.commit("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com", "2024-01-12",
                 {"c.txt": "x\n"})
        _, dados, _, _ = rodar(r.dir)
        g = dados["git"]
        self.assertEqual(len(g["identidades"]), 2)
        self.assertEqual(g["automacoes"][0]["commits"], 1)
        self.assertIn("AUT-OCULTA", codigos(dados))
        self.assertNotIn("AUT-EXTERNO", codigos(dados))

    def test_mesma_pessoa_com_dois_emails(self):
        r = self.repo
        r.commit("Carlos Souza", "carlos@empresa.com.br", "2024-01-10", {"a.py": linhas(10)})
        r.commit("Carlos Souza", "carlos.souza@gmail.com", "2024-01-11", {"b.py": linhas(10)})
        _, dados, _, _ = rodar(r.dir)
        ids = dados["git"]["identidades"]
        self.assertEqual(len(ids), 1)
        self.assertTrue(ids[0]["email_pessoal"])
        self.assertNotIn("carlos@empresa.com.br", json.dumps(dados))   # e-mail completo não sai

    def test_npm_lock_transitiva_gpl_e_distribuicao(self):
        r = self.repo
        r.escrever("package.json", json.dumps({
            "name": "@empresa/app", "license": "ISC", "dependencies": {"express": "^4.18.0", "@empresa/ui": "^1.0.0"},
            "devDependencies": {"ferramenta-gpl": "1.0.0"}}))
        r.escrever("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "@empresa/app"},
            "node_modules/express": {"version": "4.18.2", "license": "MIT"},
            "node_modules/lib-gpl": {"version": "2.0.0", "license": "GPL-3.0"},
            "node_modules/lib-agpl": {"version": "1.0.0", "license": "AGPL-3.0"},
            "node_modules/ferramenta-gpl": {"version": "1.0.0", "license": "GPL-2.0", "dev": True},
            "node_modules/pago": {"version": "1.0.0", "license": "UNLICENSED"},
            "node_modules/@empresa/ui": {"version": "1.0.0", "resolved": "https://npm.empresa.com/ui.tgz"},
        }}))
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"index.js": linhas(50)})

        _, saas, _, _ = rodar(r.dir, "--distribuicao", "saas")
        por = {d["nome"]: d for d in saas["dependencias"]}
        self.assertEqual(por["lib-gpl"]["cor"], "amarelo")       # SaaS: GPL não é acionada pela rede
        self.assertEqual(por["lib-agpl"]["cor"], "vermelho")     # AGPL é
        self.assertEqual(por["ferramenta-gpl"]["cor"], "info")   # só desenvolvimento
        self.assertEqual(por["pago"]["cor"], "vermelho")         # UNLICENSED em produção
        self.assertEqual(por["@empresa/ui"]["origem"], "interna")
        self.assertIn("LIC-PROJETO", codigos(saas))             # "ISC" do npm init

        _, inst, _, _ = rodar(r.dir, "--distribuicao", "instalado")
        self.assertEqual({d["nome"]: d for d in inst["dependencias"]}["lib-gpl"]["cor"], "vermelho")

    def test_parsers_varios_ecossistemas(self):
        r = self.repo
        r.escrever("go.mod", "module github.com/empresa/svc\n\ngo 1.22\n\nrequire (\n"
                             "\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/text v0.14.0 // indirect\n"
                             "\tgithub.com/empresa/comum v0.1.0\n)\n")
        r.escrever("Cargo.toml", '[package]\nname = "x"\nlicense = "MIT"\n[dependencies]\nserde = "1.0"\n'
                                 'local = { path = "../local" }\n[dev-dependencies]\ncriterion = "0.5"\n')
        r.escrever("composer.json", json.dumps({"require": {"php": ">=8", "monolog/monolog": "^3"}}))
        r.escrever("composer.lock", json.dumps({"packages": [{"name": "monolog/monolog", "version": "3.5.0",
                                                              "license": ["MIT"]}], "packages-dev": []}))
        r.escrever("pom.xml", '<project xmlns="http://maven.apache.org/POM/4.0.0"><groupId>br.empresa</groupId>'
                              '<artifactId>app</artifactId><properties><jackson.version>2.17.0</jackson.version>'
                              '</properties><dependencies><dependency><groupId>com.fasterxml.jackson.core</groupId>'
                              '<artifactId>jackson-databind</artifactId><version>${jackson.version}</version>'
                              '</dependency><dependency><groupId>junit</groupId><artifactId>junit</artifactId>'
                              '<version>4.13.2</version><scope>test</scope></dependency></dependencies></project>')
        r.escrever("Gemfile", "source 'https://rubygems.org'\ngem 'rails', '7.1.0'\ngroup :development, :test do\n"
                              "  gem 'rspec'\nend\n")
        r.escrever("app/App.csproj", '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" '
                                     'Version="13.0.3" /></ItemGroup></Project>')
        r.escrever("pyproject.toml", '[project]\nname = "svc"\ndependencies = ["httpx>=0.27"]\n'
                                     '[project.optional-dependencies]\ndev = ["pytest"]\n')
        r.escrever("setup.py", "from setuptools import setup\nsetup()\n")
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10")
        _, dados, _, _ = rodar(r.dir)
        por = {(d["ecossistema"], d["nome"]): d for d in dados["dependencias"]}
        self.assertEqual(por[("go", "golang.org/x/text")]["escopo"], "indeterminado")
        self.assertEqual(por[("go", "github.com/empresa/comum")]["origem"], "interna")
        self.assertEqual(por[("cargo", "local")]["origem"], "interna")
        self.assertEqual(por[("cargo", "criterion")]["escopo"], "desenvolvimento")
        self.assertEqual(por[("composer", "monolog/monolog")]["classe"], "permissiva")
        self.assertNotIn(("composer", "php"), por)
        self.assertEqual(por[("maven", "com.fasterxml.jackson.core:jackson-databind")]["versao"], "2.17.0")
        self.assertEqual(por[("maven", "junit:junit")]["escopo"], "desenvolvimento")
        self.assertEqual(por[("rubygems", "rspec")]["escopo"], "desenvolvimento")
        self.assertIn(("nuget", "Newtonsoft.Json"), por)
        self.assertEqual(por[("pypi", "pytest")]["escopo"], "desenvolvimento")
        self.assertIn("MAN-NAOANAL", codigos(dados))            # setup.py listado, não lido

    def test_contratos(self):
        r = self.repo
        r.commit("Ana", "ana@empresa.com.br", "2023-01-10", {"a.py": linhas(300)})
        r.commit("Freela", "freela@gmail.com", "2023-02-10", {"b.py": linhas(400)})   # antes do contrato
        r.commit("Freela", "freela@gmail.com", "2023-06-10", {"b.py": linhas(450)})
        r.commit("Sem Contrato", "sc@agencia.com", "2023-07-10", {"c.py": linhas(200)})
        modelo = os.path.join(r.dir, "..", os.path.basename(r.dir) + "_contratos.csv")
        self.assertEqual(p.main([r.dir, "--gerar-modelo-contratos", modelo]), 0)
        with open(modelo, encoding="utf-8-sig") as f:
            self.assertIn("freela@gmail.com", f.read())
        with open(modelo, "w", encoding="utf-8-sig") as f:
            f.write("identificador;nome;vinculo;inicio;fim;cessao;documento;observacao\n"
                    "ana@empresa.com.br;Ana;CLT;01/01/2022;;sim;contrato-ana.pdf;\n"
                    "freela@gmail.com;Freela;PJ;2023-05-01;2023-12-31;não;contrato-freela.pdf;\n"
                    "ninguem@x.com;Ninguém;PJ;2023-01-01;;sim;;\n")
        _, dados, md, _ = rodar(r.dir, "--contratos", modelo)
        os.remove(modelo)
        m = {x["id"]: x for x in dados["cessao"]["matriz"]}
        ids = {x["autor"]: x["id"] for x in dados["git"]["identidades"]}
        self.assertEqual(m[ids["Ana"]]["situacao"], "coberto")
        self.assertEqual(m[ids["Freela"]]["situacao"], "fora_da_vigencia")
        self.assertEqual(m[ids["Freela"]]["periodo_descoberto"], ["2023-02-10", "2023-02-10"])
        self.assertEqual(m[ids["Sem Contrato"]]["situacao"], "sem_registro")
        self.assertIn("CES-FORAVIG", codigos(dados, "vermelho"))
        self.assertIn("CES-SEMREG", codigos(dados, "vermelho"))
        self.assertIn("CES-SOBRA", codigos(dados))
        self.assertIn("Matriz de cessão", md)

    def test_ia_declarada_e_politica(self):
        r = self.repo
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"a.py": linhas(100)})
        r.commit("Ana", "ana@empresa.com.br", "2024-02-10", {"a.py": linhas(150), "CLAUDE.md": "regras\n"},
                 msg="feat: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
        r.commit("Bruno", "bruno@gmail.com", "2024-03-10", {"b.py": linhas(80)},
                 msg="fix\n\nCo-authored-by: Cursor Agent <cursoragent@cursor.com>")
        r.commit("Claude Dupont", "claude.dupont@empresa.com.br", "2024-04-10", {"c.py": linhas(30)})  # humano
        r.commit("Copilot", "198982749+Copilot@users.noreply.github.com", "2024-05-10", {"d.py": linhas(40)})
        r.escrever(".cursorrules", "x")
        _, dados, md, _ = rodar(r.dir, "--ferramentas-autorizadas", "claude", "--politica-ia-desde", "2024-03-01")
        f = {x["ferramenta"]: x for x in dados["ia"]["ferramentas"]}
        self.assertEqual(f["Claude (Anthropic)"]["commits"], 1)
        self.assertIn("CLAUDE.md", f["Claude (Anthropic)"]["arquivos"])
        self.assertEqual(f["Cursor"]["commits"], 1)
        self.assertEqual(f["GitHub Copilot"]["commits"], 1)
        nomes = {x["autor"] for x in dados["git"]["identidades"]}
        self.assertIn("Claude Dupont", nomes)                  # pessoa chamada Claude não é IA
        self.assertNotIn("Copilot", nomes)                     # agente fica fora da matriz de pessoas
        self.assertEqual(dados["git"]["agentes_ia"][0]["ferramenta"], "GitHub Copilot")
        cods = codigos(dados)
        for c in ("IA-USO", "IA-NAOAUT", "IA-ANTERIOR", "IA-PESSOAL", "IA-AGENTE"):
            self.assertIn(c, cods)
        self.assertNotIn("IA-SEMPOL", cods)

    def test_importacao_em_bloco(self):
        r = self.repo
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"legado.py": linhas(5000)}, msg="import inicial")
        r.commit("Ana", "ana@empresa.com.br", "2024-02-10", {"novo.py": linhas(100)})
        _, dados, _, _ = rodar(r.dir)
        self.assertIn("AUT-IMPORTACAO", codigos(dados))
        self.assertTrue(dados["git"]["importacoes"][0]["primeiro_commit"])

    def test_integridade_e_adulteracao(self):
        r = self.repo
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"a.py": linhas(10)})
        _, dados, _, saida = rodar(r.dir)
        self.assertEqual(p.verificar(saida), 0)
        caminho = os.path.join(saida, "prove_dados.json")
        dados["semaforo"] = "verde"
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f)
        self.assertEqual(p.verificar(saida), 1)
        self.assertEqual(p.verificar(caminho), 1)

    def test_sbom_exporta_e_importa(self):
        r = self.repo
        r.escrever("package.json", json.dumps({"dependencies": {"left-pad": "1.3.0", "@scope/x": "2.0.0"}}))
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10")
        externo = os.path.join(r.dir, "..", os.path.basename(r.dir) + "_sbom.json")
        with open(externo, "w") as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
                {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0",
                 "licenses": [{"license": {"id": "WTFPL"}}]},
                {"name": "x", "purl": "pkg:npm/%40scope/x@2.0.0", "licenses": [{"expression": "MIT OR Apache-2.0"}]}]}, f)
        _, dados, _, saida = rodar(r.dir, "--sbom", externo)
        os.remove(externo)
        por = {d["nome"]: d for d in dados["dependencias"]}
        self.assertEqual(por["left-pad"]["fonte_licenca"], "sbom")
        self.assertEqual(por["@scope/x"]["classe"], "permissiva")
        with open(os.path.join(saida, "prove_sbom.cdx.json")) as f:
            bom = json.load(f)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        purls = {c.get("purl") for c in bom["components"]}
        self.assertIn("pkg:npm/%40scope/x@2.0.0", purls)

    def test_anonimizar(self):
        r = self.repo
        r.commit("Maria Secreta", "maria@gmail.com", "2024-01-10", {"a.py": linhas(10)})
        _, dados, md, _ = rodar(r.dir, "--anonimizar")
        self.assertNotIn("Maria", json.dumps(dados, ensure_ascii=False))
        self.assertNotIn("Maria", md)
        self.assertIn("***@gmail.com", json.dumps(dados))

    def test_inpi(self):
        r = self.repo
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"a.py": linhas(10)})
        _, dados, md, saida = rodar(r.dir, "--inpi")
        self.assertEqual(len(dados["inpi"]["sha512"]), 128)
        self.assertTrue(os.path.isfile(os.path.join(saida, "prove_inpi_fonte.zip")))
        self.assertEqual(p.verificar(saida), 0)

    def test_falhar_em_para_ci(self):
        vazio = tempfile.mkdtemp()
        try:
            saida = tempfile.mkdtemp()
            self.assertEqual(p.main([vazio, "--saida", saida, "--falhar-em", "vermelho"]), 2)  # sem Git = vermelho
        finally:
            shutil.rmtree(vazio)

    def test_subpasta_de_monorepo(self):
        r = self.repo
        r.commit("Ana", "ana@empresa.com.br", "2024-01-10", {"svc-a/a.py": linhas(10)})
        r.commit("Bia", "bia@empresa.com.br", "2024-01-11", {"svc-b/b.py": linhas(10)})
        _, dados, _, _ = rodar(os.path.join(r.dir, "svc-a"))
        self.assertEqual([x["autor"] for x in dados["git"]["identidades"]], ["Ana"])


if __name__ == "__main__":
    unittest.main()
