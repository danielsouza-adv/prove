# PROVE — Varredura de Proveniência de Código

**Proveniência · Rastreabilidade · Origem · Verificação · Evidência**

Uma pergunta que todo investidor, comprador ou contratante público faz e quase ninguém consegue responder com documento: **a empresa é dona do próprio código?**

O PROVE roda no seu computador e, em poucos segundos, mostra onde a cadeia de titularidade do software pode quebrar:

- **Dependências e licenças**: npm, PyPI, Go, Rust, PHP, Ruby, Java/Kotlin, .NET e Dart. Separa produção de desenvolvimento e ajusta a gravidade ao modelo de distribuição (SaaS, instalado, app, biblioteca).
- **Autoria**: quem escreveu o quê e quando, a partir do histórico do Git. Sinaliza e-mail pessoal, e-mail oculto, agência externa, autoria concentrada e código que entrou no repositório em bloco.
- **Cruzamento com contratos**: compara o período de contribuição de cada pessoa com a vigência e a cláusula de cessão dos contratos.
- **Uso de IA declarado**: coautoria de IA nos commits, agentes que commitam e arquivos de configuração (Claude, Copilot, Cursor e outros), confrontados com a política de ferramentas autorizadas.
- **SBOM** no padrão CycloneDX, exigido cada vez mais em contrato corporativo e licitação.
- **Integridade**: hash de cada arquivo gerado e referência ao commit exato analisado.

## Privacidade: o código não sai da sua máquina

O PROVE lê **apenas** arquivos de manifesto (`package.json`, `requirements.txt`, `go.mod`…), metadados de licença dos pacotes de terceiros, o histórico do Git e os **nomes** de arquivos de configuração. Ele não abre os arquivos de código-fonte da aplicação e não envia nada a ninguém. Você decide o que compartilhar: o relatório gerado.

A única opção que acessa a internet é `--online`, que você liga explicitamente. Ela envia apenas o nome e a versão de cada pacote público para os registros oficiais (npm, PyPI etc.). Pacotes do seu próprio escopo ficam de fora, e você pode excluir outros com `--online-excluir`.

## Como usar

Requisitos: Python 3.8 ou superior. Git recomendado. Nenhuma instalação adicional.

```bash
# 1. Varredura básica
python3 prove_scan.py caminho/do/projeto --distribuicao saas

# 2. Cruzamento com contratos (a planilha fica com você)
python3 prove_scan.py caminho/do/projeto --gerar-modelo-contratos contratos.csv
#    ...preencha vínculo, início, fim, cessão e documento de cada pessoa...
python3 prove_scan.py caminho/do/projeto --distribuicao saas --contratos contratos.csv

# 3. Política de IA
python3 prove_scan.py caminho/do/projeto --ferramentas-autorizadas claude,copilot --politica-ia-desde 2025-01-01

# 4. Conferir se um relatório foi alterado depois de gerado
python3 prove_scan.py --verificar pasta-da-saida
```

### Opções

| Opção | Para quê |
| --- | --- |
| `--distribuicao` | `saas`, `instalado`, `mobile`, `biblioteca` ou `interno`. Muda a gravidade de GPL/AGPL/LGPL. |
| `--gerar-modelo-contratos ARQ.csv` | Cria a planilha de contratos já com os autores do histórico. |
| `--contratos ARQ.csv` | Cruza autores × contratos de cessão. |
| `--ferramentas-autorizadas LISTA` | Ferramentas de IA permitidas pela política (ex.: `claude,copilot`). |
| `--politica-ia-desde AAAA-MM-DD` | Data em que a política passou a valer. |
| `--online` | Busca licenças que faltam em registros públicos. |
| `--online-excluir PREFIXOS` | Prefixos de pacotes que nunca devem ser consultados. |
| `--sbom ARQ.json` | Importa SBOM CycloneDX ou SPDX de outra ferramenta (Syft, Trivy, FOSSA, Snyk…). |
| `--anonimizar` | Troca nomes por códigos (C01, C02…) para compartilhar o relatório. |
| `--inpi` | Gera o pacote do código e o hash SHA-512 para registro de programa de computador. |
| `--saida PASTA` | Onde gravar os resultados. |
| `--falhar-em vermelho` | Retorna código 2 se o resultado for vermelho (uso em CI). |

### O que é gerado

| Arquivo | Conteúdo |
| --- | --- |
| `prove_relatorio.md` | Relatório legível, com semáforo, achados e limitações. |
| `prove_dados.json` | Os mesmos dados em formato estruturado, com hash de integridade. |
| `prove_sbom.cdx.json` | SBOM CycloneDX 1.5. |
| `prove_hashes.sha256` | Hash de cada arquivo (confira com `--verificar` ou `sha256sum -c`). |

Veja um relatório completo, gerado sobre um projeto fictício, em [`exemplos/relatorio_exemplo.md`](exemplos/relatorio_exemplo.md).

## Planilha de contratos

Colunas (separador `;` ou `,`; datas em `AAAA-MM-DD` ou `DD/MM/AAAA`):

| Coluna | Exemplo |
| --- | --- |
| `identificador` | e-mails usados nos commits, separados por `\|` |
| `nome` | nome da pessoa ou empresa |
| `vinculo` | `clt`, `pj`, `freelancer`, `agencia`, `socio`, `estagio`, `estatutario`, `cooperado`, `voluntario`, `outro` |
| `inicio`, `fim` | vigência do contrato (fim vazio = vigente) |
| `cessao` | `sim`, `nao`, `parcial` |
| `documento` | referência ao contrato (arquivo, número, data) |
| `observacao` | livre |

Uma pessoa pode ter várias linhas (contratos sucessivos). Modelo em [`modelos/contratos_modelo.csv`](modelos/contratos_modelo.csv).

## Uso em integração contínua

O PROVE pode rodar a cada mudança no repositório e manter o relatório sempre atualizado. Exemplo para GitHub Actions em [`exemplos/github-action.yml`](exemplos/github-action.yml).

## O que o PROVE não faz

- **Não detecta código gerado por IA.** Não existe método confiável para isso, e quem promete está vendendo o que não entrega. O PROVE inventaria o uso de IA **declarado** e o confronta com a política da empresa.
- Não lê nem valida contratos: usa a planilha informada.
- Não substitui a análise documental da cadeia de cessão. O relatório indica onde olhar; a prova que importa numa transação é o documento.

A metodologia e os códigos de achado estão em [`docs/METODOLOGIA.md`](docs/METODOLOGIA.md).

## Laudo de Proveniência

O relatório do PROVE é o diagnóstico. O **Laudo de Proveniência** é a análise documental dos contratos, da política de IA e das licenças, com parecer assinado para apresentar a investidor, comprador ou contratante.

**D'Souza Advocacia Empresarial** · Dr. Daniel de Souza · OAB/DF 71.124
danielssouza.com · (61) 98379-0033

## Desenvolvimento

```bash
python3 -m unittest discover -s tests -v    # testes
python3 exemplos/gerar_exemplo.py           # regenera o relatório de exemplo
```

Repositório: https://github.com/danielsouza-adv/prove

Licença: MIT (veja [LICENSE](LICENSE)).
