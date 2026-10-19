# PROVE — Varredura de Proveniência de Código

**D'Souza Advocacia Empresarial** · Dr. Daniel de Souza · OAB/DF 71.124

- Projeto analisado: `acme-pagamentos`
- Data da varredura: 2026-10-19
- Versão da ferramenta: PROVE 2.0.0
- Modelo de distribuição: SaaS / acesso pela rede, sem entrega de software ao cliente
- Commit analisado: `4020f76a0f07` (main)
- Hash dos dados (SHA-256): `c0aef308ec953c93915ee64805f4bc756e8444b89541ab6ea34887ffda331ca3`

---

## Resultado preliminar: 🔴 VERMELHO

5 achado(s) crítico(s) · 7 ponto(s) de atenção · 2 informativo(s)

- Dependências: **6** (5 de produção ou escopo incerto, 1 de desenvolvimento)
- Contribuidores humanos: **4** · commits: 8 · período: 2023-03-01 a 2024-06-10
- Ferramentas de IA com registro: **2**
- Cruzamento com contratos: realizado

> Esta varredura lê apenas manifestos de dependência, metadados de licença de terceiros, o histórico de autoria do Git e nomes de arquivos de configuração. Nenhum arquivo de código-fonte da aplicação é lido, copiado ou transmitido.

## Achados

**🔴 VERMELHO · Contribuidor com identidade pessoal** `AUT-PESSOAL`

1 contribuidor(es) com e-mail de provedor pessoal, somando cerca de 37.5% da autoria. Cada um exige vínculo e cessão de direitos patrimoniais vigentes à época da contribuição.

- Rafa Dev (C02)

**🔴 VERMELHO · Commits fora da vigência do contrato** `CES-FORAVIG`

Há contribuições antes do início ou depois do fim dos contratos informados. O que foi produzido fora da vigência não é alcançado pelo art. 4º da Lei 9.609/98 e exige cessão específica.

- Rafa Dev (C02) · 1 commit(s) de 2023-05-20 a 2023-05-20

**🔴 VERMELHO · Contribuidor sem contrato registrado** `CES-SEMREG`

Não há contrato informado para estas pessoas. Sem vínculo formal, a regra é a titularidade do autor.

- Equipe Pixel (C03) · 1 commit(s) de 2023-10-15 a 2023-10-15

**🔴 VERMELHO · Dependência com copyleft de rede (AGPL/SSPL)** `LIC-REDE`

1 dependência(s). Licença de efeito recíproco que alcança o uso pela rede. Em SaaS ou em produto distribuído, pode obrigar a disponibilizar o código-fonte da aplicação aos usuários.

- pdf-gerador@2.1.0 (AGPL-3.0 · producao)

**🔴 VERMELHO · Dependência com licença restritiva ou sem concessão** `LIC-RESTRITA`

1 dependência(s). UNLICENSED, BUSL, Elastic, licenças não comerciais e similares: o uso depende de contrato ou de termos específicos. Sem esse documento não há direito de uso demonstrável.

- graficos-pro@3.0.0 (UNLICENSED · producao)

**🟡 AMARELO · Contribuidor de domínio externo** `AUT-EXTERNO`

1 contribuidor(es) com e-mail fora do domínio principal (acme.com.br). Indica terceiro, agência ou fornecedor: confirmar contrato com cláusula de cessão e a cadeia do próprio fornecedor.

- Equipe Pixel (C03)

**🟡 AMARELO · Código que entrou em bloco** `AUT-IMPORTACAO`

1 commit(s) adicionaram parcela relevante do código de uma só vez. Pode indicar código desenvolvido fora deste histórico (repositório anterior, fornecedor, template, código gerado). A origem desses blocos precisa ser documentada.

- d6eaee6c5a · 2023-03-01 · 2713 linhas (42.8%) · primeiro commit

**🟡 AMARELO · Sócio sem cessão formalizada** `CES-SOCIO`

Verificar contrato social ou acordo de sócios quanto à integralização ou cessão da propriedade intelectual à sociedade.

- Marina Costa (C01)

**🟡 AMARELO · Ferramenta de IA fora da política** `IA-NAOAUT`

Há registro de uso de ferramenta não incluída entre as autorizadas (Claude (Anthropic)). Verificar plano contratado, termos de uso (titularidade do resultado, uso de dados, indenização) e se houve envio de código confidencial.

- Cursor · 1 commit(s)

**🟡 AMARELO · Uso de IA associado a identidades pessoais** `IA-PESSOAL`

Commits com registro de IA feitos por contribuidores com e-mail pessoal ou oculto. Indica possível uso de conta ou plano pessoal da ferramenta, cujos termos (titularidade do resultado, uso de dados para treino, indenização) costumam diferir do plano corporativo.

- Cursor · C02

**🟡 AMARELO · Dependência com copyleft forte (GPL)** `LIC-FORTE`

1 dependência(s). Se o produto for distribuído (instalado, aplicativo, entrega de código-fonte, comum em contrato público), pode obrigar a licenciar o código derivado sob a mesma licença. No modelo SaaS informado, em regra não há distribuição; o risco se materializa se o produto passar a ser instalado, virar aplicativo ou se o contrato exigir entrega de fontes.

- leitor-xml@1.4.0 (GPL-2.0 · producao)

**🟡 AMARELO · O próprio projeto declara licença aberta** `LIC-PROJETO`

O projeto declara 'ISC' em package.json. Se o produto é proprietário, essa declaração pode ser lida como concessão pública de direitos sobre o código. O valor 'ISC' é o padrão do 'npm init' e costuma estar ali por descuido. Confirmar se é intencional.

**⚪ INFORMATIVO · Uso de IA declarado no repositório** `IA-USO`

2 ferramenta(s) com registro de uso (coautoria em commits, autoria por agente ou arquivo de configuração). 37.5% dos commits têm registro de IA. Isso não é detecção: é o que o próprio histórico declara. A proteção autoral de trechos produzidos com contribuição humana mínima é juridicamente incerta; documentar a revisão humana e a política de uso fortalece a titularidade.

- Claude (Anthropic) · 2 commit(s) · arquivos: CLAUDE.md
- Cursor · 1 commit(s) · arquivos: .cursorrules

**⚪ INFORMATIVO · Componentes internos ou de registro privado** `LIC-INTERNA`

1 componente(s) parecem ser do próprio projeto ou vir de registro privado. A titularidade deles se prova pela cadeia de cessão, não por licença.

- @acme/ui

## Matriz de cessão

| ID | Contribuidor | Vínculo | Cessão | Commits | Fora da vigência | Situação |
| --- | --- | --- | --- | ---: | ---: | --- |
| C01 | Marina Costa | Sócio | Não | 2 | 0 | 🟡 Sócio sem cessão |
| C02 | Rafa Dev | PJ | Não | 3 | 1 | 🔴 Fora da vigência |
| C03 | Equipe Pixel | — | — | 1 | 1 | 🔴 Sem contrato |
| C04 | João Pereira | CLT | Sim | 2 | 0 | 🟢 Coberto |

## Inventário de dependências

Ecossistemas: npm (6) · diretas: 4 · transitivas: 2

| Classificação da licença | Produção / incerto | Desenvolvimento |
| --- | ---: | ---: |
| Copyleft de rede (AGPL, SSPL) | 1 | 0 |
| Copyleft forte (GPL) | 1 | 0 |
| Restritiva / comercial (UNLICENSED, BUSL, Elastic, NC) | 1 | 0 |
| Permissiva (MIT, Apache, BSD…) | 1 | 1 |
| Componentes internos / privados | 1 | — |

### Dependências que exigem verificação

| Pacote | Versão | Ecossistema | Escopo | Licença | Classificação | Fonte |
| --- | --- | --- | --- | --- | --- | --- |
| 🔴 graficos-pro | 3.0.0 | npm | producao | UNLICENSED | Restritiva / comercial (UNLICENSED, BUSL, Elastic, NC) | lockfile |
| 🔴 pdf-gerador | 2.1.0 | npm | producao | AGPL-3.0 | Copyleft de rede (AGPL, SSPL) | lockfile |
| 🟡 leitor-xml | 1.4.0 | npm | producao | GPL-2.0 | Copyleft forte (GPL) | lockfile |

<details><summary>Manifestos lidos (2)</summary>

- `package-lock.json` · npm · analisado
- `package.json` · npm · analisado

</details>

## Autoria

Commits: **8** (sem merges; 0 merges à parte) · contribuidores humanos: **4** · período: 2023-03-01 a 2024-06-10 · domínio principal: acme.com.br

Linguagens (arquivos versionados): Python (7), JavaScript (1)

| ID | Contribuidor | Commits | % commits | % linhas | Identidade | Domínios | Período |
| --- | --- | ---: | ---: | ---: | --- | --- | --- |
| C01 | Marina Costa | 2 | 25.0% | 48.4% | corporativa | acme.com.br | 2023-03-01 → 2023-04-12 |
| C02 | Rafa Dev | 3 | 37.5% | 25.1% | pessoal | gmail.com | 2023-05-20 → 2024-03-05 |
| C03 | Equipe Pixel | 1 | 12.5% | 14.2% | externa | pixelagencia.com.br | 2023-10-15 → 2023-10-15 |
| C04 | João Pereira | 2 | 25.0% | 12.3% | corporativa | acme.com.br | 2024-02-01 → 2024-06-10 |

### Código que entrou em bloco

| Commit | Data | Linhas | % do total | Autor |
| --- | --- | ---: | ---: | --- |
| `d6eaee6c5a` | 2023-03-01 | 2713 | 42.8% | Marina Costa (C01) |

## Uso de IA declarado

| Ferramenta | Commits com registro | Primeiro registro | Último registro | Evidência | Arquivos |
| --- | ---: | --- | --- | --- | --- |
| Claude (Anthropic) | 2 | 2024-02-01 | 2024-06-10 | coautoria (2) | CLAUDE.md |
| Cursor | 1 | 2024-03-05 | 2024-03-05 | coautoria (1) | .cursorrules |

Política informada: Claude (Anthropic) · vigente desde 2024-01-01

## Integridade e reprodutibilidade

- Commit: `4020f76a0f07d7b32f6ad795e7725eb625d5d02f` · branch: main · remoto: —
- Alterações não commitadas no momento da varredura: 0
- Clone raso: não
- SHA-256 da ferramenta: `27e5a7668d03d613a930e5ddf40ac1ed7ea35a4ab5edda34770e2d6a483202b2`
- SHA-256 dos dados: `c0aef308ec953c93915ee64805f4bc756e8444b89541ab6ea34887ffda331ca3`
- Verificar: `python3 prove_scan.py --verificar <pasta-da-saida>`

> A verificação mostra se a saída foi alterada depois de gerada. Ela não prova que a varredura rodou sobre o repositório real: para isso, a varredura pode ser feita em sessão acompanhada ou na integração contínua do cliente.

## Limitações desta varredura

- A ferramenta **não** detecta código gerado por inteligência artificial. Não existe método confiável para isso. O que ela inventaria é o uso **declarado** (coautoria em commits, agentes, arquivos de configuração).
- Licenças são lidas conforme declaradas pelos mantenedores. Declaração incorreta do mantenedor não é detectável aqui.
- A identidade do commit reflete a configuração do Git de quem commitou, que pode não corresponder à pessoa real.
- Percentual de linhas e de commits mede volume, não autoria intelectual. Squash e rebase atribuem a autoria a quem integrou o código, não necessariamente a quem o escreveu.
- O cruzamento com contratos usa a planilha informada pelo cliente; a ferramenta não lê nem valida os contratos.
- A varredura não substitui a análise documental da cadeia de cessão, que é a prova que importa em uma transação.

## Próximo passo

Os achados indicam onde a cadeia de titularidade precisa ser verificada em documento: contrato de cessão de direitos patrimoniais de cada contribuidor, vigência à época da contribuição, política de uso de IA e compatibilidade das licenças com o modelo de distribuição do produto.

**Laudo de Proveniência**: análise documental, parecer e laudo assinado para apresentação a investidor, comprador ou contratante. danielssouza.com | (61) 98379-0033
