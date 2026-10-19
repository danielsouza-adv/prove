# Metodologia PROVE

Versão 2.0 · D'Souza Advocacia Empresarial

Este documento descreve o que o PROVE verifica, como classifica cada achado e o que cada código significa. Os códigos são estáveis entre versões: um relatório de hoje e um de daqui a um ano usam a mesma linguagem, o que permite comparar rodadas, acompanhar remediação e consolidar portfólios.

## Princípios

1. **Metadados, nunca conteúdo.** A varredura não abre arquivos de código-fonte da aplicação.
2. **Não prometer o que não existe.** Não há detecção de código gerado por IA. Há inventário do uso declarado.
3. **Distinguir limite da ferramenta de risco do cliente.** Licença que a varredura não conseguiu verificar é informativo (`LIC-NAOVERIF`), não achado contra o projeto.
4. **Gravidade depende do contexto.** A mesma GPL é crítica num software instalado e informativa numa ferramenta de desenvolvimento.
5. **O relatório indica; o documento prova.** Todo achado de autoria aponta para um documento que precisa existir.

## Semáforo

- 🔴 **Vermelho**: há ao menos um achado crítico, que tende a ser apontado em due diligence e precisa de remediação ou justificativa documental.
- 🟡 **Amarelo**: há pontos de atenção que exigem verificação documental.
- 🟢 **Verde**: nenhum indicador automático de risco. A verificação documental continua necessária.
- ⚪ **Informativo**: não altera o semáforo; registra contexto ou limites da varredura.

## Licenças de dependências

Classes, da menos para a mais restritiva: permissiva → copyleft fraco → outra/não declarada → copyleft forte → copyleft de rede → restritiva.

Expressões SPDX são avaliadas: `OR` escolhe a opção menos restritiva (o usuário pode optar), `AND` a mais restritiva (todas se aplicam) e `WITH` exceção de vinculação rebaixa GPL para copyleft fraco.

Gravidade por classe, escopo e modelo de distribuição:

| Classe | Produção, distribuído (instalado/mobile/biblioteca) | Produção, SaaS | Produção, uso interno | Escopo incerto | Desenvolvimento |
| --- | --- | --- | --- | --- | --- |
| Copyleft de rede (AGPL, SSPL) | 🔴 | 🔴 | 🟡 | 🟡 | ⚪ |
| Copyleft forte (GPL) | 🔴 | 🟡 | ⚪ | 🟡 | ⚪ |
| Restritiva (UNLICENSED, BUSL, NC…) | 🔴 | 🔴 | 🔴 | 🟡 | 🟡 |
| Copyleft fraco (LGPL, MPL, EPL) | 🟡 | ⚪ | ⚪ | 🟡 | ⚪ |
| Não declarada / outra | 🟡 | 🟡 | 🟡 | 🟡 | ⚪ |

Modelo de distribuição não informado = análise conservadora (equivale a "distribuído").

Fontes de licença, em ordem: manifesto/lockfile → pacotes instalados → SBOM importado → registro público (`--online`). "Não declarada" só é afirmado quando uma fonte confirma a ausência.

## Autoria

- Identidades são agrupadas por nome e por e-mail, respeitando `.mailmap`. Nomes genéricos (root, admin…) não agrupam.
- Robôs (dependabot, renovate, github-actions…) ficam fora da autoria.
- Agentes de IA que commitam (Copilot, Devin, Jules…) aparecem à parte: entram na política de IA, não na matriz de pessoas.
- Participação = maior valor entre % de commits e % de linhas adicionadas, desconsiderando lockfiles, código minificado e pastas de terceiros.

## Cessão

Cada commit humano é comparado com a vigência dos contratos da pessoa. Base: art. 4º da Lei 9.609/98 (programa desenvolvido na vigência de contrato cuja atividade prevê desenvolvimento pertence ao contratante, salvo estipulação em contrário). O que foi produzido fora da vigência ou sem vínculo não é alcançado pela regra.

## Códigos de achado

### Licenças e manifestos

| Código | Cor típica | Significado |
| --- | --- | --- |
| `LIC-REDE` | 🔴/🟡 | Dependência AGPL/SSPL |
| `LIC-FORTE` | 🔴/🟡 | Dependência GPL |
| `LIC-RESTRITA` | 🔴/🟡 | UNLICENSED, BUSL, Elastic, não comercial |
| `LIC-FRACO` | 🟡 | LGPL, MPL, EPL |
| `LIC-NAODECL` | 🟡 | Fonte confirma ausência de licença |
| `LIC-OUTRA` | 🟡 | Licença não reconhecida automaticamente |
| `LIC-PRIVADA` | 🟡 | Pacote não existe em registro público |
| `LIC-PROJETO` | 🟡 | O próprio projeto declara licença aberta |
| `LIC-SEMARQ` | 🟡 | Projeto sem arquivo nem declaração de licença |
| `LIC-NAOVERIF` | ⚪ | Licenças que a varredura não conseguiu verificar |
| `LIC-INTERNA` | ⚪ | Componentes internos ou de registro privado |
| `MAN-NAOANAL` | ⚪ | Manifesto encontrado e não analisado |
| `MAN-NENHUM` | ⚪ | Nenhum manifesto encontrado |

### Autoria

| Código | Cor típica | Significado |
| --- | --- | --- |
| `AUT-SEMGIT` | 🔴 | Sem repositório Git |
| `AUT-VAZIO` | 🔴 | Repositório sem commits |
| `AUT-PESSOAL` | 🔴 (≥ 20%) / 🟡 | Contribuidor com e-mail pessoal |
| `AUT-OCULTA` | 🟡 | E-mail mascarado (noreply) |
| `AUT-EXTERNO` | 🟡 | Domínio diferente do principal |
| `AUT-LOCAL` | 🟡 | Identidade sem domínio rastreável |
| `AUT-UNICO` | 🟡 | Uma só identidade humana |
| `AUT-CONCENTRACAO` | 🟡 | Uma pessoa com ≥ 60% da autoria |
| `AUT-IMPORTACAO` | 🟡 | Código que entrou em bloco |
| `AUT-RASO` | 🟡 | Clone sem histórico completo |
| `AUT-NAOCOMMIT` | ⚪ | Alterações não commitadas |

### Cessão

| Código | Cor típica | Significado |
| --- | --- | --- |
| `CES-SEMREG` | 🔴 (≥ 5%) / 🟡 | Contribuidor sem contrato |
| `CES-FORAVIG` | 🔴 (≥ 5%) / 🟡 | Commits fora da vigência |
| `CES-NAOEXPR` | 🟡 | Prestador sem cessão expressa |
| `CES-SOCIO` | 🟡 | Sócio sem cessão formalizada |
| `CES-ESTAGIO` | 🟡 | Estagiário sem cessão expressa |
| `CES-AGENCIA` | 🟡 | Agência sem cessão |
| `CES-VINCULO` | 🟡 | Vínculo não informado |
| `CES-DATAS` | 🟡 | Erro na planilha |
| `CES-CADEIA` | ⚪ | Agência com cessão: verificar cadeia do fornecedor |
| `CES-EMPREGADO` | ⚪ | Empregado sem cessão expressa (art. 4º) |
| `CES-SEMDOC` | ⚪ | Registro sem referência ao documento |
| `CES-SOBRA` | ⚪ | Contrato sem contribuidor correspondente |
| `CES-PENDENTE` | ⚪ | Cruzamento não realizado |

### Uso de IA declarado

| Código | Cor típica | Significado |
| --- | --- | --- |
| `IA-SEMPOL` | 🟡 | Uso declarado sem política informada |
| `IA-NAOAUT` | 🟡 | Ferramenta fora da política |
| `IA-ANTERIOR` | 🟡 | Uso anterior ao início da política |
| `IA-PESSOAL` | 🟡 | IA usada por identidade pessoal (plano pessoal?) |
| `IA-USO` | ⚪ | Resumo do uso declarado |
| `IA-AGENTE` | ⚪ | Commits feitos por agente de IA |
| `IA-NENHUM` | ⚪ | Nenhum registro declarado |

## Integridade

`prove_dados.json` contém o SHA-256 do próprio conteúdo canônico e o SHA-256 da ferramenta que o gerou. `prove_hashes.sha256` lista o hash de cada arquivo de saída. `--verificar` confere os dois.

Integridade não é autenticidade: a verificação prova que a saída não foi alterada depois de gerada, não que a varredura rodou sobre o repositório verdadeiro. Para o laudo, a varredura deve ser feita em sessão acompanhada ou na integração contínua do cliente, com o commit analisado registrado.
