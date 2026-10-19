# PROVE — instruções para o Claude

Ferramenta de varredura de proveniência de código do escritório D'Souza Advocacia Empresarial (Dr. Daniel de Souza, OAB/DF 71.124). Tudo em português do Brasil.

## Regras que não podem ser quebradas

- **Nunca ler conteúdo de arquivo de código-fonte da aplicação analisada.** Só manifestos, metadados de licença de terceiros, histórico do Git e nomes de arquivos. Esta é a promessa central de venda.
- **Nunca transmitir dados** do projeto. A única exceção é `--online`, opcional, que envia só nome e versão de pacotes públicos.
- **Nunca prometer detecção de código gerado por IA.** Só inventário de uso declarado.
- Arquivo único (`prove_scan.py`), só biblioteca padrão, compatível com Python 3.8. O cliente precisa conseguir auditar o script lendo um arquivo.
- E-mails completos não saem no JSON nem no relatório (só mascarados). Dados privados ficam em chaves que começam com `_` e são removidos antes de gravar.
- Os códigos de achado (`LIC-*`, `AUT-*`, `CES-*`, `IA-*`) são estáveis: não renomear; criar novos se preciso e documentar em `docs/METODOLOGIA.md`.
- Limite da ferramenta (ex.: licença não verificada) é informativo, nunca achado contra o cliente.

## Comandos

- Testes: `python3 -m unittest discover -s tests -v`
- Relatório de exemplo: `python3 exemplos/gerar_exemplo.py` (atualiza `exemplos/relatorio_exemplo.md`)

## Ao mudar algo

Adicionar teste em `tests/test_prove.py`, rodar a suíte, regenerar o exemplo e atualizar README/METODOLOGIA quando mudar comportamento visível.
