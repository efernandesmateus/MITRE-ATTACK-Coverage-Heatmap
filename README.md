# ATT&CK Coverage Heatmap

🇧🇷 Português | [🇺🇸 English](#english)

Gera uma camada (layer) do [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) a partir de uma planilha Excel de casos de uso, mostrando a **cobertura de detecção** do SOC: quais técnicas e sub-técnicas são monitoradas e por quantas regras.

A planilha é preenchida com os **nomes** das táticas e técnicas, do jeito que o analista já trabalha, sem precisar decorar IDs. O script valida tudo contra a versão mais recente do ATT&CK e, quando o MITRE muda algo, aponta a linha do Excel e sugere a correção.

<!-- Adicione aqui um print da camada aberta no Navigator: ![Exemplo](docs/exemplo.png) -->

## Funcionalidades

- **Casamento por nome**, sem diferenciar maiúsculas e ignorando espaços extras.
- **Acompanha o ATT&CK automaticamente**: consulta o índice do MITRE e usa a versão mais nova. O STIX oficial é baixado **uma única vez por versão** e fica em cache.
- **Funciona offline**: sem internet, usa a versão mais nova em cache; sem cache, usa uma planilha `enterprise-attack-v*.xlsx` local.
- **Validação completa antes de gerar**: se houver qualquer erro, nenhum JSON é gerado e todos os problemas são listados de uma vez, com o número da linha do Excel.
- **Sugestões de correção**: técnicas revogadas pelo MITRE, táticas reestruturadas, sub-técnicas que existem em outra técnica e nomes digitados com erro.
- **Valida o par tática × técnica** (impede, por exemplo, *Brute Force* em *Discovery*).
- **Score = número de regras** por técnica; as técnicas-pai exibem a soma das sub-técnicas.
- **Metadata rastreável**: cada técnica traz as fontes de dados e os nomes das regras que a cobrem.

## Requisitos

- Python 3.8+
- `pip install -r requirements.txt`

## Uso rápido

```bash
git clone https://github.com/<seu-usuario>/attack-coverage-heatmap.git
cd attack-coverage-heatmap
pip install -r requirements.txt

python gerar_mitre_json.py --mapa exemplo/casos_de_uso_exemplo.xlsx
```

Depois, no [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/): **Open Existing Layer → Upload from local** e selecione o `mitre_navigator.json` gerado.

Para ver o resultado sem rodar nada, abra `exemplo/mitre_navigator_exemplo.json` no Navigator.

## Parâmetros

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `--mapa` | `mapa_de_calor.xlsx` | Planilha de casos de uso |
| `--aba` | `Casos de Uso - Ativos` | Aba lida dentro da planilha |
| `--versao` | `latest` | Versão do ATT&CK: `latest` acompanha o MITRE; um valor fixo (ex.: `19.1`) nunca muda sozinho |
| `--offline` | — | Não acessa a internet (usa cache ou planilha local) |
| `--xlsx-referencia` | a `enterprise-attack-v*.xlsx` mais nova da pasta | Planilha de reserva, usada só sem internet e sem cache |
| `--nome` | `Cobertura de Detecção` | Nome da camada; a versão do ATT&CK é acrescentada automaticamente |
| `--saida` | `mitre_navigator.json` | Arquivo gerado |

Exemplos:

```bash
python gerar_mitre_json.py                                   # versão mais recente
python gerar_mitre_json.py --versao 19.1                     # fixa uma versão
python gerar_mitre_json.py --offline                         # sem internet
python gerar_mitre_json.py --nome "Cliente X" --saida cliente_x.json
```

## Formato da planilha

Use `exemplo/casos_de_uso_exemplo.xlsx` como modelo (a aba **Instruções** explica cada coluna).

| Data Sources | Nome da Regra | Tática | Técnica | Sub-Técnica |
|---|---|---|---|---|
| EDR | Acesso à memória do processo LSASS | Credential Access | OS Credential Dumping | LSASS Memory |
| WAF | Padrões de injeção de SQL | Initial Access | Exploit Public-Facing Application | - |

- Táticas, técnicas e sub-técnicas em **inglês**, como no site do MITRE.
- Na coluna **Sub-Técnica**, só o nome da sub-técnica (sem o da técnica-pai). Use `-` ou deixe vazio quando não houver.
- Cada linha é uma regra. Várias regras na mesma técnica aumentam o score.

## Exemplo de validação

```
Versão mais recente publicada pelo MITRE: v20.0
Referência: STIX oficial do MITRE ATT&CK v20.0 (15 táticas, 706 técnicas)

2 erro(s) encontrado(s):
 - Linha 7: Tática 'Defense Evasion' não existe nesta versão (na v19 foi dividida em 'Stealth' (TA0005) e 'Defense Impairment' (TA0112))
 - Linha 10: Sub-Técnica 'Cloud Account' não existe em 'Valid Accounts' (existe em outra técnica: Account Discovery: Cloud Account; Create Account: Cloud Account)

Corrija a planilha antes de gerar o JSON (validado contra ATT&CK v20.0).
Se a planilha ainda não foi migrada para esta versão, rode com --versao <versão anterior> para gerar o heatmap enquanto isso.
```

## Como a referência do ATT&CK é escolhida

1. Consulta o índice de versões do MITRE (arquivo pequeno, ~30 KB).
2. Usa o STIX dessa versão em cache; se ainda não existir, baixa uma vez (~55 MB) e salva como `enterprise-attack-<versão>.json`.
3. Sem internet: usa a versão mais nova em cache.
4. Sem cache: usa a planilha `enterprise-attack-v*.xlsx` mais nova da pasta. Nesse modo a validação tática × técnica fica desativada (a planilha não traz essa relação). A planilha precisa das abas `techniques` (colunas `Techniques ID` e `Techniques and Sub-techniques Names`) e `tactics` (colunas `Tatics ID` e `Tatics Name`).

Em redes com proxy, o download respeita as variáveis de ambiente `HTTPS_PROXY`/`HTTP_PROXY`.

## A camada gerada

- Gradiente de branco a vermelho, proporcional ao score.
- Técnicas-pai exibem a **soma** dos scores das sub-técnicas monitoradas (`aggregateFunction: sum`). Para mostrar a sub-técnica mais coberta, troque por `max` no script ou em *layer controls → layout* no Navigator.
- Sub-técnicas monitoradas já abrem expandidas.
- A versão do ATT&CK fica registrada no JSON e no nome da camada.

## ⚠️ Não publique seus dados reais

Nomes de regras e fontes de dados revelam a stack monitorada do ambiente, informação útil para um atacante. O `.gitignore` já ignora `mapa_de_calor.xlsx` e `mitre_navigator.json` na raiz, mas confira antes de cada commit.

## Atribuição

MITRE ATT&CK® e ATT&CK® são marcas registradas da The MITRE Corporation. Este projeto usa os dados públicos do ATT&CK conforme os [termos de uso do MITRE](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) e não é afiliado nem endossado pelo MITRE.

## Licença

[MIT](LICENSE)

---

## English

Generates a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer from an Excel spreadsheet of SOC use cases, showing **detection coverage**: which techniques and sub-techniques are monitored and by how many rules.

The spreadsheet uses technique **names** (not IDs). The script validates every row against the latest ATT&CK release, downloading the official STIX data once per version and caching it, with offline fallback to the cache or to a local `enterprise-attack-v*.xlsx`. If anything doesn't match, no JSON is produced: every problem is listed with its Excel row number and a suggested fix (revoked techniques, restructured tactics, sub-techniques that belong to another technique, typos, invalid tactic × technique pairs).

```bash
pip install -r requirements.txt
python gerar_mitre_json.py --mapa exemplo/casos_de_uso_exemplo.xlsx
```

Main options: `--versao latest|<x.y>`, `--offline`, `--nome`, `--saida`, `--aba`. Console messages and spreadsheet column headers are in Portuguese (`Data Sources`, `Nome da Regra`, `Tática`, `Técnica`, `Sub-Técnica`); tactic and technique names are in English, as on the MITRE website. See `exemplo/` for a sample spreadsheet and the resulting layer.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Licensed under [MIT](LICENSE).
