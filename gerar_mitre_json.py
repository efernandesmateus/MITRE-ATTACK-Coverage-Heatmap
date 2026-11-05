"""
Gera uma camada (layer) do MITRE ATT&CK Navigator a partir da planilha de casos de uso.

Por padrão acompanha a versão mais recente do ATT&CK:
  1. Consulta o índice do MITRE (arquivo pequeno) para saber qual é a versão atual
  2. Usa o STIX dessa versão em cache; se ainda não existir, baixa uma única vez e guarda
  3. Sem internet: usa a versão mais nova que estiver em cache
  4. Sem cache: usa a planilha enterprise-attack-v*.xlsx mais nova da pasta
     (sem validação de tática x técnica)

Uso:
  python gerar_mitre_json.py
  python gerar_mitre_json.py --versao 19.1        (fixa uma versão)
  python gerar_mitre_json.py --offline
  python gerar_mitre_json.py --mapa outra_planilha.xlsx --saida camada.json
"""

import argparse
import difflib
import json
import re
import sys
import urllib.request
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
REPO = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
STIX_URL = REPO + "/enterprise-attack/enterprise-attack-{versao}.json"
INDEX_URL = REPO + "/index.json"

# Táticas que mudaram de nome/estrutura, só para sugerir a correção na mensagem de erro
TATICAS_ALTERADAS = {
    "defense-evasion": "na v19 foi dividida em 'Stealth' (TA0005) e 'Defense Impairment' (TA0112)",
}


# --------------------------------------------------------------------------- utilidades

def normalizar(texto):
    """Minúsculas, sem espaços extras (inclui espaço não separável). Vazio/NaN vira ''."""
    if texto is None or (isinstance(texto, float) and pd.isna(texto)):
        return ""
    texto = str(texto).replace("\u00a0", " ")
    texto = re.sub(r"\s+", " ", texto).strip().lower()
    return "" if texto in ("-", "nan") else texto


def shortname_tatica(texto):
    return normalizar(texto).replace(" ", "-")


def parecidos(valor, opcoes, n=3):
    return difflib.get_close_matches(valor, list(opcoes), n=n, cutoff=0.75)


# --------------------------------------------------------------------------- referência

class Referencia:
    """Estrutura comum às duas fontes (STIX e xlsx)."""

    def __init__(self, origem):
        self.origem = origem
        self.taticas = {}            # shortname -> (ID, nome)
        self.tecnicas = {}           # ID -> {"nome", "pai", "taticas" (set ou None)}
        self.pai_por_nome = {}       # nome técnica -> ID
        self.subs_por_pai = {}       # ID pai -> {nome sub -> ID}
        self.revogadas = {}          # nome técnica ou (nome pai, nome sub) -> texto de substituição
        self.valida_pares = False    # se sabemos quais táticas cada técnica tem

    def nome_completo(self, tid):
        t = self.tecnicas[tid]
        if t["pai"]:
            return f'{self.tecnicas[t["pai"]]["nome"]}: {t["nome"]}'
        return t["nome"]

    def _indexar(self):
        for tid, t in self.tecnicas.items():
            if t["pai"]:
                self.subs_por_pai.setdefault(t["pai"], {})[normalizar(t["nome"])] = tid
            else:
                self.pai_por_nome[normalizar(t["nome"])] = tid


def carregar_stix(dados, versao):
    ref = Referencia(f"STIX oficial do MITRE ATT&CK v{versao}")
    ref.valida_pares = True
    objetos = dados["objects"]

    def ext_id(o):
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                return r.get("external_id")
        return None

    inativo = lambda o: o.get("revoked") or o.get("x_mitre_deprecated")

    por_stix_id = {}
    for o in objetos:
        if o["type"] == "x-mitre-tactic" and not inativo(o):
            ref.taticas[o["x_mitre_shortname"]] = (ext_id(o), o["name"])
        elif o["type"] == "attack-pattern":
            por_stix_id[o["id"]] = o
            if inativo(o):
                continue
            tid = ext_id(o)
            ref.tecnicas[tid] = {
                "nome": o["name"],
                "pai": tid.split(".")[0] if "." in tid else None,
                "taticas": {k["phase_name"] for k in o.get("kill_chain_phases", [])
                            if k.get("kill_chain_name") == "mitre-attack"},
            }
    ref._indexar()

    # Técnicas revogadas -> sugestão de substituta (ajuda muito na troca de versão)
    nomes_antigos = {}
    for o in por_stix_id.values():
        tid = ext_id(o)
        if tid and "." not in tid:
            nomes_antigos[tid] = o["name"]
    for r in objetos:
        if r["type"] != "relationship" or r["relationship_type"] != "revoked-by":
            continue
        antiga, nova = por_stix_id.get(r["source_ref"]), por_stix_id.get(r["target_ref"])
        if not antiga or not nova:
            continue
        id_antigo, id_novo = ext_id(antiga), ext_id(nova)
        if id_novo not in ref.tecnicas:
            continue
        texto = f"{id_antigo} foi substituída por {id_novo} '{ref.nome_completo(id_novo)}'"
        if "." in id_antigo:
            pai_antigo = nomes_antigos.get(id_antigo.split(".")[0], "")
            ref.revogadas[(normalizar(pai_antigo), normalizar(antiga["name"]))] = texto
        else:
            ref.revogadas[normalizar(antiga["name"])] = texto
    return ref


def carregar_xlsx(caminho):
    ref = Referencia(f"planilha local {caminho.name}")
    tec_df = pd.read_excel(caminho, sheet_name="techniques", engine="openpyxl")
    tat_df = pd.read_excel(caminho, sheet_name="tactics", engine="openpyxl")
    for _, row in tat_df.iterrows():
        ref.taticas[shortname_tatica(row["Tatics Name"])] = (str(row["Tatics ID"]).strip(),
                                                             str(row["Tatics Name"]).strip())
    for _, row in tec_df.iterrows():
        tid = str(row["Techniques ID"]).strip()
        nome = str(row["Techniques and Sub-techniques Names"]).strip()
        if "." in tid and ":" in nome:
            nome = nome.split(":", 1)[1].strip()
        ref.tecnicas[tid] = {"nome": nome,
                             "pai": tid.split(".")[0] if "." in tid else None,
                             "taticas": None}
    ref._indexar()
    return ref


def chave_versao(v):
    return tuple(int(p) for p in re.findall(r"\d+", v))


def versao_mais_recente_online():
    """Consulta o índice do MITRE (arquivo pequeno) e devolve a versão mais nova do Enterprise."""
    with urllib.request.urlopen(INDEX_URL, timeout=30) as resp:
        indice = json.load(resp)
    for colecao in indice["collections"]:
        if colecao["name"] == "Enterprise ATT&CK":
            return max((v["version"] for v in colecao["versions"]), key=chave_versao)
    raise ValueError("coleção Enterprise ATT&CK não encontrada no índice")


def versoes_em_cache(pasta):
    achadas = []
    for arq in pasta.glob("enterprise-attack-*.json"):
        m = re.fullmatch(r"enterprise-attack-(\d+(?:\.\d+)*)\.json", arq.name)
        if m:
            achadas.append(m.group(1))
    return sorted(achadas, key=chave_versao, reverse=True)


def ler_cache(pasta, versao):
    cache = pasta / f"enterprise-attack-{versao}.json"
    try:
        with open(cache, encoding="utf-8") as f:
            return carregar_stix(json.load(f), versao)
    except (OSError, json.JSONDecodeError, KeyError) as e:
        print(f"[aviso] Cache {cache.name} inválido ({e}).")
        return None


def baixar(pasta, versao):
    cache = pasta / f"enterprise-attack-{versao}.json"
    url = STIX_URL.format(versao=versao)
    print(f"Baixando ATT&CK v{versao} do MITRE (uma única vez por versão) ...")
    with urllib.request.urlopen(url, timeout=180) as resp:
        bruto = resp.read()
    dados = json.loads(bruto)
    temporario = cache.with_suffix(".tmp")
    temporario.write_bytes(bruto)
    temporario.replace(cache)          # só vira cache se o download terminou inteiro
    print(f"Referência salva em cache: {cache.name}")
    return carregar_stix(dados, versao)


def obter_referencia(versao, offline, xlsx_local, pasta_cache):
    """Retorna (referência, versão usada).

    versao == "latest": usa a versão mais nova publicada pelo MITRE; sem internet,
    usa a mais nova que estiver em cache. Uma versão fixa (ex.: "19.1") nunca muda sozinha.
    """
    if versao == "latest":
        alvo = None
        if not offline:
            try:
                alvo = versao_mais_recente_online()
                print(f"Versão mais recente publicada pelo MITRE: v{alvo}")
            except Exception as e:
                print(f"[aviso] Não foi possível consultar a versão atual no MITRE ({e}).")
        if alvo is None:
            em_cache = versoes_em_cache(pasta_cache)
            if em_cache:
                alvo = em_cache[0]
                print(f"[aviso] Sem acesso ao MITRE: usando a versão mais nova em cache (v{alvo}).")
    else:
        alvo = versao

    if alvo:
        if (pasta_cache / f"enterprise-attack-{alvo}.json").exists():
            ref = ler_cache(pasta_cache, alvo)
            if ref:
                return ref, alvo
        if not offline:
            try:
                return baixar(pasta_cache, alvo), alvo
            except Exception as e:
                print(f"[aviso] Não foi possível baixar a v{alvo} ({e}).")

    # Último recurso: planilha local
    candidatos = [xlsx_local] if xlsx_local else sorted(
        pasta_cache.glob("enterprise-attack-v*.xlsx"), key=lambda p: chave_versao(p.stem), reverse=True)
    for xlsx in candidatos:
        if xlsx.exists():
            m = re.search(r"v(\d+(?:[._]\d+)*)", xlsx.stem)
            v = m.group(1).replace("_", ".") if m else (alvo or "?")
            print(f"[aviso] Usando a planilha local {xlsx.name}: "
                  "a validação de tática x técnica fica desativada.")
            return carregar_xlsx(xlsx), v

    sys.exit("Nenhuma referência disponível: sem internet, sem cache JSON e sem planilha "
             "enterprise-attack-v*.xlsx na pasta do script.")


# --------------------------------------------------------------------------- validação

def validar_linha(row, ref):
    """Retorna (lista de erros, tática, ID da técnica). Coleta todos os erros da linha."""
    erros = []
    tatica = shortname_tatica(row["Tática"])
    tecnica = normalizar(row["Técnica"])
    sub = normalizar(row["Sub-Técnica"])

    # Tática
    if not tatica:
        erros.append("Tática vazia.")
    elif tatica not in ref.taticas:
        dica = TATICAS_ALTERADAS.get(tatica)
        if not dica:
            sug = parecidos(tatica, ref.taticas)
            dica = f"você quis dizer: {', '.join(ref.taticas[s][1] for s in sug)}?" if sug else ""
        erros.append(f"Tática '{row['Tática']}' não existe nesta versão" + (f" ({dica})" if dica else "."))

    # Técnica
    id_pai = ref.pai_por_nome.get(tecnica)
    if not tecnica:
        erros.append("Técnica vazia.")
    elif not id_pai:
        dica = ref.revogadas.get(tecnica)
        if not dica:
            sug = parecidos(tecnica, ref.pai_por_nome)
            dica = f"você quis dizer: {', '.join(ref.tecnicas[ref.pai_por_nome[s]]['nome'] for s in sug)}?" if sug else ""
        erros.append(f"Técnica '{row['Técnica']}' não existe nesta versão" + (f" ({dica})" if dica else "."))

    # Sub-técnica (sempre procurada dentro da técnica informada, nunca em outra)
    tid = id_pai
    if sub and id_pai:
        subs = ref.subs_por_pai.get(id_pai, {})
        tid = subs.get(sub)
        if not tid:
            dica = ref.revogadas.get((tecnica, sub))
            if not dica:
                outras = [ref.nome_completo(s[sub]) for p, s in ref.subs_por_pai.items()
                          if p != id_pai and sub in s]
                if outras:
                    dica = "existe em outra técnica: " + "; ".join(outras)
                else:
                    sug = parecidos(sub, subs)
                    dica = f"você quis dizer: {', '.join(ref.tecnicas[subs[s]]['nome'] for s in sug)}?" if sug else ""
            erros.append(f"Sub-Técnica '{row['Sub-Técnica']}' não existe em '{row['Técnica']}'"
                         + (f" ({dica})" if dica else "."))

    # Par tática x técnica
    if not erros and ref.valida_pares:
        taticas_validas = ref.tecnicas[tid]["taticas"]
        if tatica not in taticas_validas:
            nomes = ", ".join(sorted(ref.taticas[t][1] for t in taticas_validas if t in ref.taticas))
            erros.append(f"'{ref.nome_completo(tid)}' ({tid}) não pertence à tática "
                         f"'{row['Tática']}'. Táticas válidas: {nomes}.")

    return erros, tatica, tid


# --------------------------------------------------------------------------- principal

def main():
    p = argparse.ArgumentParser(description="Gera camada do MITRE ATT&CK Navigator a partir dos casos de uso.")
    p.add_argument("--mapa", default=BASE_DIR / "mapa_de_calor.xlsx", type=Path)
    p.add_argument("--aba", default="Casos de Uso - Ativos")
    p.add_argument("--versao", default="latest",
                   help="versão do ATT&CK: 'latest' (padrão, acompanha o MITRE) ou fixa, ex.: 19.1")
    p.add_argument("--xlsx-referencia", type=Path, default=None,
                   help="planilha local de reserva (padrão: a enterprise-attack-v*.xlsx mais nova da pasta)")
    p.add_argument("--saida", default=BASE_DIR / "mitre_navigator.json", type=Path)
    p.add_argument("--offline", action="store_true", help="não tenta acessar a internet")
    p.add_argument("--nome", default="Cobertura de Detecção",
                   help="nome da camada no Navigator; a versão do ATT&CK é acrescentada automaticamente")
    args = p.parse_args()

    ref, versao = obter_referencia(args.versao, args.offline, args.xlsx_referencia, BASE_DIR)
    print(f"Referência: {ref.origem} ({len(ref.taticas)} táticas, {len(ref.tecnicas)} técnicas)")

    mapa_df = pd.read_excel(args.mapa, sheet_name=args.aba, engine="openpyxl")
    mapa_df = mapa_df.dropna(how="all")

    agregado = {}
    erros = []
    for idx, row in mapa_df.iterrows():
        linha_excel = idx + 2  # +1 do índice zero, +1 do cabeçalho
        erros_linha, tatica, tid = validar_linha(row, ref)
        if erros_linha:
            erros.extend(f"Linha {linha_excel}: {e}" for e in erros_linha)
            continue
        item = agregado.setdefault((tid, tatica), {"score": 0, "fontes": set(), "regras": set()})
        item["score"] += 1
        fonte, regra = str(row["Data Sources"]).strip(), str(row["Nome da Regra"]).strip()
        if normalizar(fonte):
            item["fontes"].add(fonte)
        if normalizar(regra):
            item["regras"].add(regra)

    if erros:
        print(f"\n{len(erros)} erro(s) encontrado(s):")
        for e in erros:
            print(" -", e)
        print(f"\nCorrija a planilha antes de gerar o JSON (validado contra ATT&CK v{versao}).")
        if args.versao == "latest":
            print("Se a planilha ainda não foi migrada para esta versão, rode com "
                  "--versao <versão anterior> para gerar o heatmap enquanto isso.")
        sys.exit(1)

    tecnicas = []
    pais_com_sub = set()
    for (tid, tatica), info in sorted(agregado.items()):
        metadata = ([{"name": "Data Source", "value": f} for f in sorted(info["fontes"])]
                    + [{"name": "Nome da Regra", "value": r} for r in sorted(info["regras"])])
        tecnicas.append({"techniqueID": tid, "tactic": tatica, "score": info["score"],
                         "metadata": metadata, "enabled": True})
        if "." in tid:
            pais_com_sub.add((tid.split(".")[0], tatica))

    # Deixa as sub-técnicas monitoradas já expandidas no Navigator
    for t in tecnicas:
        if (t["techniqueID"], t["tactic"]) in pais_com_sub:
            t["showSubtechniques"] = True
            pais_com_sub.discard((t["techniqueID"], t["tactic"]))
    for pai, tatica in sorted(pais_com_sub):
        tecnicas.append({"techniqueID": pai, "tactic": tatica, "showSubtechniques": True, "enabled": True})

    # Escala do gradiente: considera também a soma das sub-técnicas exibida nas técnicas-pai
    soma_por_pai = {}
    for (tid, tatica), info in agregado.items():
        chave = (tid.split(".")[0], tatica)
        soma_por_pai[chave] = soma_por_pai.get(chave, 0) + info["score"]
    max_score = max(list(soma_por_pai.values()) + [t.get("score", 0) for t in tecnicas], default=0)
    camada = {
        "name": f"{args.nome} - ATT&CK v{versao}",
        "versions": {"attack": versao.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Casos de uso validados contra ATT&CK v{versao} ({ref.origem})",
        "techniques": tecnicas,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": max_score},
        "legendItems": [{"label": "Monitorado", "color": "#ff6666"}],
        # Técnica-pai exibe a soma dos scores das sub-técnicas monitoradas
        "layout": {"layout": "side", "aggregateFunction": "sum",
                   "showAggregateScores": True, "countUnscored": False},
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "sorting": 0,
    }
    with open(args.saida, "w", encoding="utf-8") as f:
        json.dump(camada, f, indent=4, ensure_ascii=False)
    print(f"\nArquivo {args.saida.name} gerado com sucesso! "
          f"({len(agregado)} técnica(s), max score = {max_score})")


if __name__ == "__main__":
    main()
