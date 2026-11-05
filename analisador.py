import argparse
import re
from collections import Counter, defaultdict

PADRAO_FALHA = re.compile(
    r"^(?P<mes>\w{3})\s+(?P<dia>\d+)\s+(?P<hora>\d{2}):\d{2}:\d{2}.*"
    r"Failed password for (?:invalid user )?(?P<usuario>\S+) "
    r"from (?P<ip>[\d.]+)"
)
PADRAO_SUCESSO = re.compile(
    r"Accepted (?:password|publickey) for (?P<usuario>\S+) from (?P<ip>[\d.]+)"
)

LIMITE_FORCA_BRUTA = 5          # falhas por IP para considerar suspeito
HORARIO_SUSPEITO = range(0, 6)  # de 00h às 05h


def analisar(caminho: str) -> dict:
    falhas_por_ip = Counter()
    falhas_por_usuario = Counter()
    falhas_por_hora = Counter()
    sucessos = defaultdict(set)  # ip -> usuários que logaram com sucesso

    with open(caminho, encoding="utf-8", errors="ignore") as arquivo:
        for linha in arquivo:
            falha = PADRAO_FALHA.search(linha)
            if falha:
                falhas_por_ip[falha["ip"]] += 1
                falhas_por_usuario[falha["usuario"]] += 1
                falhas_por_hora[int(falha["hora"])] += 1
                continue

            sucesso = PADRAO_SUCESSO.search(linha)
            if sucesso:
                sucessos[sucesso["ip"]].add(sucesso["usuario"])

    return {
        "falhas_por_ip": falhas_por_ip,
        "falhas_por_usuario": falhas_por_usuario,
        "falhas_por_hora": falhas_por_hora,
        "sucessos": sucessos,
    }


def gerar_relatorio(dados: dict) -> str:
    linhas = ["=== RELATÓRIO DE ANÁLISE DE LOG SSH ===\n"]

    total = sum(dados["falhas_por_ip"].values())
    linhas.append(f"Total de tentativas falhas: {total}\n")

    linhas.append("Top 5 IPs com mais falhas:")
    for ip, qtd in dados["falhas_por_ip"].most_common(5):
        linhas.append(f"  {ip}: {qtd}")

    linhas.append("\nUsuários mais visados:")
    for usuario, qtd in dados["falhas_por_usuario"].most_common(5):
        linhas.append(f"  {usuario}: {qtd}")

    linhas.append("\nPossíveis ataques de força bruta:")
    suspeitos = [
        (ip, qtd) for ip, qtd in dados["falhas_por_ip"].items()
        if qtd >= LIMITE_FORCA_BRUTA
    ]
    if suspeitos:
        for ip, qtd in sorted(suspeitos, key=lambda x: -x[1]):
            alerta = "  [ALERTA: houve login bem-sucedido depois!]" \
                if ip in dados["sucessos"] else ""
            linhas.append(f"  {ip}: {qtd} falhas{alerta}")
    else:
        linhas.append("  Nenhum IP acima do limite.")

    madrugada = sum(
        qtd for hora, qtd in dados["falhas_por_hora"].items()
        if hora in HORARIO_SUSPEITO
    )
    linhas.append(f"\nFalhas em horário suspeito (00h-05h): {madrugada}")

    return "\n".join(linhas)


def main():
    parser = argparse.ArgumentParser(description="Analisador de logs SSH")
    parser.add_argument("arquivo", help="Caminho do auth.log")
    parser.add_argument("-o", "--saida", help="Salvar relatório em arquivo")
    args = parser.parse_args()

    relatorio = gerar_relatorio(analisar(args.arquivo))
    print(relatorio)

    if args.saida:
        with open(args.saida, "w", encoding="utf-8") as f:
            f.write(relatorio)
        print(f"\nRelatório salvo em {args.saida}")


if __name__ == "__main__":
    main()