import argparse
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

PORTA_PADRAO = 443
TIMEOUT_PADRAO = 3.0

SAIDA_OK = 0
SAIDA_FALHA = 1
SAIDA_ENTRADA_INVALIDA = 2


def verificar_dns(dominio, silencioso=False):
    try:
        ip = socket.gethostbyname(dominio)
        if not silencioso:
            print(f"[OK] {dominio} -> {ip}")
        return ip

    except socket.gaierror:
        if not silencioso:
            print(f"[ERRO] Não foi possível resolver {dominio}")
        return None


def verificar_tcp(dominio, porta, timeout=TIMEOUT_PADRAO, silencioso=False):
    inicio = time.perf_counter()

    try:
        conexao = socket.create_connection(
            (dominio, porta),
            timeout=timeout
        )

        fim = time.perf_counter()
        conexao.close()

        latencia = (fim - inicio) * 1000

        if not silencioso:
            print(f"[OK] Porta {porta} acessível em {dominio}")
            print(f"[INFO] Tempo de conexão: {latencia:.2f} ms")

        return latencia

    except OSError as erro:
        if not silencioso:
            print(f"[ERRO] Falha na porta {porta}: {erro}")
        return None


def validar_porta(valor):
    try:
        porta = int(valor)
    except (TypeError, ValueError):
        raise ValueError("Digite um número inteiro.")

    if not 1 <= porta <= 65535:
        raise ValueError("A porta deve estar entre 1 e 65535.")

    return porta


def montar_resultado(dominio, ip, porta, latencia):
    return {
        "data_hora": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dominio": dominio,
        "ip": ip,
        "dns": ip is not None,
        "porta": porta,
        "conectividade": latencia is not None,
        "tempo_conexao_ms": None if latencia is None else round(latencia, 2),
    }


def formatar_relatorio(resultado):
    linhas = [
        "========== RELATORIO NETCHECK ==========",
        f"Data e hora: {resultado['data_hora']}",
        f"Dominio: {resultado['dominio']}",
        f"Endereco IP: {resultado['ip'] or 'N/D'}",
        f"DNS: {'OK' if resultado['dns'] else 'FALHOU'}",
        f"Porta TCP: {resultado['porta']}",
    ]

    if resultado["conectividade"]:
        linhas.append("Conectividade: OK")
        linhas.append(f"Tempo de conexao: {resultado['tempo_conexao_ms']:.2f} ms")
    elif resultado["dns"]:
        linhas.append("Conectividade: FALHOU")
    else:
        linhas.append("Conectividade: NAO TESTADA")

    linhas.append("========================================")
    return "\n".join(linhas)


def salvar_relatorio(conteudo, pasta="reports", silencioso=False):
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)

    agora = datetime.now().strftime("%Y%m%d_%H%M%S")
    arquivo = pasta / f"netcheck_{agora}.txt"

    arquivo.write_text(conteudo, encoding="utf-8")

    if not silencioso:
        print(f"\n[OK] Relatório salvo em: {arquivo}")

    return arquivo


def diagnosticar(dominio, porta, timeout, formato_json=False, salvar=True, pasta="reports"):
    """Executa o diagnóstico e devolve o código de saída."""
    ip = verificar_dns(dominio, silencioso=formato_json)
    latencia = None

    if ip is not None:
        latencia = verificar_tcp(dominio, porta, timeout, silencioso=formato_json)

    resultado = montar_resultado(dominio, ip, porta, latencia)

    if formato_json:
        print(json.dumps(resultado, ensure_ascii=False, indent=2))
    else:
        print("\n" + formatar_relatorio(resultado))

    if salvar:
        conteudo = (
            json.dumps(resultado, ensure_ascii=False, indent=2)
            if formato_json
            else formatar_relatorio(resultado)
        )
        salvar_relatorio(conteudo, pasta, silencioso=formato_json)

    return SAIDA_OK if resultado["conectividade"] else SAIDA_FALHA


def ler_entrada_interativa():
    print("NetCheck - Diagnóstico de Redes")
    print("-" * 35)

    dominio = input("Digite um domínio: ").strip()

    if not dominio:
        raise ValueError("O domínio não pode estar vazio.")

    entrada_porta = input(f"Digite a porta TCP ({PORTA_PADRAO}): ").strip()
    porta = validar_porta(entrada_porta) if entrada_porta else PORTA_PADRAO

    return dominio, porta


def criar_parser():
    parser = argparse.ArgumentParser(
        prog="netcheck",
        description="Diagnóstico de rede: resolução DNS e conexão TCP de um domínio.",
        epilog="Sem argumentos, o programa pergunta o domínio e a porta.",
    )
    parser.add_argument("dominio", nargs="?", help="domínio a testar, por exemplo example.com")
    parser.add_argument(
        "-p", "--porta", type=int, default=None,
        help=f"porta TCP (padrão: {PORTA_PADRAO})",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=TIMEOUT_PADRAO,
        help=f"tempo limite da conexão em segundos (padrão: {TIMEOUT_PADRAO:g})",
    )
    parser.add_argument("--json", action="store_true", dest="formato_json", help="imprime o resultado em JSON")
    parser.add_argument("--sem-relatorio", action="store_true", help="não salva o arquivo de relatório")
    parser.add_argument("-o", "--pasta", default="reports", help="pasta dos relatórios (padrão: reports)")
    return parser


def main(argv=None):
    parser = criar_parser()
    args = parser.parse_args(argv)

    try:
        if args.dominio is None:
            dominio, porta = ler_entrada_interativa()
        else:
            dominio = args.dominio.strip()
            if not dominio:
                raise ValueError("O domínio não pode estar vazio.")
            porta = validar_porta(args.porta) if args.porta is not None else PORTA_PADRAO

        if args.timeout <= 0:
            raise ValueError("O timeout deve ser maior que zero.")

    except ValueError as erro:
        print(f"[ERRO] {erro}", file=sys.stderr)
        return SAIDA_ENTRADA_INVALIDA
    except (KeyboardInterrupt, EOFError):
        print("\n[ERRO] Operação cancelada.", file=sys.stderr)
        return SAIDA_ENTRADA_INVALIDA

    return diagnosticar(
        dominio, porta, args.timeout,
        formato_json=args.formato_json,
        salvar=not args.sem_relatorio,
        pasta=args.pasta,
    )


if __name__ == "__main__":
    sys.exit(main())
