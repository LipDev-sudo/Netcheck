"""NetCheck: diagnóstico de rede (DNS, conexão TCP e certificado TLS)."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__version__ = "2.0.0"

PORTA_PADRAO = 443
TIMEOUT_PADRAO = 3.0
DIAS_AVISO_CERTIFICADO = 14

SAIDA_OK = 0
SAIDA_FALHA = 1
SAIDA_ENTRADA_INVALIDA = 2


def verificar_dns(dominio: str, silencioso: bool = False) -> str | None:
    try:
        ip = socket.gethostbyname(dominio)
        if not silencioso:
            print(f"[OK] {dominio} -> {ip}")
        return ip

    except (socket.gaierror, UnicodeError):
        if not silencioso:
            print(f"[ERRO] Não foi possível resolver {dominio}")
        return None


def verificar_tcp(
    dominio: str,
    porta: int,
    timeout: float = TIMEOUT_PADRAO,
    silencioso: bool = False,
) -> float | None:
    inicio = time.perf_counter()

    try:
        conexao = socket.create_connection((dominio, porta), timeout=timeout)

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


def medir_tcp(
    dominio: str,
    porta: int,
    timeout: float = TIMEOUT_PADRAO,
    tentativas: int = 1,
    silencioso: bool = False,
) -> dict[str, Any]:
    """Tenta conectar `tentativas` vezes e resume as latências."""
    # Com uma única tentativa mantém a saída detalhada de verificar_tcp.
    detalhar = tentativas == 1 and not silencioso
    latencias = [
        latencia
        for latencia in (
            verificar_tcp(dominio, porta, timeout, silencioso=not detalhar) for _ in range(tentativas)
        )
        if latencia is not None
    ]

    resultado: dict[str, Any] = {
        "porta": porta,
        "tentativas": tentativas,
        "sucessos": len(latencias),
        "perda_pct": round(100 * (tentativas - len(latencias)) / tentativas, 1),
        "conectividade": bool(latencias),
        "tempo_conexao_ms": None,
        "min_ms": None,
        "max_ms": None,
    }

    if latencias:
        resultado["tempo_conexao_ms"] = round(statistics.fmean(latencias), 2)
        resultado["min_ms"] = round(min(latencias), 2)
        resultado["max_ms"] = round(max(latencias), 2)

    if tentativas > 1 and not silencioso:
        if latencias:
            print(
                f"[OK] Porta {porta}: {len(latencias)}/{tentativas} conexões "
                f"(min {resultado['min_ms']:.2f} / média {resultado['tempo_conexao_ms']:.2f} "
                f"/ máx {resultado['max_ms']:.2f} ms)"
            )
        else:
            print(f"[ERRO] Porta {porta}: 0/{tentativas} conexões")

    return resultado


def verificar_tls(
    dominio: str,
    porta: int = PORTA_PADRAO,
    timeout: float = TIMEOUT_PADRAO,
    agora: datetime | None = None,
) -> dict[str, Any]:
    """Valida o certificado TLS e informa a data de expiração."""
    resultado: dict[str, Any] = {
        "porta": porta,
        "valido": False,
        "expira_em": None,
        "dias_restantes": None,
        "emissor": None,
        "erro": None,
    }

    try:
        contexto = ssl.create_default_context()
        with (
            socket.create_connection((dominio, porta), timeout=timeout) as bruto,
            contexto.wrap_socket(bruto, server_hostname=dominio) as conexao,
        ):
            certificado = conexao.getpeercert()
    except ssl.SSLCertVerificationError as erro:
        resultado["erro"] = erro.verify_message or str(erro)
        return resultado
    except (ssl.SSLError, OSError) as erro:
        resultado["erro"] = str(erro)
        return resultado

    expira = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificado["notAfter"]), tz=timezone.utc)
    dias = (expira - (agora or datetime.now(timezone.utc))).days
    emissor = dict(item[0] for item in certificado.get("issuer", ()))

    resultado.update(
        valido=dias >= 0,
        expira_em=expira.isoformat(timespec="seconds"),
        dias_restantes=dias,
        emissor=emissor.get("organizationName") or emissor.get("commonName"),
        erro=None if dias >= 0 else "Certificado expirado.",
    )
    return resultado


def validar_porta(valor: str | int) -> int:
    try:
        porta = int(valor)
    except (TypeError, ValueError):
        raise ValueError("Digite um número inteiro.") from None

    if not 1 <= porta <= 65535:
        raise ValueError("A porta deve estar entre 1 e 65535.")

    return porta


def validar_portas(valor: str) -> list[int]:
    """Converte "80,443" em [80, 443], sem repetições."""
    portas: list[int] = []

    for parte in str(valor).split(","):
        porta = validar_porta(parte.strip())
        if porta not in portas:
            portas.append(porta)

    return portas


def diagnosticar_dominio(
    dominio: str,
    portas: list[int],
    timeout: float,
    tentativas: int = 1,
    tls: bool = False,
    silencioso: bool = False,
) -> dict[str, Any]:
    ip = verificar_dns(dominio, silencioso=silencioso)
    resultado: dict[str, Any] = {
        "data_hora": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dominio": dominio,
        "ip": ip,
        "dns": ip is not None,
        "portas": [],
        "tls": None,
    }

    if ip is None:
        return resultado

    resultado["portas"] = [medir_tcp(dominio, porta, timeout, tentativas, silencioso) for porta in portas]

    if tls:
        # O TLS é verificado na 443, se estiver na lista; senão, na primeira porta.
        resultado["tls"] = verificar_tls(
            dominio, PORTA_PADRAO if PORTA_PADRAO in portas else portas[0], timeout
        )

    return resultado


def dominio_ok(resultado: dict[str, Any]) -> bool:
    """O domínio está saudável se resolve, conecta em todas as portas e o TLS (se pedido) é válido."""
    if not resultado["dns"]:
        return False

    if not all(porta["conectividade"] for porta in resultado["portas"]):
        return False

    return resultado["tls"] is None or resultado["tls"]["valido"]


def formatar_relatorio(resultado: dict[str, Any]) -> str:
    linhas = [
        "========== RELATORIO NETCHECK ==========",
        f"Data e hora: {resultado['data_hora']}",
        f"Dominio: {resultado['dominio']}",
        f"Endereco IP: {resultado['ip'] or 'N/D'}",
        f"DNS: {'OK' if resultado['dns'] else 'FALHOU'}",
    ]

    if not resultado["dns"]:
        linhas.append("Conectividade: NAO TESTADA")

    for porta in resultado["portas"]:
        linhas.append(f"Porta TCP: {porta['porta']}")

        if porta["conectividade"]:
            linhas.append("Conectividade: OK")
            linhas.append(f"Tempo de conexao: {porta['tempo_conexao_ms']:.2f} ms")
            if porta["tentativas"] > 1:
                linhas.append(
                    f"Tentativas: {porta['sucessos']}/{porta['tentativas']} "
                    f"(min {porta['min_ms']:.2f} / max {porta['max_ms']:.2f} ms, "
                    f"perda {porta['perda_pct']:g}%)"
                )
        else:
            linhas.append("Conectividade: FALHOU")

    tls = resultado.get("tls")
    if tls is not None:
        if tls["valido"]:
            aviso = " (EXPIRA EM BREVE)" if tls["dias_restantes"] < DIAS_AVISO_CERTIFICADO else ""
            linhas.append(
                f"TLS: OK, expira em {tls['dias_restantes']} dias{aviso} "
                f"({tls['expira_em']}); emissor: {tls['emissor'] or 'N/D'}"
            )
        else:
            linhas.append(f"TLS: FALHOU ({tls['erro']})")

    linhas.append("========================================")
    return "\n".join(linhas)


def salvar_relatorio(conteudo: str, pasta: str | Path = "reports", silencioso: bool = False) -> Path:
    pasta = Path(pasta)
    pasta.mkdir(parents=True, exist_ok=True)

    agora = datetime.now().strftime("%Y%m%d_%H%M%S")
    arquivo = pasta / f"netcheck_{agora}.txt"
    contador = 1

    # Evita sobrescrever relatórios gerados no mesmo segundo.
    while arquivo.exists():
        arquivo = pasta / f"netcheck_{agora}_{contador}.txt"
        contador += 1

    arquivo.write_text(conteudo, encoding="utf-8")

    if not silencioso:
        print(f"\n[OK] Relatório salvo em: {arquivo}")

    return arquivo


def diagnosticar(
    dominios: list[str],
    portas: list[int],
    timeout: float,
    tentativas: int = 1,
    tls: bool = False,
    formato_json: bool = False,
    salvar: bool = True,
    pasta: str | Path = "reports",
) -> int:
    """Executa o diagnóstico de cada domínio e devolve o código de saída."""
    resultados = [
        diagnosticar_dominio(d, portas, timeout, tentativas, tls, silencioso=formato_json) for d in dominios
    ]

    if formato_json:
        conteudo = json.dumps({"resultados": resultados}, ensure_ascii=False, indent=2)
        print(conteudo)
    else:
        conteudo = "\n\n".join(formatar_relatorio(r) for r in resultados)
        print("\n" + conteudo)

    if salvar:
        salvar_relatorio(conteudo, pasta, silencioso=formato_json)

    return SAIDA_OK if all(dominio_ok(r) for r in resultados) else SAIDA_FALHA


def ler_entrada_interativa() -> tuple[list[str], list[int]]:
    print("NetCheck - Diagnóstico de Redes")
    print("-" * 35)

    dominio = input("Digite um domínio: ").strip()

    if not dominio:
        raise ValueError("O domínio não pode estar vazio.")

    entrada_porta = input(f"Digite a(s) porta(s) TCP, separadas por vírgula ({PORTA_PADRAO}): ").strip()
    portas = validar_portas(entrada_porta) if entrada_porta else [PORTA_PADRAO]

    return [dominio], portas


def _tipo_portas(valor: str) -> list[int]:
    try:
        return validar_portas(valor)
    except ValueError as erro:
        raise argparse.ArgumentTypeError(str(erro)) from None


def criar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netcheck",
        description="Diagnóstico de rede: resolução DNS, conexão TCP e certificado TLS.",
        epilog="Sem argumentos, o programa pergunta o domínio e a(s) porta(s).",
    )
    parser.add_argument(
        "dominios", nargs="*", metavar="dominio", help="um ou mais domínios, por exemplo example.com"
    )
    parser.add_argument(
        "-p",
        "--porta",
        dest="portas",
        type=_tipo_portas,
        default=None,
        metavar="PORTAS",
        help=f"porta TCP ou lista separada por vírgula, como 80,443 (padrão: {PORTA_PADRAO})",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=TIMEOUT_PADRAO,
        help=f"tempo limite da conexão em segundos (padrão: {TIMEOUT_PADRAO:g})",
    )
    parser.add_argument(
        "-n",
        "--tentativas",
        type=int,
        default=1,
        help="número de conexões por porta, para medir mínimo, média, máximo e perda (padrão: 1)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help=f"valida o certificado TLS (na porta {PORTA_PADRAO}, se listada; senão, na primeira)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="formato_json", help="imprime o resultado em JSON"
    )
    parser.add_argument("--sem-relatorio", action="store_true", help="não salva o arquivo de relatório")
    parser.add_argument("-o", "--pasta", default="reports", help="pasta dos relatórios (padrão: reports)")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = criar_parser()
    args = parser.parse_args(argv)

    try:
        if not args.dominios:
            dominios, portas = ler_entrada_interativa()
        else:
            dominios = [d.strip() for d in args.dominios]
            if not all(dominios):
                raise ValueError("O domínio não pode estar vazio.")
            portas = args.portas or [PORTA_PADRAO]

        if args.timeout <= 0:
            raise ValueError("O timeout deve ser maior que zero.")

        if not 1 <= args.tentativas <= 100:
            raise ValueError("As tentativas devem estar entre 1 e 100.")

    except ValueError as erro:
        print(f"[ERRO] {erro}", file=sys.stderr)
        return SAIDA_ENTRADA_INVALIDA
    except (KeyboardInterrupt, EOFError):
        print("\n[ERRO] Operação cancelada.", file=sys.stderr)
        return SAIDA_ENTRADA_INVALIDA

    return diagnosticar(
        dominios,
        portas,
        args.timeout,
        args.tentativas,
        args.tls,
        formato_json=args.formato_json,
        salvar=not args.sem_relatorio,
        pasta=args.pasta,
    )


if __name__ == "__main__":
    sys.exit(main())
