import socket
import time
from datetime import datetime
from pathlib import Path


def verificar_dns(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        print(f"[OK] {dominio} -> {ip}")
        return ip

    except socket.gaierror:
        print(f"[ERRO] Não foi possível resolver {dominio}")
        return None


def verificar_tcp(dominio, porta):
    inicio = time.perf_counter()

    try:
        conexao = socket.create_connection(
            (dominio, porta),
            timeout=3
        )

        fim = time.perf_counter()
        conexao.close()

        latencia = (fim - inicio) * 1000

        print(f"[OK] Porta {porta} acessível em {dominio}")
        print(f"[INFO] Tempo de conexão: {latencia:.2f} ms")

        return latencia

    except OSError as erro:
        print(f"[ERRO] Falha na porta {porta}: {erro}")
        return None


def salvar_relatorio(conteudo):
    pasta = Path("reports")
    pasta.mkdir(exist_ok=True)

    agora = datetime.now().strftime("%Y%m%d_%H%M%S")
    arquivo = pasta / f"netcheck_{agora}.txt"

    arquivo.write_text(conteudo, encoding="utf-8")

    print(f"\n[OK] Relatório salvo em: {arquivo}")


def main():
    print("NetCheck - Diagnóstico de Redes")
    print("-" * 35)

    dominio = input("Digite um domínio: ").strip()

    if not dominio:
        print("[ERRO] O domínio não pode estar vazio.")
        return

    ip = verificar_dns(dominio)

    if ip is None:
        return

    entrada_porta = input("Digite a porta TCP (443): ").strip()

    if not entrada_porta:
        porta = 443
    else:
        try:
            porta = int(entrada_porta)
        except ValueError:
            print("[ERRO] Digite um número inteiro.")
            return

    if not 1 <= porta <= 65535:
        print("[ERRO] A porta deve estar entre 1 e 65535.")
        return

    latencia = verificar_tcp(dominio, porta)

    linhas = [
        "========== RELATORIO NETCHECK ==========",
        f"Data e hora: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Dominio: {dominio}",
        f"Endereco IP: {ip}",
        "DNS: OK",
        f"Porta TCP: {porta}",
    ]

    if latencia is not None:
        linhas.append("Conectividade: OK")
        linhas.append(f"Tempo de conexao: {latencia:.2f} ms")
    else:
        linhas.append("Conectividade: FALHOU")

    linhas.append("========================================")

    relatorio = "\n".join(linhas)

    print("\n" + relatorio)
    salvar_relatorio(relatorio)


if __name__ == "__main__":
    main()