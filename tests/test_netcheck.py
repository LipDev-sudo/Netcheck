import io
import json
import socket
import ssl
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import netcheck


class TestVerificarDNS(unittest.TestCase):
    @patch("netcheck.socket.gethostbyname")
    def test_dns_sucesso(self, mock_dns):
        mock_dns.return_value = "192.0.2.10"

        resultado = netcheck.verificar_dns("exemplo.test", silencioso=True)

        self.assertEqual(resultado, "192.0.2.10")

    @patch("netcheck.socket.gethostbyname")
    def test_dns_falha(self, mock_dns):
        mock_dns.side_effect = socket.gaierror

        resultado = netcheck.verificar_dns("invalido.test", silencioso=True)

        self.assertIsNone(resultado)

    def test_dominio_com_rotulo_vazio_nao_gera_excecao(self):
        self.assertIsNone(netcheck.verificar_dns("a..b", silencioso=True))


class TestVerificarTCP(unittest.TestCase):
    @patch("netcheck.socket.create_connection")
    @patch("netcheck.time.perf_counter")
    def test_tcp_sucesso(self, mock_timer, mock_connection):
        mock_timer.side_effect = [10.0, 10.05]

        resultado = netcheck.verificar_tcp("exemplo.test", 443, silencioso=True)

        self.assertAlmostEqual(resultado, 50.0)
        mock_connection.return_value.close.assert_called_once()

    @patch("netcheck.socket.create_connection")
    def test_tcp_falha(self, mock_connection):
        mock_connection.side_effect = OSError("Conexao recusada")

        resultado = netcheck.verificar_tcp("exemplo.test", 443, silencioso=True)

        self.assertIsNone(resultado)

    @patch("netcheck.socket.create_connection")
    def test_usa_o_timeout_informado(self, mock_connection):
        netcheck.verificar_tcp("exemplo.test", 80, timeout=7, silencioso=True)

        mock_connection.assert_called_once_with(("exemplo.test", 80), timeout=7)


class TestMedirTCP(unittest.TestCase):
    @patch("netcheck.verificar_tcp")
    def test_resume_varias_tentativas(self, mock_tcp):
        mock_tcp.side_effect = [10.0, None, 30.0, 20.0]

        resultado = netcheck.medir_tcp("exemplo.test", 443, tentativas=4, silencioso=True)

        self.assertEqual(resultado["sucessos"], 3)
        self.assertEqual(resultado["perda_pct"], 25.0)
        self.assertEqual(resultado["min_ms"], 10.0)
        self.assertEqual(resultado["max_ms"], 30.0)
        self.assertEqual(resultado["tempo_conexao_ms"], 20.0)
        self.assertTrue(resultado["conectividade"])

    @patch("netcheck.verificar_tcp", return_value=None)
    def test_todas_as_tentativas_falham(self, _tcp):
        resultado = netcheck.medir_tcp("exemplo.test", 443, tentativas=3, silencioso=True)

        self.assertFalse(resultado["conectividade"])
        self.assertEqual(resultado["perda_pct"], 100.0)
        self.assertIsNone(resultado["tempo_conexao_ms"])


def _certificado(nao_depois):
    return {
        "notAfter": nao_depois,
        "issuer": ((("organizationName", "Autoridade Teste"),),),
    }


class TestVerificarTLS(unittest.TestCase):
    def _simular(self, certificado):
        socket_bruto = MagicMock()
        conexao_tls = MagicMock()
        conexao_tls.getpeercert.return_value = certificado

        contexto = MagicMock()
        contexto.wrap_socket.return_value.__enter__.return_value = conexao_tls

        criar = MagicMock()
        criar.return_value.__enter__.return_value = socket_bruto

        return (
            patch("netcheck.ssl.create_default_context", return_value=contexto),
            patch("netcheck.socket.create_connection", criar),
        )

    def test_certificado_valido(self):
        agora = datetime(2026, 1, 1, tzinfo=timezone.utc)
        p1, p2 = self._simular(_certificado("Feb  1 00:00:00 2026 GMT"))

        with p1, p2:
            resultado = netcheck.verificar_tls("exemplo.test", agora=agora)

        self.assertTrue(resultado["valido"])
        self.assertEqual(resultado["dias_restantes"], 31)
        self.assertEqual(resultado["emissor"], "Autoridade Teste")

    def test_certificado_expirado(self):
        agora = datetime(2026, 3, 1, tzinfo=timezone.utc)
        p1, p2 = self._simular(_certificado("Feb  1 00:00:00 2026 GMT"))

        with p1, p2:
            resultado = netcheck.verificar_tls("exemplo.test", agora=agora)

        self.assertFalse(resultado["valido"])
        self.assertEqual(resultado["erro"], "Certificado expirado.")

    def test_falha_de_verificacao(self):
        erro = ssl.SSLCertVerificationError(1, "falha")
        erro.verify_message = "certificate verify failed"

        with patch("netcheck.socket.create_connection", side_effect=erro):
            resultado = netcheck.verificar_tls("exemplo.test")

        self.assertFalse(resultado["valido"])
        self.assertEqual(resultado["erro"], "certificate verify failed")

    def test_falha_de_conexao(self):
        with patch("netcheck.socket.create_connection", side_effect=OSError("recusada")):
            resultado = netcheck.verificar_tls("exemplo.test")

        self.assertFalse(resultado["valido"])
        self.assertEqual(resultado["erro"], "recusada")


class TestValidarPorta(unittest.TestCase):
    def test_porta_valida(self):
        self.assertEqual(netcheck.validar_porta("8080"), 8080)

    def test_porta_fora_do_intervalo(self):
        for valor in ("0", "65536", "-1"):
            with self.assertRaises(ValueError):
                netcheck.validar_porta(valor)

    def test_porta_nao_numerica(self):
        with self.assertRaises(ValueError):
            netcheck.validar_porta("abc")

    def test_lista_de_portas_sem_repeticao(self):
        self.assertEqual(netcheck.validar_portas("80, 443,80"), [80, 443])

    def test_lista_com_porta_invalida(self):
        with self.assertRaises(ValueError):
            netcheck.validar_portas("80,99999")


class TestSalvarRelatorio(unittest.TestCase):
    def test_nao_sobrescreve_relatorios_do_mesmo_segundo(self):
        with tempfile.TemporaryDirectory() as pasta:
            primeiro = netcheck.salvar_relatorio("a", pasta, silencioso=True)
            segundo = netcheck.salvar_relatorio("b", pasta, silencioso=True)

            self.assertNotEqual(primeiro, segundo)
            self.assertEqual(primeiro.read_text(encoding="utf-8"), "a")
            self.assertEqual(segundo.read_text(encoding="utf-8"), "b")


class TestMain(unittest.TestCase):
    def executar(self, argv):
        saida, erro = io.StringIO(), io.StringIO()
        with redirect_stdout(saida), redirect_stderr(erro):
            codigo = netcheck.main(argv)
        return codigo, saida.getvalue(), erro.getvalue()

    @patch("netcheck.verificar_tcp", return_value=12.345)
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_json_sucesso(self, _dns, _tcp):
        codigo, saida, _ = self.executar(["exemplo.test", "--json", "--sem-relatorio"])

        resultado = json.loads(saida)["resultados"][0]
        self.assertEqual(codigo, netcheck.SAIDA_OK)
        self.assertEqual(resultado["ip"], "192.0.2.10")
        self.assertEqual(resultado["portas"][0]["porta"], 443)
        self.assertTrue(resultado["portas"][0]["conectividade"])
        self.assertEqual(resultado["portas"][0]["tempo_conexao_ms"], 12.35)

    @patch("netcheck.verificar_dns", return_value=None)
    def test_falha_dns_retorna_codigo_1(self, _dns):
        codigo, saida, _ = self.executar(["invalido.test", "--json", "--sem-relatorio"])

        resultado = json.loads(saida)["resultados"][0]
        self.assertEqual(codigo, netcheck.SAIDA_FALHA)
        self.assertFalse(resultado["dns"])
        self.assertEqual(resultado["portas"], [])

    @patch("netcheck.verificar_tcp", return_value=None)
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_falha_tcp_retorna_codigo_1(self, _dns, _tcp):
        codigo, saida, _ = self.executar(["exemplo.test", "--sem-relatorio"])

        self.assertEqual(codigo, netcheck.SAIDA_FALHA)
        self.assertIn("Conectividade: FALHOU", saida)

    @patch("netcheck.verificar_tcp", side_effect=[5.0, None])
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_varias_portas_falham_se_uma_falhar(self, _dns, _tcp):
        codigo, saida, _ = self.executar(["exemplo.test", "-p", "80,443", "--json", "--sem-relatorio"])

        portas = json.loads(saida)["resultados"][0]["portas"]
        self.assertEqual([p["porta"] for p in portas], [80, 443])
        self.assertEqual([p["conectividade"] for p in portas], [True, False])
        self.assertEqual(codigo, netcheck.SAIDA_FALHA)

    @patch("netcheck.verificar_tcp", return_value=5.0)
    @patch("netcheck.verificar_dns", side_effect=["192.0.2.1", None])
    def test_varios_dominios(self, _dns, _tcp):
        codigo, saida, _ = self.executar(["a.test", "b.test", "--json", "--sem-relatorio"])

        resultados = json.loads(saida)["resultados"]
        self.assertEqual([r["dominio"] for r in resultados], ["a.test", "b.test"])
        self.assertEqual([r["dns"] for r in resultados], [True, False])
        self.assertEqual(codigo, netcheck.SAIDA_FALHA)

    @patch("netcheck.verificar_tls", return_value={"valido": False, "erro": "expirado", "porta": 443})
    @patch("netcheck.verificar_tcp", return_value=5.0)
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_tls_invalido_retorna_codigo_1(self, _dns, _tcp, _tls):
        codigo, saida, _ = self.executar(["exemplo.test", "--tls", "--sem-relatorio"])

        self.assertEqual(codigo, netcheck.SAIDA_FALHA)
        self.assertIn("TLS: FALHOU (expirado)", saida)

    @patch("netcheck.verificar_tls", return_value={"valido": True, "porta": 443})
    @patch("netcheck.verificar_tcp", return_value=5.0)
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_tls_prefere_a_porta_443(self, _dns, _tcp, mock_tls):
        self.executar(["exemplo.test", "-p", "80,443", "--tls", "--json", "--sem-relatorio"])

        self.assertEqual(mock_tls.call_args.args[1], 443)

    @patch("netcheck.verificar_tcp", side_effect=[1.0, 2.0, 3.0])
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_tentativas_geram_estatisticas(self, _dns, _tcp):
        codigo, saida, _ = self.executar(["exemplo.test", "-n", "3", "--json", "--sem-relatorio"])

        porta = json.loads(saida)["resultados"][0]["portas"][0]
        self.assertEqual(codigo, netcheck.SAIDA_OK)
        self.assertEqual((porta["min_ms"], porta["tempo_conexao_ms"], porta["max_ms"]), (1.0, 2.0, 3.0))

    def test_entradas_invalidas_retornam_codigo_2(self):
        casos = (
            ["exemplo.test", "-p", "70000"],
            ["exemplo.test", "-t", "0"],
            ["exemplo.test", "-n", "0"],
            ["exemplo.test", "-n", "101"],
            [" "],
        )

        for argv in casos:
            with self.subTest(argv=argv):
                with redirect_stderr(io.StringIO()):
                    try:
                        codigo = netcheck.main(argv)
                    except SystemExit as saida:
                        codigo = saida.code
                self.assertEqual(codigo, netcheck.SAIDA_ENTRADA_INVALIDA)

    @patch("netcheck.verificar_tcp", return_value=5.0)
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_salva_relatorio_na_pasta_indicada(self, _dns, _tcp):
        with tempfile.TemporaryDirectory() as pasta:
            codigo, _, _ = self.executar(["exemplo.test", "-o", pasta])

            arquivos = list(Path(pasta).glob("netcheck_*.txt"))
            self.assertEqual(codigo, netcheck.SAIDA_OK)
            self.assertEqual(len(arquivos), 1)
            self.assertIn("Conectividade: OK", arquivos[0].read_text(encoding="utf-8"))

    def test_versao(self):
        with redirect_stdout(io.StringIO()) as saida, self.assertRaises(SystemExit) as codigo:
            netcheck.main(["--version"])

        self.assertEqual(codigo.exception.code, 0)
        self.assertIn(netcheck.__version__, saida.getvalue())


if __name__ == "__main__":
    unittest.main()
