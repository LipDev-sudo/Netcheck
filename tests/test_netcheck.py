import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import netcheck


class TestVerificarDNS(unittest.TestCase):

    @patch("netcheck.socket.gethostbyname")
    def test_dns_sucesso(self, mock_dns):
        mock_dns.return_value = "192.0.2.10"

        resultado = netcheck.verificar_dns("exemplo.test")

        self.assertEqual(resultado, "192.0.2.10")

    @patch("netcheck.socket.gethostbyname")
    def test_dns_falha(self, mock_dns):
        mock_dns.side_effect = netcheck.socket.gaierror

        resultado = netcheck.verificar_dns("invalido.test")

        self.assertIsNone(resultado)


class TestVerificarTCP(unittest.TestCase):

    @patch("netcheck.socket.create_connection")
    @patch("netcheck.time.perf_counter")
    def test_tcp_sucesso(self, mock_timer, mock_connection):
        mock_timer.side_effect = [10.0, 10.05]

        resultado = netcheck.verificar_tcp(
            "exemplo.test", 443
        )

        self.assertAlmostEqual(resultado, 50.0)
        mock_connection.return_value.close.assert_called_once()

    @patch("netcheck.socket.create_connection")
    def test_tcp_falha(self, mock_connection):
        mock_connection.side_effect = OSError(
            "Conexao recusada"
        )

        resultado = netcheck.verificar_tcp(
            "exemplo.test", 443
        )

        self.assertIsNone(resultado)


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

        dados = json.loads(saida)
        self.assertEqual(codigo, netcheck.SAIDA_OK)
        self.assertEqual(dados["ip"], "192.0.2.10")
        self.assertEqual(dados["porta"], 443)
        self.assertTrue(dados["conectividade"])
        self.assertEqual(dados["tempo_conexao_ms"], 12.35)

    @patch("netcheck.verificar_dns", return_value=None)
    def test_falha_dns_retorna_codigo_1(self, _dns):
        codigo, saida, _ = self.executar(["invalido.test", "--json", "--sem-relatorio"])

        dados = json.loads(saida)
        self.assertEqual(codigo, netcheck.SAIDA_FALHA)
        self.assertFalse(dados["dns"])
        self.assertFalse(dados["conectividade"])

    @patch("netcheck.verificar_tcp", return_value=None)
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_falha_tcp_retorna_codigo_1(self, _dns, _tcp):
        codigo, saida, _ = self.executar(["exemplo.test", "--sem-relatorio"])

        self.assertEqual(codigo, netcheck.SAIDA_FALHA)
        self.assertIn("Conectividade: FALHOU", saida)

    def test_porta_invalida_retorna_codigo_2(self):
        codigo, _, erro = self.executar(["exemplo.test", "-p", "70000"])

        self.assertEqual(codigo, netcheck.SAIDA_ENTRADA_INVALIDA)
        self.assertIn("entre 1 e 65535", erro)

    @patch("netcheck.verificar_tcp", return_value=5.0)
    @patch("netcheck.verificar_dns", return_value="192.0.2.10")
    def test_salva_relatorio_na_pasta_indicada(self, _dns, _tcp):
        with tempfile.TemporaryDirectory() as pasta:
            codigo, _, _ = self.executar(["exemplo.test", "-o", pasta])

            arquivos = list(netcheck.Path(pasta).glob("netcheck_*.txt"))
            self.assertEqual(codigo, netcheck.SAIDA_OK)
            self.assertEqual(len(arquivos), 1)
            self.assertIn("Conectividade: OK", arquivos[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()