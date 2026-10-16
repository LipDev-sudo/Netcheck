import unittest
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


if __name__ == "__main__":
    unittest.main()