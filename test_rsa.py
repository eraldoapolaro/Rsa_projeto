from math import gcd, isqrt
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from rsa_core import (
    BITS_PRIMO,
    criptografar,
    decifrar,
    eh_primo,
    gerar_chaves,
    gerar_chaves_aleatorias,
    inverso_modular,
)


class TestesRSA(unittest.TestCase):
    def test_primalidade_conferida_por_divisao(self):
        for numero in range(-2, 2000):
            esperado = numero >= 2 and all(
                numero % divisor != 0
                for divisor in range(2, isqrt(max(numero, 0)) + 1)
            )
            with self.subTest(numero=numero):
                self.assertEqual(eh_primo(numero), esperado)

    def test_compostos_grandes_e_pseudoprimos(self):
        compostos = (
            1_000_001,
            3_215_031_751,
            341_550_071_728_321,
            (2 ** 127 - 1) * (2 ** 61 - 1),
        )
        for numero in compostos:
            with self.subTest(numero=numero):
                self.assertFalse(eh_primo(numero))

    def test_rejeita_primos_invalidos_e_repetidos(self):
        for invalido in (-7, 0, 1, 4, 9, 15, 561):
            with self.subTest(invalido=invalido):
                with self.assertRaises(ValueError):
                    gerar_chaves(invalido, 53)
                with self.assertRaises(ValueError):
                    gerar_chaves(61, invalido)
        with self.assertRaises(ValueError):
            gerar_chaves(61, 61)

    def test_inverso_conhecido_e_inexistente(self):
        self.assertEqual(inverso_modular(17, 3120), 2753)
        with self.assertRaises(ValueError):
            inverso_modular(6, 12)

    def test_chaves_manuais(self):
        publica, privada = gerar_chaves(61, 53)
        self.assertEqual(publica, (3233, 65537))
        self.assertEqual(privada, (3233, 2753))
        self.assertEqual((publica[1] * privada[1]) % 3120, 1)

    def test_escolhe_outro_e_quando_65537_nao_e_coprimo(self):
        publica, privada = gerar_chaves(917519, 53)
        phi = (917519 - 1) * (53 - 1)
        self.assertEqual(publica[1], 3)
        self.assertEqual((publica[1] * privada[1]) % phi, 1)
        cifra = criptografar("Outro expoente: çãé.", *publica)
        self.assertEqual(decifrar(cifra, *privada), "Outro expoente: çãé.")

    def test_vetor_rsa_conhecido_com_chave_informada(self):
        self.assertEqual(criptografar("A", 3233, 17), "2790")
        self.assertEqual(decifrar("2790", 3233, 2753), "A")

    def test_unicode_espacos_e_quebras_de_linha(self):
        texto = "  Ação, café e coração!\n日本語 😀\r\n\tFinal  \n"
        publica, privada = gerar_chaves(61, 53)
        cifra = criptografar(texto, *publica)
        self.assertEqual(decifrar(cifra, *privada), texto)

    def test_texto_vazio(self):
        self.assertEqual(criptografar("", 3233, 17), "")
        self.assertEqual(decifrar("", 3233, 2753), "")

    def test_todos_os_bytes_utf8_com_primos_pequenos(self):
        texto = "".join(chr(numero) for numero in range(256)) + "😀"
        for p, q in ((2, 3), (2, 5), (3, 5), (7, 31), (17, 19), (61, 53)):
            with self.subTest(p=p, q=q):
                publica, privada = gerar_chaves(p, q)
                cifra = criptografar(texto, *publica)
                self.assertEqual(decifrar(cifra, *privada), texto)

    def test_inteiros_acima_de_64_bits(self):
        publica, privada = gerar_chaves(2 ** 127 - 1, 2 ** 61 - 1)
        self.assertGreater(publica[0].bit_length(), 64)
        cifra = criptografar("Inteiros grandes e acentuação: çãé.", *publica)
        self.assertEqual(
            decifrar(cifra, *privada), "Inteiros grandes e acentuação: çãé."
        )

    def test_geracao_aleatoria_e_validacao_das_chaves(self):
        p, q, publica, privada = gerar_chaves_aleatorias()
        self.assertNotEqual(p, q)
        self.assertEqual(p.bit_length(), BITS_PRIMO)
        self.assertEqual(q.bit_length(), BITS_PRIMO)
        self.assertTrue(eh_primo(p))
        self.assertTrue(eh_primo(q))
        phi = (p - 1) * (q - 1)
        self.assertEqual(gcd(publica[1], phi), 1)
        self.assertEqual((publica[1] * privada[1]) % phi, 1)
        cifra = criptografar("Chaves aleatórias: Olá! 😀", *publica)
        self.assertEqual(decifrar(cifra, *privada), "Chaves aleatórias: Olá! 😀")

    def test_sorteio_repetido_gera_outro_primo(self):
        with patch("rsa_core.gerar_primo", side_effect=[61, 61, 53]):
            p, q, _, _ = gerar_chaves_aleatorias()
        self.assertEqual((p, q), (61, 53))

    def test_rejeita_chaves_invalidas(self):
        for n, expoente in ((0, 17), (-1, 17), (5, 17), (3233, 0), (3233, -3)):
            with self.subTest(n=n, expoente=expoente):
                with self.assertRaises(ValueError):
                    criptografar("A", n, expoente)
                with self.assertRaises(ValueError):
                    decifrar("2790", n, expoente)

    def test_rejeita_cifras_malformadas(self):
        for cifra in ("abc", "-1", "1.2", "1,2", "3233", "9999", "1_2"):
            with self.subTest(cifra=cifra):
                with self.assertRaises(ValueError):
                    decifrar(cifra, 3233, 2753)
        with self.assertRaises(ValueError):
            decifrar("1 2 3", 6, 1)

    def test_rejeita_byte_fora_da_faixa_e_utf8_invalido(self):
        for byte in (255, 256):
            with self.subTest(byte=byte):
                cifra = str(pow(byte, 17, 3233))
                with self.assertRaises(ValueError):
                    decifrar(cifra, 3233, 2753)

    def test_arquivo_rsa_e_separadores(self):
        texto = "Arquivo UTF-8.\nAcentos: ãéç."
        cifra = criptografar(texto, 3233, 17)
        with TemporaryDirectory() as pasta:
            caminho = Path(pasta) / "mensagem.rsa"
            caminho.write_text(cifra, encoding="utf-8")
            conteudo = caminho.read_text(encoding="utf-8")
        self.assertEqual(decifrar(conteudo, 3233, 2753), texto)
        separadores = "\t \n".join(cifra.split())
        self.assertEqual(decifrar(separadores, 3233, 2753), texto)


if __name__ == "__main__":
    unittest.main()
