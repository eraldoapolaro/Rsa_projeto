"""Cálculos RSA do projeto. Referências: REFERENCIAS.md, itens 1 a 3."""

from math import gcd, isqrt
from secrets import randbelow, randbits


BITS_PRIMO = 128
RODADAS_PRIMALIDADE = 64


def eh_primo(numero: int) -> bool:
    """Usa divisão exata até um milhão e Miller-Rabin acima disso."""
    if numero < 2:
        return False
    if numero in (2, 3):
        return True
    if numero % 2 == 0 or numero % 3 == 0:
        return False

    if numero <= 1_000_000:
        for divisor in range(5, isqrt(numero) + 1, 6):
            if numero % divisor == 0 or numero % (divisor + 2) == 0:
                return False
        return True

    # Decompõe numero - 1 em parte_impar * 2 ** quantidade.
    parte_impar = numero - 1
    quantidade = 0
    while parte_impar % 2 == 0:
        parte_impar //= 2
        quantidade += 1

    for _ in range(RODADAS_PRIMALIDADE):
        base = randbelow(numero - 3) + 2
        resultado = pow(base, parte_impar, numero)
        if resultado in (1, numero - 1):
            continue

        for _ in range(quantidade - 1):
            resultado = pow(resultado, 2, numero)
            if resultado == numero - 1:
                break
        else:
            return False

    return True


def gerar_primo() -> int:
    """Sorteia candidatos ímpares de 128 bits e testa a primalidade."""
    while True:
        candidato = randbits(BITS_PRIMO)
        candidato |= (1 << (BITS_PRIMO - 1)) | 1
        if eh_primo(candidato):
            return candidato


def inverso_modular(valor: int, modulo: int) -> int:
    """Calcula o inverso pelo algoritmo de Euclides estendido."""
    if modulo < 2:
        raise ValueError("O módulo do inverso deve ser maior que 1.")

    resto_anterior, resto = modulo, valor % modulo
    coef_anterior, coeficiente = 0, 1

    while resto:
        quociente = resto_anterior // resto
        resto_anterior, resto = resto, resto_anterior - quociente * resto
        coef_anterior, coeficiente = (
            coeficiente,
            coef_anterior - quociente * coeficiente,
        )

    if resto_anterior != 1:
        raise ValueError("Não existe inverso modular para esses valores.")
    return coef_anterior % modulo


def gerar_chaves(p: int, q: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Valida os primos e devolve as chaves (n, e) e (n, d)."""
    if not eh_primo(p):
        raise ValueError("p deve ser um número primo.")
    if not eh_primo(q):
        raise ValueError("q deve ser um número primo.")
    if p == q:
        raise ValueError("p e q devem ser diferentes.")

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = inverso_modular(e, phi)
    return (n, e), (n, d)


def gerar_chaves_aleatorias():
    """Gera dois primos distintos e valida ambos ao montar as chaves."""
    p = gerar_primo()
    q = gerar_primo()
    while p == q:
        q = gerar_primo()

    publica, privada = gerar_chaves(p, q)
    return p, q, publica, privada


def validar_chave(n: int, expoente: int):
    if n < 6:
        raise ValueError("n deve ser pelo menos 6.")
    if expoente < 1:
        raise ValueError("O expoente da chave deve ser positivo.")


def digitos_por_byte(n: int) -> int:
    """Cada dígito em base n fica entre 0 e n - 1, como exige o RSA."""
    quantidade = 1
    capacidade = n
    while capacidade < 256:
        capacidade *= n
        quantidade += 1
    return quantidade


def criptografar(texto: str, n: int, e: int) -> str:
    """Codifica em UTF-8 e aplica c = m ** e mod n a cada bloco."""
    validar_chave(n, e)
    quantidade = digitos_por_byte(n)
    blocos = []

    for byte in texto.encode("utf-8"):
        # Para n >= 256 há um bloco por byte. Para n menor, usamos
        # dígitos em base n, sem descartar parte do valor do byte.
        digitos = [0] * quantidade
        for indice in range(quantidade - 1, -1, -1):
            byte, digitos[indice] = divmod(byte, n)
        for digito in digitos:
            blocos.append(str(pow(digito, e, n)))

    linhas = []
    for inicio in range(0, len(blocos), 6):
        linhas.append(" ".join(blocos[inicio:inicio + 6]))
    return "\n".join(linhas)


def decifrar(cifra: str, n: int, d: int) -> str:
    """Aplica m = c ** d mod n e reconstrói os bytes UTF-8."""
    validar_chave(n, d)
    quantidade = digitos_por_byte(n)
    blocos = cifra.split()

    if len(blocos) % quantidade != 0:
        raise ValueError("A cifra está incompleta para o valor de n informado.")

    dados = bytearray()
    for inicio in range(0, len(blocos), quantidade):
        byte = 0
        for bloco in blocos[inicio:inicio + quantidade]:
            if not bloco.isascii() or not bloco.isdecimal():
                raise ValueError("A cifra deve conter números decimais.")
            valor = int(bloco)
            if valor >= n:
                raise ValueError("Cada bloco cifrado deve ser menor que n.")
            byte = byte * n + pow(valor, d, n)

        if byte > 255:
            raise ValueError("A cifra ou a chave privada não corresponde ao texto.")
        dados.append(byte)

    try:
        return dados.decode("utf-8")
    except UnicodeDecodeError as erro:
        raise ValueError(
            "O resultado não é UTF-8 válido. Confira a cifra e a chave privada."
        ) from erro
