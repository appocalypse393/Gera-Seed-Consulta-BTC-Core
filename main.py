import os
import hashlib
import binascii
import requests
import time
import random
import subprocess
import ecdsa
import base58


# Função para gerar uma seed de 12, 18 ou 24 palavras
def generate_seed(num_words):
    with open("bip39_wordlist.txt", "r") as f:
        wordlist = f.read().splitlines()

    seed_words = [random.choice(wordlist) for _ in range(num_words)]
    return " ".join(seed_words)


# Função para gerar a chave privada a partir da seed
def generate_private_key(seed):
    return hashlib.sha256(seed.encode()).hexdigest()


# Função para converter chave privada em endereço de carteira
def private_key_to_wif(private_key_hex):
    private_key_bytes = binascii.unhexlify(private_key_hex)
    extended_key = b'\x80' + private_key_bytes
    sha256_1 = hashlib.sha256(extended_key).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    checksum = sha256_2[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')  # Decodificar para string


def private_key_to_address(private_key_hex):
    private_key_bytes = binascii.unhexlify(private_key_hex)
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key_bytes = b'\x04' + verifying_key.to_string()

    # SHA-256 + RIPEMD-160
    sha256_1 = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_1)
    hashed_public_key = ripemd160.digest()

    # Adicionar o prefixo de rede (0x00 para Bitcoin Mainnet)
    network_byte = b'\x00' + hashed_public_key

    # Checksum
    sha256_2 = hashlib.sha256(network_byte).digest()
    sha256_3 = hashlib.sha256(sha256_2).digest()
    checksum = sha256_3[:4]

    # Gerar o endereço final em Base58
    address = base58.b58encode(network_byte + checksum)
    return address.decode('utf-8')  # Decodificar para string


# Função para validar uma chave privada
def validate_private_key(private_key_hex):
    try:
        private_key_bytes = binascii.unhexlify(private_key_hex)
        if len(private_key_bytes) != 32:
            return False
        ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        return True
    except (binascii.Error, ValueError, ecdsa.BadSignatureError):
        return False


# Função para fazer chamada RPC ao Bitcoin Core
def bitcoin_rpc(method, params=[]):
    rpc_user = "scriptcode"  # Substitua por seu usuário RPC
    rpc_password = "123"  # Substitua pela sua senha RPC
    rpc_port = 8332
    url = f"http://192.168.1.7:{rpc_port}"

    headers = {'content-type': 'text/plain;'}
    payload = {
        "method": method,
        "params": params,
        "jsonrpc": "2.0",
        "id": 0,
    }

    response = requests.post(url, json=payload, headers=headers, auth=(rpc_user, rpc_password))
    return response.json()


# Função para importar a chave privada no Bitcoin Core
def importar_carteira_privada(chave_privada):
    print(f"Importando chave privada: {chave_privada}")
    resultado = bitcoin_rpc("importprivkey", [chave_privada])
    return resultado


# Função para verificar o status da varredura da blockchain
def verificar_varredura():
    print("Verificando status da varredura...")
    while True:
        wallet_info = bitcoin_rpc("getwalletinfo")
        if not wallet_info['result'].get('scanning', False):
            print("Varredura concluída.")
            break
        print("Aguardando conclusão da varredura...")
        time.sleep(10)  # Espera 10 segundos antes de verificar novamente


# Função para consultar o saldo
def consultar_saldo():
    saldo = bitcoin_rpc("getbalance")
    print(f"Saldo atual: {saldo['result']} BTC")
    return saldo['result']


# Função para tocar um beep
def beep():
    # Emite um beep (varia de sistema para sistema)
    if os.name == "nt":  # Para Windows
        subprocess.call(["echo", "\a"], shell=True)
    else:
        print("\a")  # Beep em sistemas Unix


# Função principal que gera as chaves e consulta saldo
def main():
    try:
        num_chaves = int(input("Quantas chaves você quer gerar? "))
        num_palavras = int(input("Escolha o número de palavras para a seed (12, 18, ou 24): "))

        if num_palavras not in [12, 18, 24]:
            print("Número de palavras inválido. Por favor, escolha 12, 18 ou 24.")
            return

    except ValueError:
        print("Por favor, insira um número válido.")
        return

    # Arquivo para salvar as chaves com saldo
    arquivo_saldo = "carteiras_com_saldo.txt"

    # Loop para gerar as chaves e processar
    for i in range(num_chaves):
        print(f"\nGerando chave {i + 1} de {num_chaves}")

        # Gerar seed e chave privada
        seed = generate_seed(num_palavras)
        private_key = generate_private_key(seed)

        # Validar a chave privada
        if not validate_private_key(private_key):
            print(f"Chave privada inválida: {private_key}")
            continue

        # Converter chave privada para WIF e endereço
        wif = private_key_to_wif(private_key)
        address = private_key_to_address(private_key)

        print(f"Seed gerada: {seed}")
        print(f"Chave privada gerada (WIF): {wif}")
        print(f"Endereço da carteira: {address}")

        # Importar a chave privada no Bitcoin Core
        importar_carteira_privada(wif)

        # Verificar se a varredura foi concluída
        verificar_varredura()

        # Consultar o saldo
        saldo = consultar_saldo()

        if saldo > 0:
            # Salvar no arquivo se houver saldo
            with open(arquivo_saldo, "a") as f:
                f.write(f"Chave privada: {private_key}\nSeed: {seed}\nEndereço: {address}\nSaldo: {saldo} BTC\n\n")
            print("Carteira com saldo encontrada! Informações salvas.")
            beep()  # Tocar beep ao encontrar saldo

    # Tocar beep ao finalizar
    print("Processo concluído.")
    beep()


# Execução do script
if __name__ == "__main__":
    main()
