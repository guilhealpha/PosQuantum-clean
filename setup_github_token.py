#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para configurar o token do GitHub como um segredo no repositório

Este script configura o token do GitHub como um segredo no repositório,
permitindo que o workflow do GitHub Actions acesse o repositório e
crie releases.

Autor: PosQuantum Team
Data: 18/07/2025
Versão: 3.0
"""

import os
import sys
import subprocess
import argparse
import logging
import getpass
import requests
import base64
import json
from pathlib import Path

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('setup_github_token.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("setup_github_token")

def get_github_token():
    """
    Obtém o token do GitHub
    
    Returns:
        str: Token do GitHub
    """
    # Verificar se o token foi passado como argumento
    parser = argparse.ArgumentParser(description="Configurar token do GitHub")
    parser.add_argument("--token", help="Token do GitHub")
    args = parser.parse_args()
    
    if args.token:
        return args.token
    
    # Verificar se o token está definido como variável de ambiente
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    
    # Solicitar o token ao usuário
    token = getpass.getpass("Token do GitHub: ")
    return token

def get_repo_info():
    """
    Obtém informações do repositório
    
    Returns:
        tuple: (owner, repo)
    """
    try:
        # Executar comando git para obter a URL do repositório remoto
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Extrair owner e repo da URL
        url = result.stdout.strip()
        
        # Formato: https://github.com/owner/repo.git ou git@github.com:owner/repo.git
        if url.startswith("https://"):
            parts = url.split("/")
            owner = parts[-2]
            repo = parts[-1].replace(".git", "")
        else:
            parts = url.split(":")
            owner_repo = parts[-1].replace(".git", "")
            owner, repo = owner_repo.split("/")
        
        return owner, repo
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao obter informações do repositório: {e}")
        
        # Solicitar informações ao usuário
        owner = input("Nome do proprietário do repositório: ")
        repo = input("Nome do repositório: ")
        
        return owner, repo

def create_secret(token, owner, repo, secret_name, secret_value):
    """
    Cria um segredo no repositório
    
    Args:
        token: Token do GitHub
        owner: Proprietário do repositório
        repo: Nome do repositório
        secret_name: Nome do segredo
        secret_value: Valor do segredo
        
    Returns:
        bool: True se o segredo foi criado com sucesso, False caso contrário
    """
    try:
        # Obter a chave pública do repositório
        url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {token}"
        }
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        public_key_data = response.json()
        public_key = public_key_data["key"]
        public_key_id = public_key_data["key_id"]
        
        # Criptografar o segredo
        from nacl import encoding, public
        
        public_key_bytes = public.PublicKey(
            public_key.encode("utf-8"),
            encoding.Base64Encoder()
        )
        
        sealed_box = public.SealedBox(public_key_bytes)
        encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
        encrypted_value = base64.b64encode(encrypted).decode("utf-8")
        
        # Criar o segredo
        url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"
        data = {
            "encrypted_value": encrypted_value,
            "key_id": public_key_id
        }
        
        response = requests.put(url, headers=headers, json=data)
        response.raise_for_status()
        
        logger.info(f"Segredo {secret_name} criado com sucesso")
        return True
    
    except Exception as e:
        logger.error(f"Erro ao criar segredo: {e}")
        return False

def main():
    """Função principal"""
    # Obter token do GitHub
    token = get_github_token()
    if not token:
        logger.error("Token do GitHub não fornecido")
        return 1
    
    # Obter informações do repositório
    owner, repo = get_repo_info()
    logger.info(f"Repositório: {owner}/{repo}")
    
    # Criar segredo
    secret_name = "GITHUB_TOKEN"
    if create_secret(token, owner, repo, secret_name, token):
        logger.info(f"Segredo {secret_name} configurado com sucesso")
        
        # Instruções para o usuário
        print("\nSegredo configurado com sucesso!")
        print(f"O token do GitHub foi configurado como um segredo no repositório {owner}/{repo}.")
        print("O workflow do GitHub Actions agora pode acessar o repositório e criar releases.")
        print("\nPróximos passos:")
        print("1. Faça commit das alterações e push para o repositório")
        print("2. Verifique o workflow do GitHub Actions em:")
        print(f"   https://github.com/{owner}/{repo}/actions")
        
        return 0
    else:
        logger.error("Erro ao configurar segredo")
        return 1

if __name__ == "__main__":
    sys.exit(main())

