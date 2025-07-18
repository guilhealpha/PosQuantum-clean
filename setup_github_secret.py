#!/usr/bin/env python3
"""
Script para configurar o token do GitHub como segredo no repositório.
"""

import os
import sys
import requests
import base64
import json
from nacl import encoding, public

def encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")

def setup_secret(token, repo_owner, repo_name, secret_name, secret_value):
    """Configure um segredo no repositório GitHub."""
    # Obter a chave pública do repositório
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/public-key"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Erro ao obter a chave pública: {response.status_code}")
        print(response.text)
        return False
    
    public_key_data = response.json()
    public_key = public_key_data["key"]
    public_key_id = public_key_data["key_id"]
    
    # Criptografar o segredo
    encrypted_secret = encrypt(public_key, secret_value)
    
    # Configurar o segredo
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/{secret_name}"
    data = {
        "encrypted_value": encrypted_secret,
        "key_id": public_key_id
    }
    
    response = requests.put(url, headers=headers, json=data)
    if response.status_code in [201, 204]:
        print(f"Segredo {secret_name} configurado com sucesso!")
        return True
    else:
        print(f"Erro ao configurar o segredo: {response.status_code}")
        print(response.text)
        return False

def main():
    """Função principal."""
    # Obter o token do GitHub
    token = input("Token do GitHub: ").strip()
    
    # Configurar o repositório
    repo_owner = "guilhealpha"
    repo_name = "PosQuantum-clean"
    
    # Configurar o segredo
    secret_name = "POSQUANTUM_TOKEN"
    secret_value = token
    
    # Configurar o segredo no repositório
    setup_secret(token, repo_owner, repo_name, secret_name, secret_value)

if __name__ == "__main__":
    main()

