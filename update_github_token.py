#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para atualizar o token do GitHub no repositório PosQuantum-clean.

Este script atualiza o token do GitHub usado para autenticação no GitHub Actions,
permitindo a criação de releases e o upload de artefatos.

Autor: PosQuantum Team
Data: 18/07/2025
"""

import os
import sys
import requests
import base64
import json
from nacl import encoding, public

def encrypt_secret(public_key, secret_value):
    """Encrypt a secret using the repository's public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")

def update_github_token(repo_owner, repo_name, token, secret_name, secret_value):
    """Update a GitHub secret in the repository."""
    # Get the repository's public key
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/public-key"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print(f"Error getting public key: {response.status_code}")
        print(response.json())
        return False
    
    public_key_data = response.json()
    public_key = public_key_data["key"]
    key_id = public_key_data["key_id"]
    
    # Encrypt the secret
    encrypted_value = encrypt_secret(public_key, secret_value)
    
    # Update the secret
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/secrets/{secret_name}"
    data = {
        "encrypted_value": encrypted_value,
        "key_id": key_id
    }
    response = requests.put(url, headers=headers, json=data)
    
    if response.status_code != 201 and response.status_code != 204:
        print(f"Error updating secret: {response.status_code}")
        print(response.json())
        return False
    
    return True

def main():
    """Main function."""
    # Get the token from command line arguments
    if len(sys.argv) < 2:
        print("Usage: python update_github_token.py <token>")
        return 1
    
    token = sys.argv[1]
    
    # Repository information
    repo_owner = "guilhealpha"
    repo_name = "PosQuantum-clean"
    secret_name = "POSQUANTUM_TOKEN"
    
    # Update the token
    print(f"Updating token {secret_name} in repository {repo_owner}/{repo_name}...")
    result = update_github_token(repo_owner, repo_name, token, secret_name, token)
    
    if result:
        print("Token updated successfully!")
    else:
        print("Failed to update token.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

