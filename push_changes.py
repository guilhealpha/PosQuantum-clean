#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para fazer o commit e push das alterações para o repositório PosQuantum-clean.

Este script faz o commit e push das alterações para o repositório GitHub,
permitindo a execução do workflow do GitHub Actions.

Autor: PosQuantum Team
Data: 18/07/2025
"""

import os
import sys
import subprocess

def run_command(command):
    """Run a shell command and return the output."""
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr

def push_changes(token, commit_message):
    """Push changes to the GitHub repository."""
    # Configure Git
    print("Configurando Git...")
    run_command("git config --global user.name 'PosQuantum Team'")
    run_command("git config --global user.email 'posquantum@example.com'")
    
    # Add changes
    print("Adicionando alterações...")
    returncode, stdout, stderr = run_command("git add .")
    if returncode != 0:
        print(f"Erro ao adicionar alterações: {stderr}")
        return False
    
    # Commit changes
    print(f"Fazendo commit: {commit_message}")
    returncode, stdout, stderr = run_command(f'git commit -m "{commit_message}"')
    if returncode != 0:
        print(f"Erro ao fazer commit: {stderr}")
        return False
    
    # Push changes
    print("Fazendo push...")
    # Use HTTPS with token in URL
    remote_url = f"https://{token}@github.com/guilhealpha/PosQuantum-clean.git"
    returncode, stdout, stderr = run_command(f"git push {remote_url} master")
    if returncode != 0:
        print(f"Erro ao fazer push: {stderr}")
        return False
    
    return True

def main():
    """Main function."""
    # Get the token from command line arguments
    if len(sys.argv) < 2:
        print("Usage: python push_changes.py <token> [commit_message]")
        return 1
    
    token = sys.argv[1]
    commit_message = sys.argv[2] if len(sys.argv) > 2 else "🔧 CORREÇÃO FINAL: Workflow do GitHub Actions atualizado"
    
    # Push changes
    print(f"Fazendo push das alterações para o repositório guilhealpha/PosQuantum-clean...")
    result = push_changes(token, commit_message)
    
    if result:
        print("Alterações enviadas com sucesso!")
    else:
        print("Falha ao enviar alterações.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

