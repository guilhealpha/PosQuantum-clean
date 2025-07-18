#!/usr/bin/env python3
"""
Script para fazer o push do workflow para o GitHub.
"""

import os
import sys
import subprocess

def run_command(command):
    """Execute um comando shell e retorne o resultado."""
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr

def setup_git_config():
    """Configure o Git com nome e email."""
    name = input("Nome para configuração do Git: ").strip()
    email = input("Email para configuração do Git: ").strip()
    
    run_command(f'git config --global user.name "{name}"')
    run_command(f'git config --global user.email "{email}"')
    
    print("Git configurado com sucesso!")

def push_workflow():
    """Faça o push do workflow para o GitHub."""
    # Adicionar o arquivo de workflow
    returncode, stdout, stderr = run_command("git add .github/workflows/windows-build.yml")
    if returncode != 0:
        print(f"Erro ao adicionar o arquivo de workflow: {stderr}")
        return False
    
    # Fazer o commit
    commit_message = "🚀 WORKFLOW SIMPLIFICADO: Foco apenas no build Windows"
    returncode, stdout, stderr = run_command(f'git commit -m "{commit_message}"')
    if returncode != 0:
        print(f"Erro ao fazer o commit: {stderr}")
        return False
    
    # Fazer o push
    token = input("Token do GitHub: ").strip()
    repo_url = f"https://{token}@github.com/guilhealpha/PosQuantum-clean.git"
    returncode, stdout, stderr = run_command(f"git push {repo_url} master")
    if returncode != 0:
        print(f"Erro ao fazer o push: {stderr}")
        return False
    
    print("Push realizado com sucesso!")
    return True

def main():
    """Função principal."""
    # Configurar o Git
    setup_git_config()
    
    # Fazer o push do workflow
    push_workflow()

if __name__ == "__main__":
    main()

