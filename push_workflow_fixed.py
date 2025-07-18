#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys

def run_command(command):
    """Executa um comando shell e retorna o resultado."""
    print(f"Executando: {command}")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True
    )
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        print(f"Erro ao executar o comando: {command}")
        print(f"Saída de erro: {stderr}")
        return False
    
    print(f"Saída: {stdout}")
    return True

def main():
    """Função principal para fazer o push do workflow corrigido."""
    # Configurar Git
    run_command('git config --global user.name "PosQuantum Bot"')
    run_command('git config --global user.email "posquantum@example.com"')
    
    # Mover o arquivo corrigido para o local correto
    run_command('cp .github/workflows/build-multiplatform-fixed.yml .github/workflows/build-multiplatform.yml')
    
    # Adicionar o arquivo ao Git
    run_command('git add .github/workflows/build-multiplatform.yml')
    
    # Fazer o commit
    commit_message = "🔧 CORREÇÃO FINAL: Workflow do GitHub Actions simplificado e corrigido"
    run_command(f'git commit -m "{commit_message}"')
    
    # Fazer o push
    token = input("Digite o token do GitHub: ")
    remote_url = "https://github.com/guilhealpha/PosQuantum-clean.git"
    
    # Usar o token como nome de usuário
    push_command = f'git push https://{token}@github.com/guilhealpha/PosQuantum-clean.git master'
    
    success = run_command(push_command)
    
    if success:
        print("✅ Push realizado com sucesso!")
        print("O GitHub Actions irá iniciar automaticamente o build do executável Windows.")
        print("Você pode acompanhar o progresso em: https://github.com/guilhealpha/PosQuantum-clean/actions")
    else:
        print("❌ Falha ao fazer o push. Verifique o token e tente novamente.")

if __name__ == "__main__":
    main()

