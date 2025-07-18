#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para adicionar o workflow do GitHub Actions ao repositório existente

Este script adiciona apenas o arquivo de workflow do GitHub Actions ao
repositório existente e faz um commit e push.

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
from pathlib import Path

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('add_workflow.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("add_workflow")

def run_command(command, cwd=None, check=True):
    """
    Executa um comando shell
    
    Args:
        command: Comando a ser executado
        cwd: Diretório de trabalho
        check: Se deve verificar o código de retorno
        
    Returns:
        tuple: (stdout, stderr)
    """
    try:
        logger.info(f"Executando comando: {command}")
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=check,
            cwd=cwd
        )
        
        return result.stdout.strip(), result.stderr.strip()
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar comando: {e}")
        logger.error(f"Saída de erro: {e.stderr}")
        
        if check:
            raise
        
        return "", e.stderr

def init_git_repo(repo_dir):
    """
    Inicializa o repositório Git se necessário
    
    Args:
        repo_dir: Diretório do repositório
        
    Returns:
        bool: True se o repositório foi inicializado com sucesso, False caso contrário
    """
    try:
        # Verificar se o repositório já está inicializado
        if os.path.exists(os.path.join(repo_dir, ".git")):
            logger.info("Repositório Git já inicializado")
            return True
        
        # Inicializar repositório
        run_command("git init", cwd=repo_dir)
        logger.info("Repositório Git inicializado")
        
        # Configurar usuário e email
        name = input("Nome para configuração do Git: ")
        email = input("Email para configuração do Git: ")
        
        run_command(f'git config user.name "{name}"', cwd=repo_dir)
        run_command(f'git config user.email "{email}"', cwd=repo_dir)
        
        logger.info("Usuário e email configurados")
        
        return True
    
    except Exception as e:
        logger.error(f"Erro ao inicializar repositório Git: {e}")
        return False

def add_remote(repo_dir, remote_url):
    """
    Adiciona um repositório remoto se necessário
    
    Args:
        repo_dir: Diretório do repositório
        remote_url: URL do repositório remoto
        
    Returns:
        bool: True se o repositório remoto foi adicionado com sucesso, False caso contrário
    """
    try:
        # Verificar se o repositório remoto já existe
        stdout, _ = run_command("git remote -v", cwd=repo_dir, check=False)
        
        if "origin" in stdout:
            # Atualizar URL do repositório remoto
            run_command(f"git remote set-url origin {remote_url}", cwd=repo_dir)
            logger.info(f"URL do repositório remoto atualizada: {remote_url}")
        else:
            # Adicionar repositório remoto
            run_command(f"git remote add origin {remote_url}", cwd=repo_dir)
            logger.info(f"Repositório remoto adicionado: {remote_url}")
        
        return True
    
    except Exception as e:
        logger.error(f"Erro ao adicionar repositório remoto: {e}")
        return False

def commit_and_push_workflow(repo_dir, token, remote_url):
    """
    Faz commit e push apenas do arquivo de workflow
    
    Args:
        repo_dir: Diretório do repositório
        token: Token do GitHub
        remote_url: URL do repositório remoto
        
    Returns:
        bool: True se o commit e push foram bem-sucedidos, False caso contrário
    """
    try:
        # Adicionar apenas o arquivo de workflow
        workflow_path = os.path.join(repo_dir, ".github", "workflows", "build-multiplatform.yml")
        run_command(f"git add {workflow_path}", cwd=repo_dir)
        logger.info("Arquivo de workflow adicionado ao stage")
        
        # Fazer commit
        run_command('git commit -m "Adicionar workflow do GitHub Actions para build multiplataforma"', cwd=repo_dir)
        logger.info("Commit realizado")
        
        # Configurar URL remota com token
        if "https://" in remote_url:
            # Formato: https://github.com/owner/repo.git
            remote_url_with_token = remote_url.replace("https://", f"https://{token}@")
        else:
            # Manter URL original para SSH
            remote_url_with_token = remote_url
        
        # Fazer push
        branch = "main"  # ou "master", dependendo do repositório
        
        # Verificar qual branch existe
        stdout, _ = run_command("git branch", cwd=repo_dir, check=False)
        if "master" in stdout:
            branch = "master"
        
        run_command(f"git push -u origin {branch}", cwd=repo_dir)
        logger.info(f"Push realizado com sucesso para branch {branch}")
        
        return True
    
    except Exception as e:
        logger.error(f"Erro ao fazer commit e push: {e}")
        return False

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Adicionar workflow do GitHub Actions ao repositório existente")
    
    parser.add_argument("--token", help="Token do GitHub")
    parser.add_argument("--remote", help="URL do repositório remoto")
    parser.add_argument("--repo-dir", help="Diretório do repositório", default=".")
    
    args = parser.parse_args()
    
    # Obter diretório do repositório
    repo_dir = os.path.abspath(args.repo_dir)
    logger.info(f"Diretório do repositório: {repo_dir}")
    
    # Inicializar repositório Git se necessário
    if not init_git_repo(repo_dir):
        logger.error("Erro ao inicializar repositório Git")
        return 1
    
    # Obter URL do repositório remoto
    remote_url = args.remote
    if not remote_url:
        remote_url = input("URL do repositório remoto (https://github.com/owner/repo.git): ")
    
    # Adicionar repositório remoto se necessário
    if not add_remote(repo_dir, remote_url):
        logger.error("Erro ao adicionar repositório remoto")
        return 1
    
    # Obter token do GitHub
    token = args.token
    if not token:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            token = getpass.getpass("Token do GitHub: ")
    
    # Fazer commit e push apenas do arquivo de workflow
    if not commit_and_push_workflow(repo_dir, token, remote_url):
        logger.error("Erro ao fazer commit e push do arquivo de workflow")
        return 1
    
    logger.info("Workflow do GitHub Actions adicionado com sucesso")
    
    # Instruções para o usuário
    print("\nWorkflow do GitHub Actions adicionado com sucesso!")
    print(f"O arquivo de workflow foi enviado para o repositório {remote_url}.")
    print("\nPróximos passos:")
    print("1. Verifique o workflow do GitHub Actions em:")
    print("   https://github.com/<owner>/<repo>/actions")
    print("2. Aguarde a conclusão do build para baixar os executáveis gerados")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

