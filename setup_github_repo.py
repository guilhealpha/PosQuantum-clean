#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para inicializar o repositório Git do PosQuantum

Este script inicializa o repositório Git, configura o token do GitHub,
faz o primeiro commit e push para o repositório remoto.

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
        logging.FileHandler('setup_github_repo.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("setup_github_repo")

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
    Inicializa o repositório Git
    
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
    Adiciona um repositório remoto
    
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

def create_gitignore(repo_dir):
    """
    Cria o arquivo .gitignore
    
    Args:
        repo_dir: Diretório do repositório
        
    Returns:
        bool: True se o arquivo foi criado com sucesso, False caso contrário
    """
    try:
        gitignore_path = os.path.join(repo_dir, ".gitignore")
        
        with open(gitignore_path, "w", encoding="utf-8") as f:
            f.write("""# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# PyInstaller
#  Usually these files are written by a PyInstaller build script
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.pytest_cache/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
target/

# Jupyter Notebook
.ipynb_checkpoints

# pyenv
.python-version

# celery beat schedule file
celerybeat-schedule

# SageMath parsed files
*.sage.py

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/

# PyCharm
.idea/

# VS Code
.vscode/

# Logs
*.log

# Tokens
*.token

# Sensitive files
setup_github_token.log
""")
        
        logger.info("Arquivo .gitignore criado")
        return True
    
    except Exception as e:
        logger.error(f"Erro ao criar arquivo .gitignore: {e}")
        return False

def commit_and_push(repo_dir, token, remote_url):
    """
    Faz commit e push para o repositório remoto
    
    Args:
        repo_dir: Diretório do repositório
        token: Token do GitHub
        remote_url: URL do repositório remoto
        
    Returns:
        bool: True se o commit e push foram bem-sucedidos, False caso contrário
    """
    try:
        # Adicionar todos os arquivos
        run_command("git add .", cwd=repo_dir)
        logger.info("Arquivos adicionados ao stage")
        
        # Fazer commit
        run_command('git commit -m "Implementação inicial do PosQuantum"', cwd=repo_dir)
        logger.info("Commit realizado")
        
        # Configurar URL remota com token
        if "https://" in remote_url:
            # Formato: https://github.com/owner/repo.git
            remote_url_with_token = remote_url.replace("https://", f"https://{token}@")
        else:
            # Manter URL original para SSH
            remote_url_with_token = remote_url
        
        # Fazer push
        run_command(f"git push -u origin main", cwd=repo_dir)
        logger.info("Push realizado com sucesso")
        
        return True
    
    except Exception as e:
        logger.error(f"Erro ao fazer commit e push: {e}")
        return False

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Inicializar repositório Git do PosQuantum")
    
    parser.add_argument("--token", help="Token do GitHub")
    parser.add_argument("--remote", help="URL do repositório remoto")
    parser.add_argument("--repo-dir", help="Diretório do repositório", default=".")
    
    args = parser.parse_args()
    
    # Obter diretório do repositório
    repo_dir = os.path.abspath(args.repo_dir)
    logger.info(f"Diretório do repositório: {repo_dir}")
    
    # Inicializar repositório Git
    if not init_git_repo(repo_dir):
        logger.error("Erro ao inicializar repositório Git")
        return 1
    
    # Criar arquivo .gitignore
    if not create_gitignore(repo_dir):
        logger.error("Erro ao criar arquivo .gitignore")
        return 1
    
    # Obter URL do repositório remoto
    remote_url = args.remote
    if not remote_url:
        remote_url = input("URL do repositório remoto (https://github.com/owner/repo.git): ")
    
    # Adicionar repositório remoto
    if not add_remote(repo_dir, remote_url):
        logger.error("Erro ao adicionar repositório remoto")
        return 1
    
    # Obter token do GitHub
    token = args.token
    if not token:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            token = getpass.getpass("Token do GitHub: ")
    
    # Fazer commit e push
    if not commit_and_push(repo_dir, token, remote_url):
        logger.error("Erro ao fazer commit e push")
        return 1
    
    logger.info("Repositório Git inicializado e configurado com sucesso")
    
    # Instruções para o usuário
    print("\nRepositório Git inicializado e configurado com sucesso!")
    print(f"O código do PosQuantum foi enviado para o repositório {remote_url}.")
    print("\nPróximos passos:")
    print("1. Configure o token do GitHub como um segredo no repositório:")
    print("   python setup_github_token.py --token <token>")
    print("2. Verifique o workflow do GitHub Actions em:")
    print("   https://github.com/<owner>/<repo>/actions")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

