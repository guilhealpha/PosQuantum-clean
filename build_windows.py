#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de Build para Windows do PosQuantum

Este script gera um executável Windows (.exe) para o PosQuantum,
incluindo todos os módulos e dependências necessárias.

Autor: PosQuantum Team
Data: 18/07/2025
Versão: 3.0
"""

import os
import sys
import shutil
import subprocess
import argparse
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('build_windows.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("build_windows")

# Configurações de build
BUILD_CONFIG = {
    "app_name": "PosQuantum",
    "version": "3.0",
    "main_file": "main.py",
    "icon_file": "assets/icon.ico",
    "splash_image": "assets/splash.png",
    "output_dir": "dist",
    "build_dir": "build",
    "hidden_imports": [
        "PyQt6.QtCore",
        "PyQt6.QtGui",
        "PyQt6.QtWidgets",
        "posquantum_modules.crypto",
        "posquantum_modules.network",
        "posquantum_modules.compliance",
        "posquantum_modules.crypto.ml_kem",
        "posquantum_modules.crypto.ml_dsa",
        "posquantum_modules.crypto.sphincs_plus",
        "posquantum_modules.crypto.elliptic_curve_pq_hybrid",
        "posquantum_modules.crypto.hsm_virtual",
        "posquantum_modules.network.vpn_pq",
        "posquantum_modules.compliance.certifications"
    ],
    "data_files": [
        ("assets", "assets"),
        ("posquantum_modules", "posquantum_modules")
    ],
    "exclude_modules": [
        "tkinter",
        "matplotlib",
        "numpy.random._examples"
    ],
    "runtime_hooks": [
        "hooks/runtime_hook.py"
    ]
}

def check_requirements():
    """
    Verifica se todos os requisitos para o build estão instalados
    
    Returns:
        bool: True se todos os requisitos estão instalados, False caso contrário
    """
    logger.info("Verificando requisitos para build...")
    
    # Verificar Python
    python_version = sys.version.split()[0]
    logger.info(f"Python: {python_version}")
    if sys.version_info < (3, 8):
        logger.error("Python 3.8 ou superior é necessário")
        return False
    
    # Verificar PyInstaller
    try:
        import PyInstaller
        pyinstaller_version = PyInstaller.__version__
        logger.info(f"PyInstaller: {pyinstaller_version}")
    except ImportError:
        logger.error("PyInstaller não encontrado. Instale com: pip install pyinstaller")
        return False
    
    # Verificar PyQt6
    try:
        from PyQt6.QtCore import QT_VERSION_STR
        logger.info(f"PyQt6: {QT_VERSION_STR}")
    except ImportError:
        logger.warning("PyQt6 não encontrado. Instale com: pip install PyQt6")
        return False
    
    # Verificar módulos do PosQuantum
    try:
        import posquantum_modules
        logger.info("Módulos PosQuantum: OK")
    except ImportError:
        logger.error("Módulos PosQuantum não encontrados")
        return False
    
    logger.info("Todos os requisitos estão instalados")
    return True

def create_runtime_hooks():
    """
    Cria os hooks de runtime para o PyInstaller
    
    Returns:
        bool: True se os hooks foram criados com sucesso, False caso contrário
    """
    logger.info("Criando hooks de runtime...")
    
    # Criar diretório de hooks
    hooks_dir = Path("hooks")
    hooks_dir.mkdir(exist_ok=True)
    
    # Criar hook de runtime
    runtime_hook = hooks_dir / "runtime_hook.py"
    
    with open(runtime_hook, "w", encoding="utf-8") as f:
        f.write("""# -*- coding: utf-8 -*-
\"\"\"
Hook de runtime para o PosQuantum

Este hook é executado pelo PyInstaller durante a inicialização do aplicativo
para garantir que todos os módulos sejam carregados corretamente.
\"\"\"

import os
import sys
import importlib

def import_submodules(package_name):
    \"\"\"Importa todos os submódulos de um pacote\"\"\"
    package = importlib.import_module(package_name)
    
    if hasattr(package, '__path__'):
        for loader, name, is_pkg in importlib.util.find_modules(package_name):
            full_name = package_name + '.' + name
            importlib.import_module(full_name)
            if is_pkg:
                import_submodules(full_name)

# Configurar diretório base
if hasattr(sys, '_MEIPASS'):
    # Executando a partir do executável PyInstaller
    BASE_DIR = sys._MEIPASS
else:
    # Executando a partir do script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Adicionar diretório base ao path
sys.path.insert(0, BASE_DIR)

# Importar submódulos
try:
    import_submodules('posquantum_modules')
except Exception as e:
    print(f"Erro ao importar submódulos: {e}")

# Configurar variáveis de ambiente
os.environ['POSQUANTUM_BASE_DIR'] = BASE_DIR
""")
    
    logger.info(f"Hook de runtime criado: {runtime_hook}")
    return True

def create_spec_file():
    """
    Cria o arquivo .spec para o PyInstaller
    
    Returns:
        str: Caminho para o arquivo .spec criado
    """
    logger.info("Criando arquivo .spec...")
    
    app_name = BUILD_CONFIG["app_name"]
    version = BUILD_CONFIG["version"]
    main_file = BUILD_CONFIG["main_file"]
    icon_file = BUILD_CONFIG.get("icon_file")
    splash_image = BUILD_CONFIG.get("splash_image")
    output_dir = BUILD_CONFIG["output_dir"]
    build_dir = BUILD_CONFIG["build_dir"]
    hidden_imports = BUILD_CONFIG["hidden_imports"]
    data_files = BUILD_CONFIG["data_files"]
    exclude_modules = BUILD_CONFIG["exclude_modules"]
    runtime_hooks = BUILD_CONFIG["runtime_hooks"]
    
    # Verificar se os arquivos existem
    if icon_file and not os.path.exists(icon_file):
        logger.warning(f"Arquivo de ícone não encontrado: {icon_file}")
        icon_file = None
    
    if splash_image and not os.path.exists(splash_image):
        logger.warning(f"Imagem de splash não encontrada: {splash_image}")
        splash_image = None
    
    # Criar arquivo .spec
    spec_file = f"{app_name}-{version}.spec"
    
    with open(spec_file, "w", encoding="utf-8") as f:
        f.write(f"""# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Dados adicionais
added_data = [
""")
        
        # Adicionar dados
        for src, dst in data_files:
            f.write(f"    ('{src}', '{dst}'),\n")
        
        f.write(f"""]

# Imports ocultos
hidden_imports = [
""")
        
        # Adicionar imports ocultos
        for imp in hidden_imports:
            f.write(f"    '{imp}',\n")
        
        f.write(f"""]

# Módulos excluídos
excluded_modules = [
""")
        
        # Adicionar módulos excluídos
        for mod in exclude_modules:
            f.write(f"    '{mod}',\n")
        
        f.write(f"""]

# Hooks de runtime
runtime_hooks = [
""")
        
        # Adicionar hooks de runtime
        for hook in runtime_hooks:
            f.write(f"    '{hook}',\n")
        
        f.write(f"""]

a = Analysis(
    ['{main_file}'],
    pathex=[],
    binaries=[],
    datas=added_data,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=runtime_hooks,
    excludes=excluded_modules,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
""")
        
        # Adicionar splash screen se disponível
        if splash_image:
            f.write(f"""
splash = Splash(
    '{splash_image}',
    binaries=a.binaries,
    datas=a.datas,
    text_pos=None,
    text_size=12,
    minify_script=True,
    always_on_top=True,
)
""")
        
        # Configurar executável
        exe_args = f"""
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
"""
        
        # Adicionar splash se disponível
        if splash_image:
            exe_args += "    splash,\n    splash.binaries,\n"
        
        # Continuar configuração do executável
        exe_args += f"""    [],
    name='{app_name}-{version}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,"""
        
        # Adicionar ícone se disponível
        if icon_file:
            exe_args += f"""
    icon='{icon_file}',"""
        
        # Finalizar configuração do executável
        exe_args += f"""
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
"""
        
        f.write(exe_args)
    
    logger.info(f"Arquivo .spec criado: {spec_file}")
    return spec_file

def run_pyinstaller(spec_file):
    """
    Executa o PyInstaller com o arquivo .spec
    
    Args:
        spec_file: Caminho para o arquivo .spec
        
    Returns:
        bool: True se o build foi bem-sucedido, False caso contrário
    """
    logger.info("Executando PyInstaller...")
    
    try:
        # Comando PyInstaller
        cmd = [
            "pyinstaller",
            "--clean",
            "--noconfirm",
            spec_file
        ]
        
        # Executar comando
        logger.info(f"Comando: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Capturar saída
        for line in process.stdout:
            logger.info(line.strip())
        
        # Aguardar conclusão
        process.wait()
        
        # Verificar resultado
        if process.returncode == 0:
            logger.info("Build concluído com sucesso")
            return True
        else:
            logger.error(f"Erro no build: código de retorno {process.returncode}")
            
            # Capturar erro
            for line in process.stderr:
                logger.error(line.strip())
            
            return False
    
    except Exception as e:
        logger.error(f"Erro ao executar PyInstaller: {e}")
        return False

def verify_build():
    """
    Verifica se o build foi gerado corretamente
    
    Returns:
        bool: True se o build foi verificado com sucesso, False caso contrário
    """
    logger.info("Verificando build...")
    
    app_name = BUILD_CONFIG["app_name"]
    version = BUILD_CONFIG["version"]
    output_dir = BUILD_CONFIG["output_dir"]
    
    # Caminho do executável
    exe_path = os.path.join(output_dir, f"{app_name}-{version}.exe")
    
    # Verificar se o executável existe
    if not os.path.exists(exe_path):
        logger.error(f"Executável não encontrado: {exe_path}")
        return False
    
    # Verificar tamanho do executável
    size_mb = os.path.getsize(exe_path) / (1024 * 1024)
    logger.info(f"Tamanho do executável: {size_mb:.2f} MB")
    
    if size_mb < 5:
        logger.warning("Executável parece muito pequeno, pode estar faltando dependências")
    
    logger.info(f"Build verificado: {exe_path}")
    return True

def create_github_workflow():
    """
    Cria um workflow do GitHub Actions para build multiplataforma
    
    Returns:
        bool: True se o workflow foi criado com sucesso, False caso contrário
    """
    logger.info("Criando workflow do GitHub Actions...")
    
    # Criar diretório .github/workflows
    workflow_dir = Path(".github/workflows")
    workflow_dir.mkdir(parents=True, exist_ok=True)
    
    # Criar arquivo de workflow
    workflow_file = workflow_dir / "build-multiplatform.yml"
    
    with open(workflow_file, "w", encoding="utf-8") as f:
        f.write("""name: Build PosQuantum

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  build:
    name: Build on ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: windows-latest
            platform: windows
            executable: PosQuantum-3.0.exe
            artifact: PosQuantum-Windows
          - os: ubuntu-latest
            platform: linux
            executable: PosQuantum-3.0
            artifact: PosQuantum-Linux
          - os: macos-latest
            platform: macos
            executable: PosQuantum-3.0
            artifact: PosQuantum-macOS

    runs-on: ${{ matrix.os }}

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install pyinstaller
        pip install PyQt6
        pip install -r requirements.txt

    - name: Create runtime hooks
      run: |
        mkdir -p hooks
        echo '# -*- coding: utf-8 -*-
import os
import sys
import importlib

def import_submodules(package_name):
    """Importa todos os submódulos de um pacote"""
    package = importlib.import_module(package_name)
    
    if hasattr(package, "__path__"):
        for loader, name, is_pkg in importlib.util.find_modules(package_name):
            full_name = package_name + "." + name
            importlib.import_module(full_name)
            if is_pkg:
                import_submodules(full_name)

# Configurar diretório base
if hasattr(sys, "_MEIPASS"):
    # Executando a partir do executável PyInstaller
    BASE_DIR = sys._MEIPASS
else:
    # Executando a partir do script
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Adicionar diretório base ao path
sys.path.insert(0, BASE_DIR)

# Importar submódulos
try:
    import_submodules("posquantum_modules")
except Exception as e:
    print(f"Erro ao importar submódulos: {e}")

# Configurar variáveis de ambiente
os.environ["POSQUANTUM_BASE_DIR"] = BASE_DIR' > hooks/runtime_hook.py

    - name: Build with PyInstaller
      run: |
        pyinstaller --clean --noconfirm --onefile --name="PosQuantum-3.0" --add-data="assets:assets" --add-data="posquantum_modules:posquantum_modules" --hidden-import="PyQt6.QtCore" --hidden-import="PyQt6.QtGui" --hidden-import="PyQt6.QtWidgets" --hidden-import="posquantum_modules.crypto" --hidden-import="posquantum_modules.network" --hidden-import="posquantum_modules.compliance" --runtime-hook="hooks/runtime_hook.py" main.py

    - name: Upload artifact
      uses: actions/upload-artifact@v3
      with:
        name: ${{ matrix.artifact }}
        path: dist/${{ matrix.executable }}
""")
    
    logger.info(f"Workflow do GitHub Actions criado: {workflow_file}")
    return True

def main():
    """Função principal"""
    parser = argparse.ArgumentParser(description="Script de Build para Windows do PosQuantum")
    
    parser.add_argument("--check-only", action="store_true", help="Apenas verifica os requisitos e sai")
    parser.add_argument("--create-workflow", action="store_true", help="Cria um workflow do GitHub Actions para build multiplataforma")
    parser.add_argument("--output-dir", help="Diretório de saída para o executável")
    
    args = parser.parse_args()
    
    # Verificar requisitos
    if not check_requirements():
        logger.error("Requisitos não atendidos. Abortando build.")
        return 1
    
    # Sair se apenas verificação
    if args.check_only:
        logger.info("Verificação concluída. Todos os requisitos atendidos.")
        return 0
    
    # Atualizar diretório de saída se especificado
    if args.output_dir:
        BUILD_CONFIG["output_dir"] = args.output_dir
    
    # Criar workflow do GitHub Actions
    if args.create_workflow:
        if create_github_workflow():
            logger.info("Workflow do GitHub Actions criado com sucesso.")
            return 0
        else:
            logger.error("Erro ao criar workflow do GitHub Actions.")
            return 1
    
    # Criar hooks de runtime
    if not create_runtime_hooks():
        logger.error("Erro ao criar hooks de runtime. Abortando build.")
        return 1
    
    # Criar arquivo .spec
    spec_file = create_spec_file()
    
    # Executar PyInstaller
    if not run_pyinstaller(spec_file):
        logger.error("Erro ao executar PyInstaller. Abortando build.")
        return 1
    
    # Verificar build
    if not verify_build():
        logger.error("Erro ao verificar build. O build pode estar incompleto.")
        return 1
    
    logger.info("Build concluído com sucesso!")
    
    # Mostrar caminho do executável
    app_name = BUILD_CONFIG["app_name"]
    version = BUILD_CONFIG["version"]
    output_dir = BUILD_CONFIG["output_dir"]
    exe_path = os.path.join(output_dir, f"{app_name}-{version}.exe")
    
    logger.info(f"Executável gerado: {os.path.abspath(exe_path)}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

