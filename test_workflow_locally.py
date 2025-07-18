#!/usr/bin/env python3
"""
Script para testar o workflow do GitHub Actions localmente.
Este script simula as etapas do workflow para garantir que funcionem corretamente.
"""

import os
import sys
import subprocess
import platform
import shutil

def run_command(command, working_dir=None):
    """Execute um comando shell e retorne o resultado."""
    print(f"Executando: {command}")
    
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        universal_newlines=True,
        cwd=working_dir
    )
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        print(f"ERRO (código {process.returncode}):")
        print(stderr)
    else:
        print("SUCESSO!")
        
    return process.returncode, stdout, stderr

def create_runtime_hook():
    """Crie o hook de runtime para o PyInstaller."""
    print("\n=== Criando hook de runtime ===")
    
    # Criar diretório hooks se não existir
    if not os.path.exists("hooks"):
        os.makedirs("hooks")
    
    # Conteúdo do hook de runtime
    hook_content = '''import sys
import os

# Add all module directories to sys.path
module_dirs = [
    "posquantum_modules",
    "posquantum_modules/crypto",
    "posquantum_modules/core",
    "posquantum_modules/network",
    "posquantum_modules/security",
    "posquantum_modules/ui",
    "posquantum_modules/compliance"
]

# Get the base directory of the frozen application
base_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))

# Add each module directory to sys.path
for module_dir in module_dirs:
    full_path = os.path.join(base_dir, module_dir)
    if full_path not in sys.path:
        sys.path.insert(0, full_path)

print("Runtime hook executed successfully")
print("sys.path:", sys.path)
'''
    
    # Escrever o hook de runtime
    with open("hooks/runtime_hook.py", "w") as f:
        f.write(hook_content)
    
    print("Hook de runtime criado com sucesso!")

def install_dependencies():
    """Instale as dependências necessárias."""
    print("\n=== Instalando dependências ===")
    
    # Instalar PyInstaller
    run_command("pip install pyinstaller")
    
    # Instalar PyQt6
    run_command("pip install PyQt6")
    
    # Instalar outras dependências
    if os.path.exists("requirements.txt"):
        run_command("pip install -r requirements.txt")
    else:
        print("Arquivo requirements.txt não encontrado. Pulando instalação de dependências adicionais.")

def build_with_pyinstaller():
    """Construa o executável com PyInstaller."""
    print("\n=== Construindo com PyInstaller ===")
    
    # Comando PyInstaller
    pyinstaller_command = (
        "pyinstaller --clean --noconfirm --onefile "
        "--name=\"PosQuantum\" "
        "--add-data=\"assets;assets\" "
        "--hidden-import=PyQt6.QtCore "
        "--hidden-import=PyQt6.QtGui "
        "--hidden-import=PyQt6.QtWidgets "
        "--hidden-import=posquantum_modules.crypto "
        "--hidden-import=posquantum_modules.core "
        "--hidden-import=posquantum_modules.network "
        "--hidden-import=posquantum_modules.security "
        "--hidden-import=posquantum_modules.ui "
        "--hidden-import=posquantum_modules.compliance "
        "--runtime-hook=hooks/runtime_hook.py "
        "main.py"
    )
    
    # Executar comando PyInstaller
    returncode, stdout, stderr = run_command(pyinstaller_command)
    
    if returncode == 0:
        print("\nExecutável construído com sucesso!")
        
        # Verificar se o executável foi gerado
        executable_path = os.path.join("dist", "PosQuantum.exe" if platform.system() == "Windows" else "PosQuantum")
        if os.path.exists(executable_path):
            print(f"Executável gerado em: {os.path.abspath(executable_path)}")
        else:
            print(f"AVISO: Executável não encontrado em {executable_path}")
    else:
        print("\nErro ao construir o executável!")

def main():
    """Função principal."""
    print("=== Teste do Workflow do GitHub Actions ===")
    
    # Criar hook de runtime
    create_runtime_hook()
    
    # Instalar dependências
    install_dependencies()
    
    # Construir com PyInstaller
    build_with_pyinstaller()
    
    print("\n=== Teste concluído ===")

if __name__ == "__main__":
    main()

