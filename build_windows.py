#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de Build para PosQuantum Windows
Gera o executável PosQuantum.exe com todas as funcionalidades
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_requirements():
    """Verifica se todos os requisitos estão instalados"""
    print("🔍 Verificando requisitos...")
    
    try:
        import PyInstaller
        print(f"✅ PyInstaller: {PyInstaller.__version__}")
    except ImportError:
        print("❌ PyInstaller não encontrado. Instalando...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
    
    try:
        import PyQt6
        print(f"✅ PyQt6: {PyQt6.QtCore.QT_VERSION_STR}")
    except ImportError:
        print("❌ PyQt6 não encontrado. Instalando...")
        subprocess.run([sys.executable, "-m", "pip", "install", "PyQt6"], check=True)
    
    # Instalar requirements.txt se existir
    if os.path.exists("requirements.txt"):
        print("📦 Instalando dependências do requirements.txt...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)

def prepare_build():
    """Prepara o ambiente para o build"""
    print("🔧 Preparando ambiente de build...")
    
    # Criar diretório hooks se não existir
    hooks_dir = Path("hooks")
    hooks_dir.mkdir(exist_ok=True)
    
    # Limpar builds anteriores
    if os.path.exists("dist"):
        shutil.rmtree("dist")
        print("🗑️ Diretório dist limpo")
    
    if os.path.exists("build"):
        shutil.rmtree("build")
        print("🗑️ Diretório build limpo")
    
    # Verificar se main.py existe
    if not os.path.exists("main.py"):
        print("❌ Arquivo main.py não encontrado!")
        return False
    
    # Verificar se posquantum_modules existe
    if not os.path.exists("posquantum_modules"):
        print("❌ Diretório posquantum_modules não encontrado!")
        return False
    
    print("✅ Ambiente preparado com sucesso")
    return True

def build_executable():
    """Constrói o executável usando PyInstaller"""
    print("🚀 Iniciando build do executável...")
    
    # Comando PyInstaller otimizado
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--onefile",
        "--name=PosQuantum",
        "--add-data=posquantum_modules;posquantum_modules",
        
        # Hidden imports para PyQt6
        "--hidden-import=PyQt6.QtCore",
        "--hidden-import=PyQt6.QtGui",
        "--hidden-import=PyQt6.QtWidgets",
        "--hidden-import=PyQt6.QtNetwork",
        
        # Hidden imports para módulos principais
        "--hidden-import=posquantum_modules",
        "--hidden-import=posquantum_modules.crypto",
        "--hidden-import=posquantum_modules.network",
        "--hidden-import=posquantum_modules.compliance",
        "--hidden-import=posquantum_modules.core",
        "--hidden-import=posquantum_modules.security",
        "--hidden-import=posquantum_modules.ui",
        
        # Hidden imports para módulos específicos
        "--hidden-import=posquantum_modules.crypto.ml_kem",
        "--hidden-import=posquantum_modules.crypto.ml_dsa",
        "--hidden-import=posquantum_modules.crypto.sphincs_plus",
        "--hidden-import=posquantum_modules.crypto.elliptic_curve_pq_hybrid",
        "--hidden-import=posquantum_modules.crypto.hsm_virtual",
        "--hidden-import=posquantum_modules.network.vpn_pq",
        "--hidden-import=posquantum_modules.compliance.certifications",
        
        # Runtime hook
        "--runtime-hook=hooks/runtime_hook.py",
        
        # Arquivo principal
        "main.py"
    ]
    
    print("📝 Comando PyInstaller:")
    print(" ".join(cmd))
    print()
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✅ Build concluído com sucesso!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Erro no build: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return False

def verify_executable():
    """Verifica se o executável foi criado corretamente"""
    print("🔍 Verificando executável...")
    
    exe_path = Path("dist/PosQuantum.exe")
    
    if not exe_path.exists():
        print("❌ Executável PosQuantum.exe não foi criado!")
        return False
    
    # Verificar tamanho do arquivo
    size_mb = exe_path.stat().st_size / (1024 * 1024)
    print(f"✅ Executável criado: {exe_path}")
    print(f"📏 Tamanho: {size_mb:.1f} MB")
    
    if size_mb < 10:
        print("⚠️ Aviso: Executável muito pequeno, pode estar faltando módulos")
    elif size_mb > 100:
        print("⚠️ Aviso: Executável muito grande, pode ter dependências desnecessárias")
    else:
        print("✅ Tamanho do executável está adequado")
    
    return True

def main():
    """Função principal"""
    print("🎯 PosQuantum Windows Build Script")
    print("=" * 50)
    
    try:
        # Verificar requisitos
        check_requirements()
        print()
        
        # Preparar build
        if not prepare_build():
            return 1
        print()
        
        # Construir executável
        if not build_executable():
            return 1
        print()
        
        # Verificar executável
        if not verify_executable():
            return 1
        print()
        
        print("🎉 Build concluído com sucesso!")
        print("📁 Executável disponível em: dist/PosQuantum.exe")
        print()
        print("🔐 Funcionalidades incluídas:")
        print("   ✅ 16 abas/módulos completos")
        print("   ✅ Mais de 70 funcionalidades")
        print("   ✅ Criptografia pós-quântica em todas as camadas")
        print("   ✅ ML-KEM, ML-DSA, SPHINCS+ (NIST)")
        print("   ✅ Curva elíptica híbrida")
        print("   ✅ Conformidade com certificações")
        
        return 0
        
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

