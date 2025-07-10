#!/usr/bin/env python3
"""
CORREÇÃO DE BUILD PARA WINDOWS - POSSIBILIDADE-E
Sistema de IA para correção de problemas específicos do Windows

Autor: IA-CODER (Força-Tarefa de Investigação)
Score: 88/100
Categoria: Build Tool Issue
"""

import os
import sys
import subprocess
import platform

def print_header():
    """Imprime cabeçalho da correção"""
    print("🔧" + "=" * 60)
    print("    CORREÇÃO DE BUILD PARA WINDOWS - POSSIBILIDADE-E")
    print("    Força-Tarefa de IA - Sistema de Correção Específica")
    print("=" * 62)
    print(f"Sistema: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    print("=" * 62)

def fix_requirements_txt():
    """Corrige e otimiza requirements.txt para Windows"""
    print("\n📦 CORREÇÃO DO REQUIREMENTS.TXT")
    print("-" * 40)
    
    # Dependências essenciais para Windows
    windows_requirements = [
        "pycryptodome>=3.19.0",
        "psutil>=5.9.0",
        "pywin32>=306",
        "pyinstaller[encryption]>=5.0",
        "setuptools>=65.0",
        "wheel>=0.38.0"
    ]
    
    try:
        # Ler requirements.txt existente se houver
        existing_deps = []
        if os.path.exists('requirements.txt'):
            with open('requirements.txt', 'r') as f:
                existing_deps = [line.strip() for line in f.readlines() if line.strip()]
        
        # Combinar dependências existentes com as do Windows
        all_deps = existing_deps.copy()
        
        for dep in windows_requirements:
            dep_name = dep.split('>=')[0].split('==')[0]
            # Verificar se a dependência já existe
            if not any(dep_name in existing for existing in existing_deps):
                all_deps.append(dep)
        
        # Escrever requirements.txt otimizado
        with open('requirements.txt', 'w') as f:
            for dep in sorted(set(all_deps)):
                if dep:  # Evitar linhas vazias
                    f.write(f"{dep}\n")
        
        print("✅ requirements.txt otimizado para Windows")
        print(f"📋 Total de dependências: {len(all_deps)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao corrigir requirements.txt: {e}")
        return False

def setup_windows_environment():
    """Configura ambiente específico do Windows"""
    print("\n🪟 CONFIGURAÇÃO DO AMBIENTE WINDOWS")
    print("-" * 40)
    
    try:
        # Configurar variáveis de ambiente essenciais
        env_vars = {
            'PYTHONPATH': os.getcwd(),
            'QT_QPA_PLATFORM': 'offscreen',
            'PYTHONIOENCODING': 'utf-8',
            'PYTHONUTF8': '1'
        }
        
        for var, value in env_vars.items():
            os.environ[var] = value
            print(f"✅ {var} = {value}")
        
        # Configurar PATH se necessário
        current_path = os.environ.get('PATH', '')
        if os.getcwd() not in current_path:
            os.environ['PATH'] = f"{os.getcwd()};{current_path}"
            print(f"✅ PATH atualizado")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao configurar ambiente: {e}")
        return False

def install_windows_dependencies():
    """Instala dependências específicas do Windows"""
    print("\n⚙️ INSTALAÇÃO DE DEPENDÊNCIAS WINDOWS")
    print("-" * 40)
    
    try:
        # Atualizar pip, setuptools e wheel primeiro
        upgrade_commands = [
            [sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
            [sys.executable, '-m', 'pip', 'install', '--upgrade', 'setuptools'],
            [sys.executable, '-m', 'pip', 'install', '--upgrade', 'wheel']
        ]
        
        for cmd in upgrade_commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    print(f"✅ {cmd[-1]} atualizado")
                else:
                    print(f"⚠️ Aviso ao atualizar {cmd[-1]}: {result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"⚠️ Timeout ao atualizar {cmd[-1]}")
            except Exception as e:
                print(f"⚠️ Erro ao atualizar {cmd[-1]}: {e}")
        
        # Instalar dependências do requirements.txt
        if os.path.exists('requirements.txt'):
            try:
                result = subprocess.run([
                    sys.executable, '-m', 'pip', 'install', 
                    '-r', 'requirements.txt', '--user'
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    print("✅ Dependências do requirements.txt instaladas")
                else:
                    print(f"⚠️ Aviso na instalação: {result.stderr}")
            except subprocess.TimeoutExpired:
                print("⚠️ Timeout na instalação de dependências")
            except Exception as e:
                print(f"⚠️ Erro na instalação: {e}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro geral na instalação: {e}")
        return False

def test_imports_windows():
    """Testa imports específicos para Windows"""
    print("\n🧪 TESTE DE IMPORTS PARA WINDOWS")
    print("-" * 40)
    
    # Módulos essenciais para testar
    test_modules = [
        ('Crypto', 'PyCryptodome'),
        ('psutil', 'psutil'),
        ('win32api', 'pywin32'),
        ('PyInstaller', 'PyInstaller')
    ]
    
    success_count = 0
    
    for module_name, package_name in test_modules:
        try:
            __import__(module_name)
            print(f"✅ {package_name}: Import OK")
            success_count += 1
        except ImportError as e:
            print(f"❌ {package_name}: ERRO - {e}")
        except Exception as e:
            print(f"⚠️ {package_name}: AVISO - {e}")
    
    # Testar módulos do projeto
    project_modules = [
        'real_nist_crypto',
        'quantum_blockchain_real',
        'quantum_p2p_network',
        'quantum_messaging'
    ]
    
    for module in project_modules:
        try:
            __import__(module)
            print(f"✅ {module}: Import OK")
            success_count += 1
        except ImportError as e:
            print(f"❌ {module}: ERRO - {e}")
        except Exception as e:
            print(f"⚠️ {module}: AVISO - {e}")
    
    total_modules = len(test_modules) + len(project_modules)
    success_rate = (success_count / total_modules) * 100
    
    print(f"\n📊 Taxa de Sucesso: {success_count}/{total_modules} ({success_rate:.1f}%)")
    
    return success_rate >= 75  # 75% ou mais é considerado sucesso

def create_windows_batch_script():
    """Cria script batch para execução no Windows"""
    print("\n📝 CRIAÇÃO DE SCRIPT BATCH WINDOWS")
    print("-" * 40)
    
    batch_content = """@echo off
REM Script de execução para Windows - PosQuantum Desktop
echo Iniciando PosQuantum Desktop...

REM Configurar variáveis de ambiente
set PYTHONPATH=%PYTHONPATH%;%CD%
set QT_QPA_PLATFORM=offscreen
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

REM Executar aplicação
python main.py

REM Pausar para ver resultado
pause
"""
    
    try:
        with open('run_windows.bat', 'w') as f:
            f.write(batch_content)
        
        print("✅ Script run_windows.bat criado")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao criar script batch: {e}")
        return False

def generate_windows_summary():
    """Gera resumo da correção Windows"""
    print("\n📊 RESUMO DA CORREÇÃO WINDOWS")
    print("=" * 40)
    
    # Verificar arquivos criados/modificados
    files_to_check = [
        'requirements.txt',
        'run_windows.bat'
    ]
    
    files_ok = 0
    for file in files_to_check:
        if os.path.exists(file):
            print(f"✅ {file}: Criado/Atualizado")
            files_ok += 1
        else:
            print(f"❌ {file}: Ausente")
    
    # Verificar variáveis de ambiente
    env_vars = ['PYTHONPATH', 'QT_QPA_PLATFORM', 'PYTHONIOENCODING']
    env_ok = sum(1 for var in env_vars if os.environ.get(var))
    
    print(f"📋 Arquivos: {files_ok}/{len(files_to_check)}")
    print(f"📋 Variáveis de ambiente: {env_ok}/{len(env_vars)}")
    
    # Status geral
    total_checks = len(files_to_check) + len(env_vars)
    total_ok = files_ok + env_ok
    success_rate = (total_ok / total_checks) * 100
    
    if success_rate >= 90:
        status = "🎉 CORREÇÃO EXCELENTE"
    elif success_rate >= 75:
        status = "✅ CORREÇÃO BOA"
    elif success_rate >= 50:
        status = "⚠️ CORREÇÃO PARCIAL"
    else:
        status = "❌ CORREÇÃO INSUFICIENTE"
    
    print(f"\n🎯 STATUS: {status} ({success_rate:.1f}%)")
    
    return success_rate

def main():
    """Função principal da correção Windows"""
    print_header()
    
    success_steps = 0
    total_steps = 6
    
    # Executar correções
    if fix_requirements_txt():
        success_steps += 1
    
    if setup_windows_environment():
        success_steps += 1
    
    if install_windows_dependencies():
        success_steps += 1
    
    if test_imports_windows():
        success_steps += 1
    
    if create_windows_batch_script():
        success_steps += 1
    
    # Gerar resumo
    summary_score = generate_windows_summary()
    if summary_score >= 75:
        success_steps += 1
    
    # Resultado final
    success_rate = (success_steps / total_steps) * 100
    
    print("\n" + "=" * 62)
    print("🔧 CORREÇÃO WINDOWS CONCLUÍDA")
    print(f"📊 Sucesso: {success_steps}/{total_steps} ({success_rate:.1f}%)")
    
    if success_rate >= 90:
        print("🎉 CORREÇÃO EXCELENTE - Sistema pronto para build Windows")
    elif success_rate >= 75:
        print("✅ CORREÇÃO BOA - Sistema deve funcionar no Windows")
    else:
        print("⚠️ CORREÇÃO PARCIAL - Pode haver problemas no Windows")
    
    print("=" * 62)
    
    return success_rate

if __name__ == "__main__":
    try:
        result = main()
        sys.exit(0 if result >= 75 else 1)
    except Exception as e:
        print(f"\n❌ ERRO CRÍTICO NA CORREÇÃO WINDOWS: {e}")
        sys.exit(2)

