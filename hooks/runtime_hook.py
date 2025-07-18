# -*- coding: utf-8 -*-
"""
Hook de runtime corrigido para o PosQuantum

Este hook é executado pelo PyInstaller durante a inicialização do aplicativo
para garantir que todos os módulos sejam carregados corretamente.
"""

import os
import sys
import importlib
import importlib.util
import importlib.machinery

# Corrigir sys.path antes de qualquer importação
def fix_sys_path():
    """Corrige sys.path para garantir que todos os módulos sejam encontrados"""
    if hasattr(sys, '_MEIPASS'):
        # Executando a partir do executável PyInstaller
        base_dir = sys._MEIPASS
    else:
        # Executando a partir do script
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Adicionar diretório base ao path
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)
    
    # Adicionar diretórios de módulos ao path
    module_dirs = [
        os.path.join(base_dir, 'posquantum_modules'),
        os.path.join(base_dir, 'posquantum_modules', 'crypto'),
        os.path.join(base_dir, 'posquantum_modules', 'network'),
        os.path.join(base_dir, 'posquantum_modules', 'compliance')
    ]
    
    for module_dir in module_dirs:
        if os.path.exists(module_dir) and module_dir not in sys.path:
            sys.path.insert(0, module_dir)
    
    return base_dir

# Corrigir sys.path
base_dir = fix_sys_path()

# Configurar variáveis de ambiente
os.environ['POSQUANTUM_BASE_DIR'] = base_dir

# Função para importar submódulos
def import_submodules(package_name):
    """Importa todos os submódulos de um pacote"""
    try:
        # Importar pacote
        if package_name in sys.modules:
            package = sys.modules[package_name]
        else:
            package = importlib.import_module(package_name)
        
        # Verificar se o pacote tem path
        if hasattr(package, '__path__'):
            # Iterar sobre submódulos
            for finder, name, is_pkg in importlib.machinery.PathFinder.find_spec(package_name).submodule_search_locations:
                full_name = package_name + '.' + name
                try:
                    importlib.import_module(full_name)
                    if is_pkg:
                        import_submodules(full_name)
                except Exception as e:
                    print(f"Erro ao importar {full_name}: {e}")
    except Exception as e:
        print(f"Erro ao importar submódulos de {package_name}: {e}")

# Importar módulos principais
try:
    # Verificar se os módulos existem
    module_path = os.path.join(base_dir, 'posquantum_modules')
    if os.path.exists(module_path):
        # Importar módulos principais
        import posquantum_modules
        import posquantum_modules.crypto
        import posquantum_modules.network
        import posquantum_modules.compliance
except Exception as e:
    print(f"Erro ao importar módulos principais: {e}")

# Debug completo
print("Runtime hook executado com sucesso")
print(f"sys.path: {sys.path}")
print(f"Diretório base: {base_dir}")
print(f"Módulos disponíveis: {os.listdir(base_dir) if os.path.exists(base_dir) else 'Diretório base não encontrado'}")
