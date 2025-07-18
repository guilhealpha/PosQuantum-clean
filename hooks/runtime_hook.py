# -*- coding: utf-8 -*-
"""
Runtime Hook para PosQuantum
Corrige o sys.path para garantir que todos os módulos sejam encontrados
"""

import os
import sys

def setup_posquantum_paths():
    """Configura os caminhos necessários para o PosQuantum"""
    
    # Determinar diretório base
    if hasattr(sys, '_MEIPASS'):
        # Executando a partir do executável PyInstaller
        base_dir = sys._MEIPASS
        print(f"[PosQuantum] Executando do executável PyInstaller: {base_dir}")
    else:
        # Executando a partir do script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"[PosQuantum] Executando do script: {base_dir}")
    
    # Adicionar diretório base ao path se não estiver presente
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)
        print(f"[PosQuantum] Adicionado ao sys.path: {base_dir}")
    
    # Definir diretórios de módulos
    module_dirs = [
        os.path.join(base_dir, 'posquantum_modules'),
        os.path.join(base_dir, 'posquantum_modules', 'crypto'),
        os.path.join(base_dir, 'posquantum_modules', 'network'),
        os.path.join(base_dir, 'posquantum_modules', 'compliance'),
        os.path.join(base_dir, 'posquantum_modules', 'core'),
        os.path.join(base_dir, 'posquantum_modules', 'security'),
        os.path.join(base_dir, 'posquantum_modules', 'ui')
    ]
    
    # Adicionar cada diretório de módulo ao path
    for module_dir in module_dirs:
        if os.path.exists(module_dir) and module_dir not in sys.path:
            sys.path.insert(0, module_dir)
            print(f"[PosQuantum] Adicionado módulo ao sys.path: {module_dir}")
    
    # Configurar variáveis de ambiente
    os.environ['POSQUANTUM_BASE_DIR'] = base_dir
    os.environ['POSQUANTUM_MODULES_DIR'] = os.path.join(base_dir, 'posquantum_modules')
    
    # Verificar se os módulos principais existem
    main_modules = [
        'posquantum_modules.crypto.ml_kem',
        'posquantum_modules.crypto.ml_dsa',
        'posquantum_modules.crypto.sphincs_plus',
        'posquantum_modules.crypto.elliptic_curve_pq_hybrid',
        'posquantum_modules.crypto.hsm_virtual',
        'posquantum_modules.network.vpn_pq',
        'posquantum_modules.compliance.certifications'
    ]
    
    print("[PosQuantum] Verificando módulos principais...")
    for module_name in main_modules:
        try:
            module_path = module_name.replace('.', os.sep) + '.py'
            full_path = os.path.join(base_dir, module_path)
            if os.path.exists(full_path):
                print(f"[PosQuantum] ✅ Módulo encontrado: {module_name}")
            else:
                print(f"[PosQuantum] ⚠️ Módulo não encontrado: {module_name} ({full_path})")
        except Exception as e:
            print(f"[PosQuantum] ❌ Erro ao verificar módulo {module_name}: {e}")
    
    print(f"[PosQuantum] Runtime hook configurado com sucesso!")
    print(f"[PosQuantum] sys.path atual: {len(sys.path)} entradas")
    print(f"[PosQuantum] Diretório base: {base_dir}")
    
    return base_dir

# Executar configuração
try:
    setup_posquantum_paths()
except Exception as e:
    print(f"[PosQuantum] ERRO no runtime hook: {e}")
    import traceback
    traceback.print_exc()

