@echo off
echo ===================================
echo  Build do PosQuantum para Windows
echo ===================================
echo.

REM Verificar se Python está instalado
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Erro: Python nao encontrado. Por favor, instale o Python 3.8 ou superior.
    echo Voce pode baixar o Python em: https://www.python.org/downloads/windows/
    pause
    exit /b 1
)

REM Instalar dependências
echo Instalando dependencias...
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Erro ao instalar dependencias.
    pause
    exit /b 1
)

REM Instalar PyInstaller
echo Instalando PyInstaller...
python -m pip install pyinstaller
if %errorlevel% neq 0 (
    echo Erro ao instalar PyInstaller.
    pause
    exit /b 1
)

REM Criar diretório hooks se não existir
if not exist hooks mkdir hooks

REM Criar hook de runtime
echo Criando hook de runtime...
echo # -*- coding: utf-8 -*- > hooks\runtime_hook.py
echo """ >> hooks\runtime_hook.py
echo Hook de runtime corrigido para o PosQuantum >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo Este hook é executado pelo PyInstaller durante a inicialização do aplicativo >> hooks\runtime_hook.py
echo para garantir que todos os módulos sejam carregados corretamente. >> hooks\runtime_hook.py
echo """ >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo import os >> hooks\runtime_hook.py
echo import sys >> hooks\runtime_hook.py
echo import importlib >> hooks\runtime_hook.py
echo import importlib.util >> hooks\runtime_hook.py
echo import importlib.machinery >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo # Corrigir sys.path antes de qualquer importação >> hooks\runtime_hook.py
echo def fix_sys_path(): >> hooks\runtime_hook.py
echo     """Corrige sys.path para garantir que todos os módulos sejam encontrados""" >> hooks\runtime_hook.py
echo     if hasattr(sys, '_MEIPASS'): >> hooks\runtime_hook.py
echo         # Executando a partir do executável PyInstaller >> hooks\runtime_hook.py
echo         base_dir = sys._MEIPASS >> hooks\runtime_hook.py
echo     else: >> hooks\runtime_hook.py
echo         # Executando a partir do script >> hooks\runtime_hook.py
echo         base_dir = os.path.dirname(os.path.abspath(__file__)) >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo     # Adicionar diretório base ao path >> hooks\runtime_hook.py
echo     if base_dir not in sys.path: >> hooks\runtime_hook.py
echo         sys.path.insert(0, base_dir) >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo     # Adicionar diretórios de módulos ao path >> hooks\runtime_hook.py
echo     module_dirs = [ >> hooks\runtime_hook.py
echo         os.path.join(base_dir, 'posquantum_modules'), >> hooks\runtime_hook.py
echo         os.path.join(base_dir, 'posquantum_modules', 'crypto'), >> hooks\runtime_hook.py
echo         os.path.join(base_dir, 'posquantum_modules', 'network'), >> hooks\runtime_hook.py
echo         os.path.join(base_dir, 'posquantum_modules', 'compliance'), >> hooks\runtime_hook.py
echo         os.path.join(base_dir, 'posquantum_modules', 'core'), >> hooks\runtime_hook.py
echo         os.path.join(base_dir, 'posquantum_modules', 'security'), >> hooks\runtime_hook.py
echo         os.path.join(base_dir, 'posquantum_modules', 'ui') >> hooks\runtime_hook.py
echo     ] >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo     for module_dir in module_dirs: >> hooks\runtime_hook.py
echo         if os.path.exists(module_dir) and module_dir not in sys.path: >> hooks\runtime_hook.py
echo             sys.path.insert(0, module_dir) >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo     return base_dir >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo # Corrigir sys.path >> hooks\runtime_hook.py
echo base_dir = fix_sys_path() >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo # Configurar variáveis de ambiente >> hooks\runtime_hook.py
echo os.environ['POSQUANTUM_BASE_DIR'] = base_dir >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo # Importar módulos principais >> hooks\runtime_hook.py
echo try: >> hooks\runtime_hook.py
echo     # Verificar se os módulos existem >> hooks\runtime_hook.py
echo     module_path = os.path.join(base_dir, 'posquantum_modules') >> hooks\runtime_hook.py
echo     if os.path.exists(module_path): >> hooks\runtime_hook.py
echo         # Importar módulos principais >> hooks\runtime_hook.py
echo         import posquantum_modules >> hooks\runtime_hook.py
echo         import posquantum_modules.crypto >> hooks\runtime_hook.py
echo         import posquantum_modules.network >> hooks\runtime_hook.py
echo         import posquantum_modules.compliance >> hooks\runtime_hook.py
echo         import posquantum_modules.core >> hooks\runtime_hook.py
echo         import posquantum_modules.security >> hooks\runtime_hook.py
echo         import posquantum_modules.ui >> hooks\runtime_hook.py
echo except Exception as e: >> hooks\runtime_hook.py
echo     print(f"Erro ao importar módulos principais: {e}") >> hooks\runtime_hook.py
echo. >> hooks\runtime_hook.py
echo # Debug completo >> hooks\runtime_hook.py
echo print("Runtime hook executado com sucesso") >> hooks\runtime_hook.py
echo print(f"sys.path: {sys.path}") >> hooks\runtime_hook.py
echo print(f"Diretório base: {base_dir}") >> hooks\runtime_hook.py
echo print(f"Módulos disponíveis: {os.listdir(base_dir) if os.path.exists(base_dir) else 'Diretório base não encontrado'}") >> hooks\runtime_hook.py

REM Executar PyInstaller
echo Executando PyInstaller...
python -m PyInstaller --clean --noconfirm --onefile --name="PosQuantum-3.0" --add-data="assets;assets" --add-data="posquantum_modules;posquantum_modules" ^
--hidden-import="PyQt6.QtCore" ^
--hidden-import="PyQt6.QtGui" ^
--hidden-import="PyQt6.QtWidgets" ^
--hidden-import="posquantum_modules.crypto" ^
--hidden-import="posquantum_modules.network" ^
--hidden-import="posquantum_modules.compliance" ^
--hidden-import="posquantum_modules.core" ^
--hidden-import="posquantum_modules.security" ^
--hidden-import="posquantum_modules.ui" ^
--hidden-import="posquantum_modules.crypto.ml_kem" ^
--hidden-import="posquantum_modules.crypto.ml_dsa" ^
--hidden-import="posquantum_modules.crypto.sphincs_plus" ^
--hidden-import="posquantum_modules.crypto.elliptic_curve_pq_hybrid" ^
--hidden-import="posquantum_modules.crypto.hsm_virtual" ^
--hidden-import="posquantum_modules.network.vpn_pq" ^
--hidden-import="posquantum_modules.compliance.certifications" ^
--hidden-import="posquantum_modules.core.blockchain_real_implementation_clean" ^
--hidden-import="posquantum_modules.core.crypto_real_implementation_clean" ^
--hidden-import="posquantum_modules.core.dashboard_real_implementation_clean" ^
--hidden-import="posquantum_modules.core.i18n_system" ^
--runtime-hook="hooks\runtime_hook.py" main.py
if %errorlevel% neq 0 (
    echo Erro ao executar PyInstaller.
    pause
    exit /b 1
)

echo.
echo Build concluido com sucesso!
echo O executavel foi gerado em: dist\PosQuantum-3.0.exe
echo.
pause

