@echo off
echo ========================================
echo PosQuantum Windows Build Script
echo ========================================
echo.

echo Verificando Python...
python --version
if %errorlevel% neq 0 (
    echo ERRO: Python nao encontrado!
    echo Por favor, instale Python 3.10 ou superior
    pause
    exit /b 1
)

echo.
echo Executando build do PosQuantum...
python build_windows.py

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo BUILD CONCLUIDO COM SUCESSO!
    echo ========================================
    echo.
    echo Executavel disponivel em: dist\PosQuantum.exe
    echo.
    echo Pressione qualquer tecla para abrir o diretorio...
    pause >nul
    explorer dist
) else (
    echo.
    echo ========================================
    echo ERRO NO BUILD!
    echo ========================================
    echo.
    echo Verifique os erros acima e tente novamente.
    pause
)

