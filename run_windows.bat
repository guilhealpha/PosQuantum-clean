@echo off
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
