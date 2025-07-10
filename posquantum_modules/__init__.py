#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ PosQuantum Modules - Pacote Principal
Arquivo: __init__.py
Descrição: Inicialização do pacote de módulos pós-quânticos
Autor: QuantumShield Team
Versão: 2.0
"""

__version__ = "2.0.0"
__author__ = "QuantumShield Team"
__description__ = "Primeiro Software Desktop 100% Pós-Quântico do Mundo"

# Importações principais do pacote
try:
    from .core import *
except ImportError:
    # Fallback silencioso se módulos core não estiverem disponíveis
    pass

# Metadados do pacote
__all__ = [
    'core',
    '__version__',
    '__author__',
    '__description__'
]

