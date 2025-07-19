# -*- coding: utf-8 -*-

"""
Módulos Core do PosQuantum

Este módulo contém as implementações core do sistema PosQuantum,
incluindo blockchain, criptografia, dashboard e internacionalização.

Autor: Equipe PosQuantum
Data: 18/07/2025
Versão: 3.0
"""

from .blockchain_real_implementation_clean import BlockchainImplementation
from .crypto_real_implementation_clean import CryptoImplementation
from .dashboard_real_implementation_clean import DashboardImplementation
from .i18n_system import I18NSystem

__all__ = [
    'BlockchainImplementation',
    'CryptoImplementation', 
    'DashboardImplementation',
    'I18NSystem'
]

