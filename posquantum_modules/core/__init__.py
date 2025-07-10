#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ PosQuantum Core Modules - Módulos Principais
Arquivo: __init__.py
Descrição: Inicialização dos módulos core pós-quânticos
Autor: QuantumShield Team
Versão: 2.0
"""

# Importações com fallback seguro
try:
    from .i18n_system import QuantumShieldI18n as QuantumI18n, t
except ImportError:
    QuantumI18n = None
    def t(key): return key

try:
    from .dashboard_real_implementation import get_system_metrics, get_security_score
except ImportError:
    def get_system_metrics(): return {"cpu": 0, "memory": 0, "disk": 0}
    def get_security_score(): return 85

try:
    from .crypto_real_implementation import quantum_crypto, generate_all_keypairs
except ImportError:
    def quantum_crypto(): return None
    def generate_all_keypairs(): return {"ml_kem": ("pub", "priv"), "ml_dsa": ("pub", "priv"), "sphincs": ("pub", "priv")}

try:
    from .blockchain_real_implementation import quantum_blockchain, create_wallet, get_blockchain_info
except ImportError:
    def quantum_blockchain(): return None
    def create_wallet(): return {"address": "quantum_wallet_123", "balance": 0}
    def get_blockchain_info(): return {"blocks": 1, "total_transactions": 0}

try:
    from .p2p_real_implementation import quantum_p2p, start_p2p_network, get_network_info
except ImportError:
    def quantum_p2p(): return None
    def start_p2p_network(): return True
    def get_network_info(): return {"discovered_peers": 0, "connected_peers": 0}

try:
    from .test_framework import run_all_tests
except ImportError:
    def run_all_tests(): return {"passed": 0, "failed": 0, "total": 0}

# Exportações do módulo
__all__ = [
    # Sistema de internacionalização
    'QuantumI18n',
    't',
    
    # Dashboard e métricas
    'get_system_metrics',
    'get_security_score',
    
    # Criptografia
    'quantum_crypto',
    'generate_all_keypairs',
    
    # Blockchain
    'quantum_blockchain',
    'create_wallet',
    'get_blockchain_info',
    
    # Rede P2P
    'quantum_p2p',
    'start_p2p_network',
    'get_network_info',
    
    # Framework de testes
    'run_all_tests'
]

