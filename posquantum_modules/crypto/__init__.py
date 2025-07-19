# -*- coding: utf-8 -*-

"""
Módulo de Criptografia Pós-Quântica PosQuantum

Este módulo contém todas as implementações de algoritmos criptográficos pós-quânticos
em conformidade com os padrões NIST FIPS 203, 204 e 205.

Autor: Equipe PosQuantum
Data: 18/07/2025
Versão: 3.0
"""

# Importações das implementações principais
from .ml_kem import MLKEMImplementation, SecurityLevel as MLKEMSecurityLevel
from .ml_dsa import MLDSAImplementation, SecurityLevel as MLDSASecurityLevel
from .sphincs_plus import SPHINCSPlusImplementation, SecurityLevel as SPHINCSSecurityLevel, HashFunction
from .elliptic_curve_pq_hybrid import EllipticCurvePQHybrid
from .hsm_virtual import HSMVirtual

# Aliases para compatibilidade
MLKEM = MLKEMImplementation
MLDSA = MLDSAImplementation
SPHINCSPlus = SPHINCSPlusImplementation

__all__ = [
    'MLKEMImplementation',
    'MLDSAImplementation', 
    'SPHINCSPlusImplementation',
    'EllipticCurvePQHybrid',
    'HSMVirtual',
    'MLKEM',
    'MLDSA',
    'SPHINCSPlus',
    'MLKEMSecurityLevel',
    'MLDSASecurityLevel',
    'SPHINCSSecurityLevel',
    'HashFunction'
]

