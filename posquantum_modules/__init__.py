# -*- coding: utf-8 -*-

"""
PosQuantum Modules - Módulos de Criptografia Pós-Quântica

Este pacote contém todas as implementações de criptografia pós-quântica,
rede, conformidade e funcionalidades core do sistema PosQuantum.

Autor: Equipe PosQuantum
Data: 18/07/2025
Versão: 3.0
"""

__version__ = "3.0"
__author__ = "Equipe PosQuantum"

# Importações principais para facilitar o acesso
from . import crypto
from . import network
from . import compliance

# Disponibilizar as classes principais diretamente
from .crypto import (
    MLKEMImplementation,
    MLDSAImplementation,
    SPHINCSPlusImplementation,
    EllipticCurvePQHybrid,
    HSMVirtual
)

from .network import VPNPostQuantum
from .compliance import CertificationManager

__all__ = [
    'crypto',
    'network', 
    'compliance',
    'MLKEMImplementation',
    'MLDSAImplementation',
    'SPHINCSPlusImplementation',
    'EllipticCurvePQHybrid',
    'HSMVirtual',
    'VPNPostQuantum',
    'CertificationManager'
]

