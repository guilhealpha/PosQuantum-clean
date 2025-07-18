#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de Conformidade do PosQuantum

Este módulo gerencia a conformidade do PosQuantum com padrões e certificações
de segurança, incluindo FIPS 140-3, Common Criteria EAL4, ISO 27001 e SOC 2 Type II.

Autor: PosQuantum Team
Data: 18/07/2025
Versão: 3.0
"""

from posquantum_modules.compliance.certifications import (
    CertificationManager,
    Certification,
    CertificationStatus
)

__all__ = [
    'CertificationManager',
    'Certification',
    'CertificationStatus'
]

