#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo de Gerenciamento de Certificações do PosQuantum

Este módulo gerencia e exibe o status das certificações do PosQuantum,
fornecendo uma visão clara da conformidade do sistema com os padrões
de segurança e criptografia.

Autor: PosQuantum Team
Data: 18/07/2025
Versão: 3.0
"""

import os
import json
import logging
from enum import Enum
from typing import Dict, List, Any, Optional

# Configuração de logging
logger = logging.getLogger("posquantum.compliance.certifications")

class CertificationStatus(Enum):
    """Status de uma certificação"""
    NOT_STARTED = "Não Iniciada"
    IN_PROGRESS = "Em Andamento"
    COMPLETED = "Concluída"
    MAINTENANCE = "Em Manutenção"
    EXPIRED = "Expirada"

class Certification:
    """
    Representa uma certificação de segurança ou conformidade
    """
    
    def __init__(self, name: str, description: str, category: str, 
                 cost: str, duration: str, status: CertificationStatus, 
                 details: Optional[Dict[str, Any]] = None):
        """
        Inicializa uma certificação
        
        Args:
            name: Nome da certificação
            description: Descrição da certificação
            category: Categoria da certificação
            cost: Custo estimado da certificação
            duration: Duração estimada do processo
            status: Status atual da certificação
            details: Detalhes adicionais da certificação (opcional)
        """
        self.name = name
        self.description = description
        self.category = category
        self.cost = cost
        self.duration = duration
        self.status = status
        self.details = details if details else {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte a certificação para um dicionário"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "cost": self.cost,
            "duration": self.duration,
            "status": self.status.value,
            "details": self.details
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Certification':
        """Cria uma certificação a partir de um dicionário"""
        status_value = data.get("status", "Não Iniciada")
        status = CertificationStatus(status_value)
        
        return cls(
            name=data["name"],
            description=data["description"],
            category=data["category"],
            cost=data["cost"],
            duration=data["duration"],
            status=status,
            details=data.get("details")
        )

class CertificationManager:
    """
    Gerencia as certificações do PosQuantum
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Inicializa o gerenciador de certificações
        
        Args:
            storage_path: Caminho para o arquivo de armazenamento (opcional)
        """
        self.certifications = []
        self.storage_path = storage_path if storage_path else "certifications.json"
        self._load_certifications()
    
    def _load_certifications(self) -> None:
        """
        Carrega as certificações do arquivo de armazenamento
        """
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.certifications = [Certification.from_dict(cert_data) for cert_data in data]
                logger.info(f"{len(self.certifications)} certificações carregadas de {self.storage_path}")
            except Exception as e:
                logger.error(f"Erro ao carregar certificações: {e}")
                self._initialize_default_certifications()
        else:
            self._initialize_default_certifications()
    
    def _initialize_default_certifications(self) -> None:
        """
        Inicializa as certificações padrão
        """
        self.certifications = [
            # Certificações Gratuitas
            Certification(
                name="NIST Cybersecurity Framework Self-Assessment",
                description="Auto-avaliação de conformidade com o framework de cibersegurança do NIST",
                category="Gratuita",
                cost="$0",
                duration="1-2 semanas",
                status=CertificationStatus.NOT_STARTED
            ),
            Certification(
                name="OpenSSF Scorecard",
                description="Análise automatizada de práticas de desenvolvimento seguro",
                category="Gratuita",
                cost="$0",
                duration="Contínua",
                status=CertificationStatus.NOT_STARTED
            ),
            Certification(
                name="OWASP SAMM Assessment",
                description="Auto-avaliação de maturidade de segurança no desenvolvimento",
                category="Gratuita",
                cost="$0",
                duration="2-4 semanas",
                status=CertificationStatus.NOT_STARTED
            ),
            
            # Certificações de Baixo Custo
            Certification(
                name="Cyber Essentials (Reino Unido)",
                description="Certificação de segurança para acesso a contratos governamentais no Reino Unido",
                category="Baixo Custo",
                cost="£300-500",
                duration="1-2 meses",
                status=CertificationStatus.NOT_STARTED
            ),
            Certification(
                name="Essential 8 (Austrália)",
                description="Certificação de segurança para conformidade com o governo australiano",
                category="Baixo Custo",
                cost="AUD $5.000-15.000",
                duration="2-3 meses",
                status=CertificationStatus.NOT_STARTED
            ),
            
            # Certificações Formais
            Certification(
                name="FIPS 140-3",
                description="Padrão americano e canadense para validação de módulos criptográficos",
                category="Formal",
                cost="$150.000 - $500.000",
                duration="18-24 meses",
                status=CertificationStatus.NOT_STARTED
            ),
            Certification(
                name="Common Criteria EAL4",
                description="Padrão internacional para avaliação de segurança de produtos de TI",
                category="Formal",
                cost="$200.000 - $800.000",
                duration="12-18 meses",
                status=CertificationStatus.NOT_STARTED
            ),
            Certification(
                name="ISO/IEC 27001:2022",
                description="Padrão internacional para sistemas de gestão de segurança da informação",
                category="Formal",
                cost="$50.000 - $150.000",
                duration="6-12 meses",
                status=CertificationStatus.NOT_STARTED
            ),
            Certification(
                name="SOC 2 Type II",
                description="Auditoria de controles de segurança para provedores de serviços",
                category="Formal",
                cost="$75.000 - $200.000",
                duration="6-9 meses",
                status=CertificationStatus.NOT_STARTED
            )
        ]
        
        self.save_certifications()
    
    def save_certifications(self) -> None:
        """
        Salva as certificações no arquivo de armazenamento
        """
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump([cert.to_dict() for cert in self.certifications], f, indent=4, ensure_ascii=False)
            logger.info(f"Certificações salvas em {self.storage_path}")
        except Exception as e:
            logger.error(f"Erro ao salvar certificações: {e}")
    
    def get_all_certifications(self) -> List[Dict[str, Any]]:
        """
        Retorna todas as certificações
        
        Returns:
            Lista de dicionários com informações das certificações
        """
        return [cert.to_dict() for cert in self.certifications]
    
    def get_certification_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Retorna uma certificação pelo nome
        
        Args:
            name: Nome da certificação
            
        Returns:
            Dicionário com informações da certificação ou None se não encontrada
        """
        for cert in self.certifications:
            if cert.name.lower() == name.lower():
                return cert.to_dict()
        
        return None
    
    def update_certification_status(self, name: str, status: CertificationStatus, 
                                     details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Atualiza o status de uma certificação
        
        Args:
            name: Nome da certificação
            status: Novo status da certificação
            details: Detalhes adicionais (opcional)
            
        Returns:
            True se a atualização foi bem-sucedida, False caso contrário
        """
        for cert in self.certifications:
            if cert.name.lower() == name.lower():
                cert.status = status
                if details:
                    cert.details.update(details)
                self.save_certifications()
                logger.info(f"Status da certificação '{name}' atualizado para {status.value}")
                return True
        
        logger.warning(f"Certificação não encontrada: {name}")
        return False
    
    def apply_for_free_certifications(self) -> Dict[str, Any]:
        """
        Aplica para as certificações gratuitas
        
        Returns:
            Dicionário com os resultados da aplicação
        """
        logger.info("Aplicando para certificações gratuitas...")
        
        results = {}
        
        # NIST Cybersecurity Framework Self-Assessment
        self.update_certification_status(
            "NIST Cybersecurity Framework Self-Assessment",
            CertificationStatus.IN_PROGRESS,
            {"start_date": time.strftime("%Y-%m-%d"), "progress": "Iniciando auto-avaliação"}
        )
        results["NIST CSF"] = {"status": "Iniciado", "message": "Auto-avaliação iniciada"}
        
        # OpenSSF Scorecard
        self.update_certification_status(
            "OpenSSF Scorecard",
            CertificationStatus.IN_PROGRESS,
            {"start_date": time.strftime("%Y-%m-%d"), "progress": "Análise automatizada em andamento"}
        )
        results["OpenSSF Scorecard"] = {"status": "Iniciado", "message": "Análise automatizada em andamento"}
        
        # OWASP SAMM Assessment
        self.update_certification_status(
            "OWASP SAMM Assessment",
            CertificationStatus.IN_PROGRESS,
            {"start_date": time.strftime("%Y-%m-%d"), "progress": "Iniciando avaliação de maturidade"}
        )
        results["OWASP SAMM"] = {"status": "Iniciado", "message": "Avaliação de maturidade iniciada"}
        
        return results

# Exemplo de uso
if __name__ == "__main__":
    # Configurar logging
    logging.basicConfig(level=logging.INFO)
    
    # Criar instância do gerenciador de certificações
    cert_manager = CertificationManager()
    
    # Listar todas as certificações
    all_certs = cert_manager.get_all_certifications()
    print("Certificações disponíveis:")
    for cert in all_certs:
        print(f"  - {cert['name']} ({cert['status']})")
    
    # Aplicar para as certificações gratuitas
    apply_results = cert_manager.apply_for_free_certifications()
    print("\nResultados da aplicação para certificações gratuitas:")
    for name, result in apply_results.items():
        print(f"  - {name}: {result['message']}")
    
    # Listar certificações novamente
    all_certs = cert_manager.get_all_certifications()
    print("\nCertificações após aplicação:")
    for cert in all_certs:
        print(f"  - {cert['name']} ({cert['status']})")


