#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🌐 QuantumShield i18n System - Internacionalização
Arquivo: i18n_system.py
Descrição: Sistema de tradução para Português e Inglês
Autor: QuantumShield Team
Versão: 2.0
"""

import json
import os
from typing import Dict, Any

class QuantumShieldI18n:
    """Sistema de internacionalização do QuantumShield"""
    
    def __init__(self, default_language: str = "pt_BR"):
        self.current_language = default_language
        self.translations = {}
        self.load_translations()
    
    def load_translations(self):
        """Carregar traduções"""
        self.translations = {
            "pt_BR": self.get_portuguese_translations(),
            "en_US": self.get_english_translations()
        }
    
    def get_portuguese_translations(self) -> Dict[str, Any]:
        """Traduções em Português"""
        return {
            # Interface Principal
            "app_title": "QuantumShield Desktop v2.0 - 100% Pós-Quântico",
            "status_ready": "✅ QuantumShield Desktop iniciado - Proteção pós-quântica ativa",
            
            # Abas
            "tab_dashboard": "📊 Dashboard",
            "tab_crypto": "🔐 Criptografia",
            "tab_blockchain": "⛓️ Blockchain",
            "tab_p2p": "🌐 Rede P2P",
            "tab_communication": "📞 Comunicação",
            "tab_email": "📧 Email",
            "tab_satellite": "🛰️ Satélite",
            "tab_ai": "🤖 IA",
            "tab_enterprise": "🏢 Empresarial",
            "tab_storage": "💾 Storage",
            "tab_identity": "🆔 Identidade",
            "tab_analytics": "📊 Analytics",
            "tab_security": "🔒 Segurança",
            "tab_connectivity": "🌐 Conectividade",
            "tab_certifications": "📜 Certificações",
            "tab_governance": "🏛️ Governança",
            
            # Dashboard
            "dashboard_title": "📊 Dashboard Executivo - Métricas em Tempo Real",
            "dashboard_system_metrics": "Métricas do Sistema",
            "dashboard_modules_status": "Status dos Módulos",
            "dashboard_activity_logs": "Logs de Atividade",
            "dashboard_security_score": "Score de Segurança",
            "dashboard_cpu": "CPU",
            "dashboard_ram": "RAM",
            "dashboard_network": "Rede",
            "dashboard_loading": "Carregando...",
            "dashboard_security_active": "95% - Proteção Pós-Quântica Ativa",
            
            # Criptografia
            "crypto_title": "🔐 Criptografia Pós-Quântica NIST",
            "crypto_generate_kem": "Gerar Chaves ML-KEM-768",
            "crypto_generate_dsa": "Gerar Chaves ML-DSA-65",
            "crypto_generate_sphincs": "Gerar Chaves SPHINCS+",
            "crypto_encrypt_files": "Criptografar Arquivos",
            "crypto_sign_documents": "Assinar Documentos",
            "crypto_verify_integrity": "Verificar Integridade",
            "crypto_results_placeholder": "Resultados das operações criptográficas aparecerão aqui...",
            "crypto_generating_kem": "🔐 Gerando chaves ML-KEM-768...",
            "crypto_kem_success": "✅ Chaves ML-KEM-768 geradas com sucesso!",
            "crypto_generating_dsa": "🔐 Gerando chaves ML-DSA-65...",
            "crypto_dsa_success": "✅ Chaves ML-DSA-65 geradas com sucesso!",
            "crypto_generating_sphincs": "🔐 Gerando chaves SPHINCS+...",
            "crypto_sphincs_success": "✅ Chaves SPHINCS+ geradas com sucesso!",
            "crypto_encrypting_file": "🔒 Criptografando arquivo",
            "crypto_file_encrypted": "✅ Arquivo criptografado com ML-KEM-768!",
            "crypto_signing_document": "✍️ Assinando documento",
            "crypto_document_signed": "✅ Documento assinado com ML-DSA-65!",
            "crypto_verifying_integrity": "🔍 Verificando integridade",
            "crypto_integrity_verified": "✅ Integridade verificada com SHA3-512!",
            
            # Blockchain
            "blockchain_title": "⛓️ Blockchain QuantumCoin - 3 Criptomoedas",
            "blockchain_wallets": "Carteiras",
            "blockchain_qtc": "🥇 QuantumCoin (QTC):",
            "blockchain_qtg": "🥈 QuantumGold (QTG):",
            "blockchain_qts": "🥉 QuantumSilver (QTS):",
            "blockchain_transfer": "Transferir Moedas",
            "blockchain_mine": "Iniciar Mineração",
            "blockchain_explorer": "Explorer Blockchain",
            "blockchain_contracts": "Smart Contracts",
            "blockchain_governance": "Votação Governance",
            "blockchain_staking": "Staking QTG",
            "blockchain_history": "Histórico de Transações",
            "blockchain_history_date": "Data",
            "blockchain_history_type": "Tipo",
            "blockchain_history_currency": "Moeda",
            "blockchain_history_amount": "Quantidade",
            "blockchain_history_status": "Status",
            
            # P2P
            "p2p_title": "🌐 Rede P2P - Mesh Network Pós-Quântica",
            "p2p_network_status": "Status da Rede",
            "p2p_peers_connected": "Peers Conectados",
            "p2p_status": "Status",
            "p2p_disconnected": "Desconectado",
            "p2p_discovering": "Descobrindo...",
            "p2p_discover": "Descobrir Rede",
            "p2p_chat": "Chat Criptografado",
            "p2p_files": "Transferir Arquivos",
            "p2p_browser": "Navegador P2P",
            "p2p_streaming": "Streaming P2P",
            "p2p_vpn": "VPN Mesh",
            "p2p_peers_discovered": "Peers Descobertos",
            
            # Mensagens de implementação
            "implementation_communication": "Interface de comunicação será implementada no Sprint 3",
            "implementation_email": "Cliente email será implementado no Sprint 3",
            "implementation_satellite": "Funcionalidades de satélite serão implementadas no Sprint 4",
            "implementation_ai": "IA inteligente será implementada no Sprint 4",
            "implementation_enterprise": "Funcionalidades empresariais serão implementadas no Sprint 4",
            "implementation_storage": "Storage distribuído será implementado no Sprint 3",
            "implementation_identity": "Identidade quântica será implementada no Sprint 4",
            "implementation_analytics": "Analytics será implementado no Sprint 4",
            "implementation_security": "Segurança avançada será implementada no Sprint 4",
            "implementation_connectivity": "Conectividade será implementada no Sprint 3",
            "implementation_certifications": "Certificações serão implementadas no Sprint 5",
            "implementation_governance": "Governança será implementada no Sprint 5",
            
            # Diálogos
            "dialog_transfer_title": "Transferência",
            "dialog_transfer_message": "Interface de transferência será implementada no Sprint 3",
            "dialog_mining_title": "Mineração",
            "dialog_mining_message": "Mineração distribuída será implementada no Sprint 3",
            "dialog_explorer_title": "Explorer",
            "dialog_explorer_message": "Explorer blockchain será implementado no Sprint 3",
            "dialog_contracts_title": "Smart Contracts",
            "dialog_contracts_message": "Smart contracts serão implementados no Sprint 3",
            "dialog_governance_title": "Governance",
            "dialog_governance_message": "Sistema de governance será implementado no Sprint 5",
            "dialog_staking_title": "Staking",
            "dialog_staking_message": "Staking QTG será implementado no Sprint 3",
            "dialog_discovery_title": "Descoberta",
            "dialog_discovery_message": "Descoberta de rede será implementada no Sprint 2",
            "dialog_chat_title": "Chat",
            "dialog_chat_message": "Chat criptografado será implementado no Sprint 2",
            "dialog_files_title": "Arquivos",
            "dialog_files_message": "Transferência P2P será implementada no Sprint 3",
            "dialog_browser_title": "Navegador P2P",
            "dialog_browser_message": "Navegador P2P será implementado no Sprint 3",
            "dialog_streaming_title": "Streaming",
            "dialog_streaming_message": "Streaming P2P será implementado no Sprint 3",
            "dialog_vpn_title": "VPN Mesh",
            "dialog_vpn_message": "VPN Mesh será implementada no Sprint 2",
            
            # Seleção de arquivos
            "file_select_encrypt": "Selecionar arquivo para criptografar",
            "file_select_sign": "Selecionar documento para assinar",
            "file_select_verify": "Selecionar arquivo para verificar",
            
            # Configurações
            "settings_language": "Idioma",
            "settings_portuguese": "Português (Brasil)",
            "settings_english": "English (US)",
        }
    
    def get_english_translations(self) -> Dict[str, Any]:
        """Traduções em Inglês"""
        return {
            # Main Interface
            "app_title": "QuantumShield Desktop v2.0 - 100% Post-Quantum",
            "status_ready": "✅ QuantumShield Desktop started - Post-quantum protection active",
            
            # Tabs
            "tab_dashboard": "📊 Dashboard",
            "tab_crypto": "🔐 Cryptography",
            "tab_blockchain": "⛓️ Blockchain",
            "tab_p2p": "🌐 P2P Network",
            "tab_communication": "📞 Communication",
            "tab_email": "📧 Email",
            "tab_satellite": "🛰️ Satellite",
            "tab_ai": "🤖 AI",
            "tab_enterprise": "🏢 Enterprise",
            "tab_storage": "💾 Storage",
            "tab_identity": "🆔 Identity",
            "tab_analytics": "📊 Analytics",
            "tab_security": "🔒 Security",
            "tab_connectivity": "🌐 Connectivity",
            "tab_certifications": "📜 Certifications",
            "tab_governance": "🏛️ Governance",
            
            # Dashboard
            "dashboard_title": "📊 Executive Dashboard - Real-Time Metrics",
            "dashboard_system_metrics": "System Metrics",
            "dashboard_modules_status": "Modules Status",
            "dashboard_activity_logs": "Activity Logs",
            "dashboard_security_score": "Security Score",
            "dashboard_cpu": "CPU",
            "dashboard_ram": "RAM",
            "dashboard_network": "Network",
            "dashboard_loading": "Loading...",
            "dashboard_security_active": "95% - Post-Quantum Protection Active",
            
            # Cryptography
            "crypto_title": "🔐 NIST Post-Quantum Cryptography",
            "crypto_generate_kem": "Generate ML-KEM-768 Keys",
            "crypto_generate_dsa": "Generate ML-DSA-65 Keys",
            "crypto_generate_sphincs": "Generate SPHINCS+ Keys",
            "crypto_encrypt_files": "Encrypt Files",
            "crypto_sign_documents": "Sign Documents",
            "crypto_verify_integrity": "Verify Integrity",
            "crypto_results_placeholder": "Cryptographic operation results will appear here...",
            "crypto_generating_kem": "🔐 Generating ML-KEM-768 keys...",
            "crypto_kem_success": "✅ ML-KEM-768 keys generated successfully!",
            "crypto_generating_dsa": "🔐 Generating ML-DSA-65 keys...",
            "crypto_dsa_success": "✅ ML-DSA-65 keys generated successfully!",
            "crypto_generating_sphincs": "🔐 Generating SPHINCS+ keys...",
            "crypto_sphincs_success": "✅ SPHINCS+ keys generated successfully!",
            "crypto_encrypting_file": "🔒 Encrypting file",
            "crypto_file_encrypted": "✅ File encrypted with ML-KEM-768!",
            "crypto_signing_document": "✍️ Signing document",
            "crypto_document_signed": "✅ Document signed with ML-DSA-65!",
            "crypto_verifying_integrity": "🔍 Verifying integrity",
            "crypto_integrity_verified": "✅ Integrity verified with SHA3-512!",
            
            # Blockchain
            "blockchain_title": "⛓️ QuantumCoin Blockchain - 3 Cryptocurrencies",
            "blockchain_wallets": "Wallets",
            "blockchain_qtc": "🥇 QuantumCoin (QTC):",
            "blockchain_qtg": "🥈 QuantumGold (QTG):",
            "blockchain_qts": "🥉 QuantumSilver (QTS):",
            "blockchain_transfer": "Transfer Coins",
            "blockchain_mine": "Start Mining",
            "blockchain_explorer": "Blockchain Explorer",
            "blockchain_contracts": "Smart Contracts",
            "blockchain_governance": "Governance Voting",
            "blockchain_staking": "QTG Staking",
            "blockchain_history": "Transaction History",
            "blockchain_history_date": "Date",
            "blockchain_history_type": "Type",
            "blockchain_history_currency": "Currency",
            "blockchain_history_amount": "Amount",
            "blockchain_history_status": "Status",
            
            # P2P
            "p2p_title": "🌐 P2P Network - Post-Quantum Mesh Network",
            "p2p_network_status": "Network Status",
            "p2p_peers_connected": "Connected Peers",
            "p2p_status": "Status",
            "p2p_disconnected": "Disconnected",
            "p2p_discovering": "Discovering...",
            "p2p_discover": "Discover Network",
            "p2p_chat": "Encrypted Chat",
            "p2p_files": "Transfer Files",
            "p2p_browser": "P2P Browser",
            "p2p_streaming": "P2P Streaming",
            "p2p_vpn": "Mesh VPN",
            "p2p_peers_discovered": "Discovered Peers",
            
            # Implementation messages
            "implementation_communication": "Communication interface will be implemented in Sprint 3",
            "implementation_email": "Email client will be implemented in Sprint 3",
            "implementation_satellite": "Satellite features will be implemented in Sprint 4",
            "implementation_ai": "Intelligent AI will be implemented in Sprint 4",
            "implementation_enterprise": "Enterprise features will be implemented in Sprint 4",
            "implementation_storage": "Distributed storage will be implemented in Sprint 3",
            "implementation_identity": "Quantum identity will be implemented in Sprint 4",
            "implementation_analytics": "Analytics will be implemented in Sprint 4",
            "implementation_security": "Advanced security will be implemented in Sprint 4",
            "implementation_connectivity": "Connectivity will be implemented in Sprint 3",
            "implementation_certifications": "Certifications will be implemented in Sprint 5",
            "implementation_governance": "Governance will be implemented in Sprint 5",
            
            # Dialogs
            "dialog_transfer_title": "Transfer",
            "dialog_transfer_message": "Transfer interface will be implemented in Sprint 3",
            "dialog_mining_title": "Mining",
            "dialog_mining_message": "Distributed mining will be implemented in Sprint 3",
            "dialog_explorer_title": "Explorer",
            "dialog_explorer_message": "Blockchain explorer will be implemented in Sprint 3",
            "dialog_contracts_title": "Smart Contracts",
            "dialog_contracts_message": "Smart contracts will be implemented in Sprint 3",
            "dialog_governance_title": "Governance",
            "dialog_governance_message": "Governance system will be implemented in Sprint 5",
            "dialog_staking_title": "Staking",
            "dialog_staking_message": "QTG staking will be implemented in Sprint 3",
            "dialog_discovery_title": "Discovery",
            "dialog_discovery_message": "Network discovery will be implemented in Sprint 2",
            "dialog_chat_title": "Chat",
            "dialog_chat_message": "Encrypted chat will be implemented in Sprint 2",
            "dialog_files_title": "Files",
            "dialog_files_message": "P2P transfer will be implemented in Sprint 3",
            "dialog_browser_title": "P2P Browser",
            "dialog_browser_message": "P2P browser will be implemented in Sprint 3",
            "dialog_streaming_title": "Streaming",
            "dialog_streaming_message": "P2P streaming will be implemented in Sprint 3",
            "dialog_vpn_title": "Mesh VPN",
            "dialog_vpn_message": "Mesh VPN will be implemented in Sprint 2",
            
            # File selection
            "file_select_encrypt": "Select file to encrypt",
            "file_select_sign": "Select document to sign",
            "file_select_verify": "Select file to verify",
            
            # Settings
            "settings_language": "Language",
            "settings_portuguese": "Português (Brasil)",
            "settings_english": "English (US)",
        }
    
    def set_language(self, language: str):
        """Definir idioma atual"""
        if language in self.translations:
            self.current_language = language
            return True
        return False
    
    def get_available_languages(self) -> Dict[str, str]:
        """Obter idiomas disponíveis"""
        return {
            "pt_BR": "Português (Brasil)",
            "en_US": "English (US)"
        }
    
    def t(self, key: str, **kwargs) -> str:
        """Traduzir chave"""
        try:
            translation = self.translations[self.current_language].get(key, key)
            if kwargs:
                return translation.format(**kwargs)
            return translation
        except:
            return key
    
    def get_current_language(self) -> str:
        """Obter idioma atual"""
        return self.current_language

# Instância global
i18n = QuantumShieldI18n()

def t(key: str, **kwargs) -> str:
    """Função de tradução global"""
    return i18n.t(key, **kwargs)

def set_language(language: str) -> bool:
    """Função para definir idioma global"""
    return i18n.set_language(language)

def get_available_languages() -> Dict[str, str]:
    """Função para obter idiomas disponíveis"""
    return i18n.get_available_languages()

