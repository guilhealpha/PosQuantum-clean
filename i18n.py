#!/usr/bin/env python3
"""
🌐 Sistema de Internacionalização (i18n) - QuantumShield
Suporte a múltiplos idiomas (Português e Inglês)

Autor: QuantumShield Team
Data: 07/01/2025
"""

import json
import os
from pathlib import Path
from typing import Dict, Optional

class I18nManager:
    """Gerenciador de internacionalização"""
    
    def __init__(self, default_language='pt'):
        """Inicializar gerenciador de idiomas"""
        self.current_language = default_language
        self.translations = {}
        self.translations_dir = Path.home() / '.quantumshield' / 'translations'
        self.translations_dir.mkdir(parents=True, exist_ok=True)
        
        # Criar traduções padrão
        self._create_default_translations()
        self._load_translations()
    
    def _create_default_translations(self):
        """Criar arquivos de tradução padrão"""
        
        # Traduções em Português
        pt_translations = {
            # Interface principal
            "app_title": "🛡️ PosQuantum - Segurança Pós-Quântica",
            "dashboard": "📊 Dashboard",
            "cryptography": "🔐 Criptografia",
            "blockchain": "⛓️ Blockchain",
            "p2p_network": "🌐 Rede P2P",
            "satellite": "🛰️ Satélite",
            "ai_security": "🤖 IA Segurança",
            "storage": "💾 Storage",
            "identity": "👤 Identidade",
            "compliance": "📋 Compliance",
            "analytics": "📊 Analytics",
            "settings": "⚙️ Configurações",
            
            # Dashboard
            "quantum_network": "🌐 Rede Quântica",
            "wallets": "💰 Carteiras",
            "security_status": "🛡️ Status de Segurança",
            "satellites_active": "🛰️ Satélites Ativos",
            "system_metrics": "📊 Métricas do Sistema",
            "online": "Online",
            "connecting": "Conectando",
            "offline": "Offline",
            
            # Criptografia
            "post_quantum_crypto": "🔐 Criptografia Pós-Quântica NIST",
            "algorithm_status": "📊 STATUS DOS ALGORITMOS",
            "generate_keys": "🔑 Gerar Chaves",
            "encrypt": "🔒 Criptografar",
            "decrypt": "🔓 Descriptografar",
            "sign": "✍️ Assinar",
            "verify": "🔍 Verificar",
            "backup": "💾 Backup",
            "active": "Ativo",
            "inactive": "Inativo",
            "level": "Nível",
            
            # Blockchain
            "quantum_wallets": "💰 CARTEIRAS QUÂNTICAS",
            "send": "💸 Enviar",
            "receive": "📥 Receber",
            "new_transaction": "📋 NOVA TRANSAÇÃO",
            "to_address": "Para:",
            "amount": "Valor:",
            "coin": "Moeda:",
            "send_transaction": "💸 Enviar Transação",
            "verify_address": "🔍 Verificar Endereço",
            "mining": "⛏️ MINERAÇÃO",
            "mining_status": "⛏️ STATUS DE MINERAÇÃO",
            "start_mining": "⛏️ Iniciar Mineração",
            "stop_mining": "⏸️ Parar Mineração",
            "mining_stats": "📊 Estatísticas",
            "transaction_history": "📊 HISTÓRICO DE TRANSAÇÕES",
            "blockchain_network": "🌐 REDE BLOCKCHAIN",
            "sync_blockchain": "🔄 Sincronizar Blockchain",
            "hashrate": "Hashrate",
            "blocks_mined": "Blocos minerados",
            "next_block": "Próximo bloco",
            
            # P2P Network
            "discovered_computers": "🖥️ COMPUTADORES DESCOBERTOS",
            "p2p_chat": "💬 CHAT P2P",
            "file_sharing": "📁 COMPARTILHAMENTO DE ARQUIVOS",
            "drag_files_here": "Arraste arquivos aqui para compartilhar",
            "chat": "💬 Chat",
            "files": "📁 Arquivos",
            "connect": "🔄 Conectar",
            "message": "Mensagem:",
            "send_message": "📤 Enviar",
            "vpn_active": "VPN Ativo",
            "backup_synced": "Backup Sincronizado",
            "peers": "peers",
            
            # Botões e ações gerais
            "ok": "OK",
            "cancel": "Cancelar",
            "yes": "Sim",
            "no": "Não",
            "save": "Salvar",
            "load": "Carregar",
            "delete": "Deletar",
            "edit": "Editar",
            "copy": "Copiar",
            "paste": "Colar",
            "cut": "Recortar",
            "undo": "Desfazer",
            "redo": "Refazer",
            "close": "Fechar",
            "minimize": "Minimizar",
            "maximize": "Maximizar",
            "help": "Ajuda",
            "about": "Sobre",
            "exit": "Sair",
            
            # Status e mensagens
            "success": "Sucesso",
            "error": "Erro",
            "warning": "Aviso",
            "info": "Informação",
            "loading": "Carregando...",
            "connecting_status": "Conectando...",
            "connected": "Conectado",
            "disconnected": "Desconectado",
            "failed": "Falhou",
            "completed": "Concluído",
            "pending": "Pendente",
            "confirmed": "Confirmado",
            "invalid": "Inválido",
            "valid": "Válido",
            
            # Configurações
            "language": "Idioma",
            "theme": "Tema",
            "notifications": "Notificações",
            "auto_start": "Iniciar automaticamente",
            "minimize_to_tray": "Minimizar para bandeja",
            "enable_logging": "Habilitar logs",
            "log_level": "Nível de log",
            "network_settings": "Configurações de rede",
            "security_settings": "Configurações de segurança",
            "backup_settings": "Configurações de backup",
            
            # Mensagens específicas
            "wallet_created": "Carteira criada com sucesso",
            "transaction_sent": "Transação enviada com sucesso",
            "file_shared": "Arquivo compartilhado",
            "peer_connected": "Peer conectado",
            "peer_disconnected": "Peer desconectado",
            "mining_started": "Mineração iniciada",
            "mining_stopped": "Mineração parada",
            "block_mined": "Bloco minerado com sucesso",
            "backup_completed": "Backup concluído",
            "sync_completed": "Sincronização concluída",
            "keys_generated": "Chaves geradas com sucesso",
            "data_encrypted": "Dados criptografados",
            "data_decrypted": "Dados descriptografados",
            "signature_created": "Assinatura criada",
            "signature_verified": "Assinatura verificada",
            
            # Erros comuns
            "invalid_address": "Endereço inválido",
            "insufficient_balance": "Saldo insuficiente",
            "connection_failed": "Falha na conexão",
            "file_not_found": "Arquivo não encontrado",
            "permission_denied": "Permissão negada",
            "network_error": "Erro de rede",
            "crypto_error": "Erro criptográfico",
            "invalid_input": "Entrada inválida",
            "operation_failed": "Operação falhou",
            "timeout": "Tempo esgotado"
        }
        
        # Traduções em Inglês
        en_translations = {
            # Interface principal
            "app_title": "🛡️ PosQuantum - Post-Quantum Security",
            "dashboard": "📊 Dashboard",
            "cryptography": "🔐 Cryptography",
            "blockchain": "⛓️ Blockchain",
            "p2p_network": "🌐 P2P Network",
            "satellite": "🛰️ Satellite",
            "ai_security": "🤖 AI Security",
            "storage": "💾 Storage",
            "identity": "👤 Identity",
            "compliance": "📋 Compliance",
            "analytics": "📊 Analytics",
            "settings": "⚙️ Settings",
            
            # Dashboard
            "quantum_network": "🌐 Quantum Network",
            "wallets": "💰 Wallets",
            "security_status": "🛡️ Security Status",
            "satellites_active": "🛰️ Active Satellites",
            "system_metrics": "📊 System Metrics",
            "online": "Online",
            "connecting": "Connecting",
            "offline": "Offline",
            
            # Criptografia
            "post_quantum_crypto": "🔐 NIST Post-Quantum Cryptography",
            "algorithm_status": "📊 ALGORITHM STATUS",
            "generate_keys": "🔑 Generate Keys",
            "encrypt": "🔒 Encrypt",
            "decrypt": "🔓 Decrypt",
            "sign": "✍️ Sign",
            "verify": "🔍 Verify",
            "backup": "💾 Backup",
            "active": "Active",
            "inactive": "Inactive",
            "level": "Level",
            
            # Blockchain
            "quantum_wallets": "💰 QUANTUM WALLETS",
            "send": "💸 Send",
            "receive": "📥 Receive",
            "new_transaction": "📋 NEW TRANSACTION",
            "to_address": "To:",
            "amount": "Amount:",
            "coin": "Coin:",
            "send_transaction": "💸 Send Transaction",
            "verify_address": "🔍 Verify Address",
            "mining": "⛏️ MINING",
            "mining_status": "⛏️ MINING STATUS",
            "start_mining": "⛏️ Start Mining",
            "stop_mining": "⏸️ Stop Mining",
            "mining_stats": "📊 Statistics",
            "transaction_history": "📊 TRANSACTION HISTORY",
            "blockchain_network": "🌐 BLOCKCHAIN NETWORK",
            "sync_blockchain": "🔄 Sync Blockchain",
            "hashrate": "Hashrate",
            "blocks_mined": "Blocks mined",
            "next_block": "Next block",
            
            # P2P Network
            "discovered_computers": "🖥️ DISCOVERED COMPUTERS",
            "p2p_chat": "💬 P2P CHAT",
            "file_sharing": "📁 FILE SHARING",
            "drag_files_here": "Drag files here to share",
            "chat": "💬 Chat",
            "files": "📁 Files",
            "connect": "🔄 Connect",
            "message": "Message:",
            "send_message": "📤 Send",
            "vpn_active": "VPN Active",
            "backup_synced": "Backup Synced",
            "peers": "peers",
            
            # Botões e ações gerais
            "ok": "OK",
            "cancel": "Cancel",
            "yes": "Yes",
            "no": "No",
            "save": "Save",
            "load": "Load",
            "delete": "Delete",
            "edit": "Edit",
            "copy": "Copy",
            "paste": "Paste",
            "cut": "Cut",
            "undo": "Undo",
            "redo": "Redo",
            "close": "Close",
            "minimize": "Minimize",
            "maximize": "Maximize",
            "help": "Help",
            "about": "About",
            "exit": "Exit",
            
            # Status e mensagens
            "success": "Success",
            "error": "Error",
            "warning": "Warning",
            "info": "Information",
            "loading": "Loading...",
            "connecting_status": "Connecting...",
            "connected": "Connected",
            "disconnected": "Disconnected",
            "failed": "Failed",
            "completed": "Completed",
            "pending": "Pending",
            "confirmed": "Confirmed",
            "invalid": "Invalid",
            "valid": "Valid",
            
            # Configurações
            "language": "Language",
            "theme": "Theme",
            "notifications": "Notifications",
            "auto_start": "Auto start",
            "minimize_to_tray": "Minimize to tray",
            "enable_logging": "Enable logging",
            "log_level": "Log level",
            "network_settings": "Network settings",
            "security_settings": "Security settings",
            "backup_settings": "Backup settings",
            
            # Mensagens específicas
            "wallet_created": "Wallet created successfully",
            "transaction_sent": "Transaction sent successfully",
            "file_shared": "File shared",
            "peer_connected": "Peer connected",
            "peer_disconnected": "Peer disconnected",
            "mining_started": "Mining started",
            "mining_stopped": "Mining stopped",
            "block_mined": "Block mined successfully",
            "backup_completed": "Backup completed",
            "sync_completed": "Sync completed",
            "keys_generated": "Keys generated successfully",
            "data_encrypted": "Data encrypted",
            "data_decrypted": "Data decrypted",
            "signature_created": "Signature created",
            "signature_verified": "Signature verified",
            
            # Erros comuns
            "invalid_address": "Invalid address",
            "insufficient_balance": "Insufficient balance",
            "connection_failed": "Connection failed",
            "file_not_found": "File not found",
            "permission_denied": "Permission denied",
            "network_error": "Network error",
            "crypto_error": "Cryptographic error",
            "invalid_input": "Invalid input",
            "operation_failed": "Operation failed",
            "timeout": "Timeout"
        }
        
        # Salvar traduções
        pt_file = self.translations_dir / 'pt.json'
        en_file = self.translations_dir / 'en.json'
        
        with open(pt_file, 'w', encoding='utf-8') as f:
            json.dump(pt_translations, f, ensure_ascii=False, indent=2)
        
        with open(en_file, 'w', encoding='utf-8') as f:
            json.dump(en_translations, f, ensure_ascii=False, indent=2)
    
    def _load_translations(self):
        """Carregar traduções dos arquivos"""
        for lang_file in self.translations_dir.glob('*.json'):
            lang_code = lang_file.stem
            try:
                with open(lang_file, 'r', encoding='utf-8') as f:
                    self.translations[lang_code] = json.load(f)
            except Exception as e:
                print(f"Erro ao carregar tradução {lang_code}: {e}")
    
    def set_language(self, language_code: str):
        """Definir idioma atual"""
        if language_code in self.translations:
            self.current_language = language_code
            return True
        return False
    
    def get_language(self) -> str:
        """Obter idioma atual"""
        return self.current_language
    
    def get_available_languages(self) -> Dict[str, str]:
        """Obter idiomas disponíveis"""
        return {
            'pt': 'Português',
            'en': 'English'
        }
    
    def t(self, key: str, **kwargs) -> str:
        """Traduzir chave (função principal de tradução)"""
        return self.translate(key, **kwargs)
    
    def translate(self, key: str, **kwargs) -> str:
        """Traduzir chave para o idioma atual"""
        if self.current_language not in self.translations:
            return key
        
        translation = self.translations[self.current_language].get(key, key)
        
        # Substituir variáveis se fornecidas
        if kwargs:
            try:
                translation = translation.format(**kwargs)
            except (KeyError, ValueError):
                pass
        
        return translation
    
    def translate_to(self, key: str, language: str, **kwargs) -> str:
        """Traduzir chave para idioma específico"""
        if language not in self.translations:
            return key
        
        translation = self.translations[language].get(key, key)
        
        # Substituir variáveis se fornecidas
        if kwargs:
            try:
                translation = translation.format(**kwargs)
            except (KeyError, ValueError):
                pass
        
        return translation
    
    def add_translation(self, language: str, key: str, value: str):
        """Adicionar nova tradução"""
        if language not in self.translations:
            self.translations[language] = {}
        
        self.translations[language][key] = value
        
        # Salvar no arquivo
        lang_file = self.translations_dir / f'{language}.json'
        with open(lang_file, 'w', encoding='utf-8') as f:
            json.dump(self.translations[language], f, ensure_ascii=False, indent=2)
    
    def get_translation_keys(self) -> list:
        """Obter todas as chaves de tradução disponíveis"""
        keys = set()
        for lang_translations in self.translations.values():
            keys.update(lang_translations.keys())
        return sorted(list(keys))

# Instância global do gerenciador de i18n
_i18n_manager = None

def get_i18n_manager() -> I18nManager:
    """Obter instância global do gerenciador de i18n"""
    global _i18n_manager
    if _i18n_manager is None:
        _i18n_manager = I18nManager()
    return _i18n_manager

def t(key: str, **kwargs) -> str:
    """Função global de tradução (atalho)"""
    return get_i18n_manager().translate(key, **kwargs)

def set_language(language_code: str) -> bool:
    """Função global para definir idioma"""
    return get_i18n_manager().set_language(language_code)

def get_language() -> str:
    """Função global para obter idioma atual"""
    return get_i18n_manager().get_language()

def get_available_languages() -> Dict[str, str]:
    """Função global para obter idiomas disponíveis"""
    return get_i18n_manager().get_available_languages()

# Exemplo de uso:
if __name__ == "__main__":
    # Testar sistema de i18n
    i18n = I18nManager()
    
    print("=== Teste do Sistema de Internacionalização ===")
    
    # Testar em português
    i18n.set_language('pt')
    print(f"Idioma atual: {i18n.get_language()}")
    print(f"Título: {i18n.t('app_title')}")
    print(f"Dashboard: {i18n.t('dashboard')}")
    print(f"Sucesso: {i18n.t('success')}")
    
    print("\n" + "="*50)
    
    # Testar em inglês
    i18n.set_language('en')
    print(f"Current language: {i18n.get_language()}")
    print(f"Title: {i18n.t('app_title')}")
    print(f"Dashboard: {i18n.t('dashboard')}")
    print(f"Success: {i18n.t('success')}")
    
    print("\n=== Sistema de i18n funcionando! ===")

