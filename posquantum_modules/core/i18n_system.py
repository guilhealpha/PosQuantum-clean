# -*- coding: utf-8 -*-

"""
Sistema de Internacionalização (i18n) PosQuantum

Este módulo implementa um sistema completo de internacionalização
para suporte a múltiplos idiomas no sistema PosQuantum.

Autor: Equipe PosQuantum
Data: 18/07/2025
Versão: 3.0
"""

import os
import json
import logging
from typing import Dict, Optional, Any, List
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

class SupportedLanguage(Enum):
    """Idiomas suportados pelo sistema."""
    PORTUGUESE_BR = "pt-BR"
    ENGLISH_US = "en-US"
    SPANISH_ES = "es-ES"
    FRENCH_FR = "fr-FR"
    GERMAN_DE = "de-DE"
    ITALIAN_IT = "it-IT"
    JAPANESE_JP = "ja-JP"
    CHINESE_CN = "zh-CN"
    RUSSIAN_RU = "ru-RU"
    ARABIC_SA = "ar-SA"

class I18NSystem:
    """
    Sistema de internacionalização para o PosQuantum.
    
    Este sistema fornece:
    - Suporte a múltiplos idiomas
    - Carregamento dinâmico de traduções
    - Formatação de números e datas por localidade
    - Pluralização automática
    - Fallback para idioma padrão
    """
    
    def __init__(self, default_language: SupportedLanguage = SupportedLanguage.PORTUGUESE_BR):
        """
        Inicializa o sistema de internacionalização.
        
        Args:
            default_language: Idioma padrão do sistema
        """
        self.default_language = default_language
        self.current_language = default_language
        self.translations: Dict[str, Dict[str, str]] = {}
        self.loaded_languages: List[SupportedLanguage] = []
        
        # Carregar traduções padrão
        self._load_default_translations()
        
        logger.info(f"Sistema i18n inicializado com idioma padrão: {default_language.value}")
    
    def _load_default_translations(self) -> None:
        """Carrega as traduções padrão embutidas no sistema."""
        
        # Traduções em Português (Brasil)
        self.translations["pt-BR"] = {
            # Interface principal
            "app_title": "PosQuantum - Criptografia Pós-Quântica",
            "app_subtitle": "Sistema de Segurança Avançada",
            
            # Menus e navegação
            "menu_crypto": "Criptografia",
            "menu_keys": "Chaves",
            "menu_certificates": "Certificados",
            "menu_network": "Rede",
            "menu_compliance": "Conformidade",
            "menu_dashboard": "Dashboard",
            "menu_settings": "Configurações",
            "menu_help": "Ajuda",
            "menu_about": "Sobre",
            
            # Algoritmos criptográficos
            "algo_mlkem": "ML-KEM",
            "algo_mldsa": "ML-DSA",
            "algo_sphincs": "SPHINCS+",
            "algo_hybrid": "Híbrido EC-PQ",
            
            # Ações
            "action_generate": "Gerar",
            "action_encrypt": "Criptografar",
            "action_decrypt": "Descriptografar",
            "action_sign": "Assinar",
            "action_verify": "Verificar",
            "action_save": "Salvar",
            "action_load": "Carregar",
            "action_export": "Exportar",
            "action_import": "Importar",
            "action_cancel": "Cancelar",
            "action_ok": "OK",
            "action_apply": "Aplicar",
            "action_reset": "Redefinir",
            
            # Status e mensagens
            "status_ready": "Pronto",
            "status_processing": "Processando...",
            "status_success": "Sucesso",
            "status_error": "Erro",
            "status_warning": "Aviso",
            "status_info": "Informação",
            
            # Segurança
            "security_level_low": "Baixo",
            "security_level_medium": "Médio",
            "security_level_high": "Alto",
            "security_level_maximum": "Máximo",
            
            # Conformidade
            "compliance_fips": "FIPS 140-3",
            "compliance_cc": "Common Criteria",
            "compliance_iso": "ISO 27001",
            "compliance_soc": "SOC 2 Type II",
            
            # Mensagens de erro
            "error_invalid_input": "Entrada inválida",
            "error_file_not_found": "Arquivo não encontrado",
            "error_permission_denied": "Permissão negada",
            "error_network_error": "Erro de rede",
            "error_crypto_failed": "Operação criptográfica falhou",
            
            # Mensagens de sucesso
            "success_key_generated": "Chave gerada com sucesso",
            "success_data_encrypted": "Dados criptografados com sucesso",
            "success_data_decrypted": "Dados descriptografados com sucesso",
            "success_signature_created": "Assinatura criada com sucesso",
            "success_signature_verified": "Assinatura verificada com sucesso",
            
            # Unidades e formatação
            "unit_bytes": "bytes",
            "unit_kb": "KB",
            "unit_mb": "MB",
            "unit_gb": "GB",
            "unit_seconds": "segundos",
            "unit_minutes": "minutos",
            "unit_hours": "horas",
            "unit_days": "dias"
        }
        
        # Traduções em Inglês (Estados Unidos)
        self.translations["en-US"] = {
            # Interface principal
            "app_title": "PosQuantum - Post-Quantum Cryptography",
            "app_subtitle": "Advanced Security System",
            
            # Menus e navegação
            "menu_crypto": "Cryptography",
            "menu_keys": "Keys",
            "menu_certificates": "Certificates",
            "menu_network": "Network",
            "menu_compliance": "Compliance",
            "menu_dashboard": "Dashboard",
            "menu_settings": "Settings",
            "menu_help": "Help",
            "menu_about": "About",
            
            # Algoritmos criptográficos
            "algo_mlkem": "ML-KEM",
            "algo_mldsa": "ML-DSA",
            "algo_sphincs": "SPHINCS+",
            "algo_hybrid": "EC-PQ Hybrid",
            
            # Ações
            "action_generate": "Generate",
            "action_encrypt": "Encrypt",
            "action_decrypt": "Decrypt",
            "action_sign": "Sign",
            "action_verify": "Verify",
            "action_save": "Save",
            "action_load": "Load",
            "action_export": "Export",
            "action_import": "Import",
            "action_cancel": "Cancel",
            "action_ok": "OK",
            "action_apply": "Apply",
            "action_reset": "Reset",
            
            # Status e mensagens
            "status_ready": "Ready",
            "status_processing": "Processing...",
            "status_success": "Success",
            "status_error": "Error",
            "status_warning": "Warning",
            "status_info": "Information",
            
            # Segurança
            "security_level_low": "Low",
            "security_level_medium": "Medium",
            "security_level_high": "High",
            "security_level_maximum": "Maximum",
            
            # Conformidade
            "compliance_fips": "FIPS 140-3",
            "compliance_cc": "Common Criteria",
            "compliance_iso": "ISO 27001",
            "compliance_soc": "SOC 2 Type II",
            
            # Mensagens de erro
            "error_invalid_input": "Invalid input",
            "error_file_not_found": "File not found",
            "error_permission_denied": "Permission denied",
            "error_network_error": "Network error",
            "error_crypto_failed": "Cryptographic operation failed",
            
            # Mensagens de sucesso
            "success_key_generated": "Key generated successfully",
            "success_data_encrypted": "Data encrypted successfully",
            "success_data_decrypted": "Data decrypted successfully",
            "success_signature_created": "Signature created successfully",
            "success_signature_verified": "Signature verified successfully",
            
            # Unidades e formatação
            "unit_bytes": "bytes",
            "unit_kb": "KB",
            "unit_mb": "MB",
            "unit_gb": "GB",
            "unit_seconds": "seconds",
            "unit_minutes": "minutes",
            "unit_hours": "hours",
            "unit_days": "days"
        }
        
        # Marcar idiomas como carregados
        self.loaded_languages = [SupportedLanguage.PORTUGUESE_BR, SupportedLanguage.ENGLISH_US]
        
        logger.info("Traduções padrão carregadas")
    
    def set_language(self, language: SupportedLanguage) -> bool:
        """
        Define o idioma atual do sistema.
        
        Args:
            language: Idioma a ser definido
            
        Returns:
            True se o idioma foi definido com sucesso, False caso contrário
        """
        try:
            if language not in self.loaded_languages:
                # Tentar carregar o idioma
                if not self._load_language(language):
                    logger.warning(f"Não foi possível carregar o idioma {language.value}")
                    return False
            
            self.current_language = language
            logger.info(f"Idioma alterado para: {language.value}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao definir idioma: {e}")
            return False
    
    def _load_language(self, language: SupportedLanguage) -> bool:
        """
        Carrega um idioma específico.
        
        Args:
            language: Idioma a ser carregado
            
        Returns:
            True se carregado com sucesso, False caso contrário
        """
        try:
            # Em uma implementação real, isso carregaria de arquivos externos
            # Por enquanto, retornamos False para idiomas não implementados
            if language in [SupportedLanguage.PORTUGUESE_BR, SupportedLanguage.ENGLISH_US]:
                if language not in self.loaded_languages:
                    self.loaded_languages.append(language)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao carregar idioma {language.value}: {e}")
            return False
    
    def get_text(self, key: str, **kwargs) -> str:
        """
        Obtém um texto traduzido.
        
        Args:
            key: Chave da tradução
            **kwargs: Parâmetros para formatação
            
        Returns:
            Texto traduzido ou chave se não encontrado
        """
        try:
            # Tentar idioma atual
            current_lang = self.current_language.value
            if current_lang in self.translations:
                if key in self.translations[current_lang]:
                    text = self.translations[current_lang][key]
                    if kwargs:
                        return text.format(**kwargs)
                    return text
            
            # Fallback para idioma padrão
            default_lang = self.default_language.value
            if default_lang in self.translations:
                if key in self.translations[default_lang]:
                    text = self.translations[default_lang][key]
                    if kwargs:
                        return text.format(**kwargs)
                    return text
            
            # Se não encontrou, retornar a chave
            logger.warning(f"Tradução não encontrada para chave: {key}")
            return key
            
        except Exception as e:
            logger.error(f"Erro ao obter tradução para {key}: {e}")
            return key
    
    def get_current_language(self) -> SupportedLanguage:
        """Obtém o idioma atual."""
        return self.current_language
    
    def get_available_languages(self) -> List[SupportedLanguage]:
        """Obtém a lista de idiomas disponíveis."""
        return self.loaded_languages.copy()
    
    def get_language_name(self, language: SupportedLanguage) -> str:
        """
        Obtém o nome nativo de um idioma.
        
        Args:
            language: Idioma
            
        Returns:
            Nome nativo do idioma
        """
        language_names = {
            SupportedLanguage.PORTUGUESE_BR: "Português (Brasil)",
            SupportedLanguage.ENGLISH_US: "English (United States)",
            SupportedLanguage.SPANISH_ES: "Español (España)",
            SupportedLanguage.FRENCH_FR: "Français (France)",
            SupportedLanguage.GERMAN_DE: "Deutsch (Deutschland)",
            SupportedLanguage.ITALIAN_IT: "Italiano (Italia)",
            SupportedLanguage.JAPANESE_JP: "日本語 (日本)",
            SupportedLanguage.CHINESE_CN: "中文 (中国)",
            SupportedLanguage.RUSSIAN_RU: "Русский (Россия)",
            SupportedLanguage.ARABIC_SA: "العربية (السعودية)"
        }
        
        return language_names.get(language, language.value)
    
    def format_number(self, number: float, decimals: int = 2) -> str:
        """
        Formata um número de acordo com a localidade atual.
        
        Args:
            number: Número a ser formatado
            decimals: Número de casas decimais
            
        Returns:
            Número formatado
        """
        try:
            if self.current_language == SupportedLanguage.PORTUGUESE_BR:
                # Formato brasileiro: 1.234,56
                formatted = f"{number:,.{decimals}f}"
                formatted = formatted.replace(",", "X").replace(".", ",").replace("X", ".")
                return formatted
            else:
                # Formato internacional: 1,234.56
                return f"{number:,.{decimals}f}"
                
        except Exception as e:
            logger.error(f"Erro ao formatar número: {e}")
            return str(number)
    
    def format_file_size(self, size_bytes: int) -> str:
        """
        Formata um tamanho de arquivo.
        
        Args:
            size_bytes: Tamanho em bytes
            
        Returns:
            Tamanho formatado com unidade
        """
        try:
            if size_bytes < 1024:
                return f"{size_bytes} {self.get_text('unit_bytes')}"
            elif size_bytes < 1024 * 1024:
                size_kb = size_bytes / 1024
                return f"{self.format_number(size_kb, 1)} {self.get_text('unit_kb')}"
            elif size_bytes < 1024 * 1024 * 1024:
                size_mb = size_bytes / (1024 * 1024)
                return f"{self.format_number(size_mb, 1)} {self.get_text('unit_mb')}"
            else:
                size_gb = size_bytes / (1024 * 1024 * 1024)
                return f"{self.format_number(size_gb, 2)} {self.get_text('unit_gb')}"
                
        except Exception as e:
            logger.error(f"Erro ao formatar tamanho de arquivo: {e}")
            return f"{size_bytes} bytes"
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Obtém informações sobre o sistema de internacionalização.
        
        Returns:
            Dicionário com informações do sistema
        """
        return {
            "current_language": self.current_language.value,
            "current_language_name": self.get_language_name(self.current_language),
            "default_language": self.default_language.value,
            "loaded_languages": [lang.value for lang in self.loaded_languages],
            "available_languages": [lang.value for lang in SupportedLanguage],
            "total_translations": {
                lang: len(translations) 
                for lang, translations in self.translations.items()
            }
        }

def main():
    """Função principal para demonstração."""
    print("=== Sistema de Internacionalização PosQuantum ===")
    
    # Inicializar sistema i18n
    i18n = I18NSystem()
    
    # Demonstrar uso em português
    print(f"Título: {i18n.get_text('app_title')}")
    print(f"Menu Criptografia: {i18n.get_text('menu_crypto')}")
    print(f"Ação Gerar: {i18n.get_text('action_generate')}")
    
    # Mudar para inglês
    i18n.set_language(SupportedLanguage.ENGLISH_US)
    print(f"\nTítulo (EN): {i18n.get_text('app_title')}")
    print(f"Menu Cryptography (EN): {i18n.get_text('menu_crypto')}")
    print(f"Action Generate (EN): {i18n.get_text('action_generate')}")
    
    # Demonstrar formatação
    print(f"\nNúmero formatado: {i18n.format_number(1234.56)}")
    print(f"Tamanho de arquivo: {i18n.format_file_size(1024 * 1024 * 2.5)}")
    
    # Informações do sistema
    info = i18n.get_system_info()
    print(f"\nIdioma atual: {info['current_language_name']}")
    print(f"Idiomas carregados: {len(info['loaded_languages'])}")

if __name__ == "__main__":
    main()

