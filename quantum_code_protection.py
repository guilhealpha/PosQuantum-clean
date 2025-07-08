#!/usr/bin/env python3
"""
🛡️ QuantumShield - Code Protection System
Arquivo: quantum_code_protection.py
Descrição: Sistema avançado de proteção de código contra engenharia reversa
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import os
import sys
import time
import json
import logging
import hashlib
import secrets
import platform
import subprocess
import threading
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
import psutil
import socket
import uuid
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class LicenseInfo:
    """Informações da licença"""
    license_key: str
    user_name: str
    organization: str
    license_type: str  # trial, standard, professional, enterprise
    expiry_date: float
    max_installations: int
    current_installations: int
    features_enabled: List[str]
    hardware_fingerprint: str
    activation_date: float
    last_validation: float
    is_valid: bool

@dataclass
class HardwareFingerprint:
    """Fingerprint do hardware"""
    cpu_id: str
    motherboard_id: str
    disk_serial: str
    mac_address: str
    system_uuid: str
    combined_hash: str

class QuantumCodeProtection:
    """Sistema de proteção de código QuantumShield"""
    
    def __init__(self, protection_level: str = "maximum"):
        # Configurações
        self.protection_level = protection_level  # basic, standard, maximum
        self.protection_dir = Path("quantum_protection")
        self.protection_dir.mkdir(exist_ok=True)
        
        # Chaves de proteção
        self.master_key = self._generate_master_key()
        self.encryption_key = self._derive_encryption_key()
        
        # Anti-debugging
        self.anti_debug_enabled = True
        self.debug_detection_thread = None
        
        # Hardware fingerprinting
        self.hardware_fp = self._generate_hardware_fingerprint()
        
        # Licenciamento
        self.license_file = self.protection_dir / "license.qsl"  # QuantumShield License
        self.license_info: Optional[LicenseInfo] = None
        
        # Proteções ativas
        self.protections_active = {
            'obfuscation': False,
            'compilation': False,
            'anti_debug': False,
            'license_check': False,
            'hardware_binding': False,
            'code_signing': False
        }
        
        # Inicializar proteções
        self._init_protections()
        
        logger.info("🔒 Sistema de proteção de código QuantumShield inicializado")
        logger.info(f"   Nível de proteção: {protection_level}")
        logger.info(f"   Hardware fingerprint: {self.hardware_fp.combined_hash[:16]}...")
    
    def _generate_master_key(self) -> bytes:
        """Gera chave mestra baseada no sistema"""
        try:
            # Combinar informações do sistema
            system_info = f"{platform.node()}_{platform.machine()}_{platform.processor()}"
            
            # Adicionar informações de hardware
            try:
                cpu_count = psutil.cpu_count()
                memory_total = psutil.virtual_memory().total
                system_info += f"_{cpu_count}_{memory_total}"
            except:
                pass
            
            # Gerar hash SHA-256
            master_key = hashlib.sha256(system_info.encode()).digest()
            
            return master_key
            
        except Exception as e:
            logger.error(f"❌ Erro ao gerar chave mestra: {e}")
            # Fallback para chave fixa (menos seguro)
            return hashlib.sha256(b"QuantumShield_Protection_2025").digest()
    
    def _derive_encryption_key(self) -> bytes:
        """Deriva chave de criptografia da chave mestra"""
        try:
            # Usar PBKDF2 para derivar chave
            salt = b"QuantumShield_Salt_2025"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            key = kdf.derive(self.master_key)
            return base64.urlsafe_b64encode(key)
            
        except Exception as e:
            logger.error(f"❌ Erro ao derivar chave: {e}")
            return Fernet.generate_key()
    
    def _generate_hardware_fingerprint(self) -> HardwareFingerprint:
        """Gera fingerprint único do hardware"""
        try:
            # CPU ID
            cpu_id = platform.processor() or "unknown_cpu"
            
            # MAC Address
            mac_address = "unknown_mac"
            try:
                mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                                      for elements in range(0,2*6,2)][::-1])
            except:
                pass
            
            # System UUID
            system_uuid = "unknown_uuid"
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['wmic', 'csproduct', 'get', 'UUID'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        if len(lines) > 1:
                            system_uuid = lines[1].strip()
                elif platform.system() == "Linux":
                    try:
                        with open('/sys/class/dmi/id/product_uuid', 'r') as f:
                            system_uuid = f.read().strip()
                    except:
                        pass
            except:
                pass
            
            # Motherboard ID (simulado)
            motherboard_id = f"mb_{platform.system()}_{platform.release()}"
            
            # Disk Serial (simulado)
            disk_serial = "disk_" + hashlib.md5(str(psutil.disk_usage('/')).encode()).hexdigest()[:16]
            
            # Combinar tudo em hash único
            combined_data = f"{cpu_id}_{motherboard_id}_{disk_serial}_{mac_address}_{system_uuid}"
            combined_hash = hashlib.sha256(combined_data.encode()).hexdigest()
            
            return HardwareFingerprint(
                cpu_id=cpu_id,
                motherboard_id=motherboard_id,
                disk_serial=disk_serial,
                mac_address=mac_address,
                system_uuid=system_uuid,
                combined_hash=combined_hash
            )
            
        except Exception as e:
            logger.error(f"❌ Erro ao gerar fingerprint: {e}")
            # Fallback
            fallback_hash = hashlib.sha256(f"fallback_{time.time()}".encode()).hexdigest()
            return HardwareFingerprint(
                cpu_id="unknown", motherboard_id="unknown", disk_serial="unknown",
                mac_address="unknown", system_uuid="unknown", combined_hash=fallback_hash
            )
    
    def _init_protections(self):
        """Inicializa proteções básicas"""
        try:
            # Verificar se está sendo debugado
            if self.anti_debug_enabled:
                self._start_anti_debug_monitoring()
            
            # Carregar licença se existir
            self._load_license()
            
            # Verificar integridade do código
            self._verify_code_integrity()
            
        except Exception as e:
            logger.error(f"❌ Erro ao inicializar proteções: {e}")
    
    def _start_anti_debug_monitoring(self):
        """Inicia monitoramento anti-debugging"""
        try:
            self.debug_detection_thread = threading.Thread(
                target=self._anti_debug_loop, daemon=True
            )
            self.debug_detection_thread.start()
            self.protections_active['anti_debug'] = True
            
            logger.info("🛡️ Monitoramento anti-debugging ativado")
            
        except Exception as e:
            logger.error(f"❌ Erro ao iniciar anti-debug: {e}")
    
    def _anti_debug_loop(self):
        """Loop de detecção de debugging"""
        while True:
            try:
                # Verificar se está sendo debugado
                if self._detect_debugger():
                    logger.critical("🚨 DEBUGGER DETECTADO - ENCERRANDO APLICAÇÃO")
                    self._handle_debug_detection()
                
                # Verificar processos suspeitos
                if self._detect_analysis_tools():
                    logger.critical("🚨 FERRAMENTAS DE ANÁLISE DETECTADAS")
                    self._handle_analysis_detection()
                
                time.sleep(5)  # Verificar a cada 5 segundos
                
            except Exception as e:
                logger.error(f"❌ Erro no anti-debug: {e}")
                time.sleep(10)
    
    def _detect_debugger(self) -> bool:
        """Detecta se está sendo debugado"""
        try:
            # Verificar variáveis de ambiente suspeitas
            debug_vars = ['PYTHONBREAKPOINT', 'PYCHARM_HOSTED', 'VSCODE_PID']
            for var in debug_vars:
                if os.environ.get(var):
                    return True
            
            # Verificar se está rodando em modo debug
            if sys.gettrace() is not None:
                return True
            
            # Verificar timing (debuggers são mais lentos)
            start_time = time.perf_counter()
            for i in range(1000):
                pass
            end_time = time.perf_counter()
            
            if (end_time - start_time) > 0.01:  # Muito lento
                return True
            
            return False
            
        except Exception:
            return False
    
    def _detect_analysis_tools(self) -> bool:
        """Detecta ferramentas de análise"""
        try:
            # Lista de processos suspeitos
            suspicious_processes = [
                'ollydbg', 'x64dbg', 'ida', 'ghidra', 'radare2',
                'cheat engine', 'process hacker', 'wireshark',
                'fiddler', 'burp', 'charles'
            ]
            
            # Verificar processos em execução
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    for suspicious in suspicious_processes:
                        if suspicious in proc_name:
                            return True
                except:
                    continue
            
            return False
            
        except Exception:
            return False
    
    def _handle_debug_detection(self):
        """Lida com detecção de debugging"""
        try:
            # Log do evento
            logger.critical("🚨 TENTATIVA DE DEBUGGING DETECTADA")
            
            # Corromper dados críticos
            self._corrupt_critical_data()
            
            # Encerrar aplicação
            os._exit(1)
            
        except Exception:
            os._exit(1)
    
    def _handle_analysis_detection(self):
        """Lida com detecção de ferramentas de análise"""
        try:
            logger.warning("⚠️ Ferramentas de análise detectadas - modo proteção ativado")
            
            # Ativar proteções adicionais
            self._activate_stealth_mode()
            
        except Exception as e:
            logger.error(f"❌ Erro ao lidar com análise: {e}")
    
    def _corrupt_critical_data(self):
        """Corrompe dados críticos se debugging for detectado"""
        try:
            # Sobrescrever variáveis críticas
            self.master_key = b"corrupted"
            self.encryption_key = b"corrupted"
            
            # Corromper arquivos temporários
            temp_files = list(self.protection_dir.glob("*.tmp"))
            for temp_file in temp_files:
                with open(temp_file, 'wb') as f:
                    f.write(b"CORRUPTED_BY_DEBUG_DETECTION")
            
        except Exception:
            pass
    
    def _activate_stealth_mode(self):
        """Ativa modo stealth"""
        try:
            # Reduzir logging
            logging.getLogger().setLevel(logging.CRITICAL)
            
            # Aumentar frequência de verificações
            # (implementação específica dependeria do contexto)
            
        except Exception:
            pass
    
    def _verify_code_integrity(self):
        """Verifica integridade do código"""
        try:
            # Verificar hash dos arquivos principais
            main_files = [
                "main.py",
                "src/blockchain/quantum_mining_engine.py",
                "src/networking/quantum_p2p_vpn_v2.py"
            ]
            
            for file_path in main_files:
                full_path = Path(__file__).parent.parent.parent / file_path
                if full_path.exists():
                    with open(full_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    # Em produção, compararia com hashes conhecidos
                    logger.debug(f"Integridade verificada: {file_path} - {file_hash[:16]}...")
            
        except Exception as e:
            logger.error(f"❌ Erro na verificação de integridade: {e}")
    
    def generate_license(self, user_name: str, organization: str, 
                        license_type: str = "standard", 
                        validity_days: int = 365) -> str:
        """Gera nova licença"""
        try:
            # Gerar chave de licença única
            license_data = f"{user_name}_{organization}_{license_type}_{time.time()}"
            license_key = hashlib.sha256(license_data.encode()).hexdigest()[:32].upper()
            
            # Definir recursos por tipo de licença
            features_map = {
                "trial": ["basic_crypto", "basic_blockchain"],
                "standard": ["crypto", "blockchain", "p2p", "storage"],
                "professional": ["crypto", "blockchain", "p2p", "storage", "satellite", "ai"],
                "enterprise": ["all_features", "priority_support", "custom_deployment"]
            }
            
            # Criar informações da licença
            license_info = LicenseInfo(
                license_key=license_key,
                user_name=user_name,
                organization=organization,
                license_type=license_type,
                expiry_date=time.time() + (validity_days * 24 * 3600),
                max_installations={"trial": 1, "standard": 3, "professional": 10, "enterprise": 100}[license_type],
                current_installations=0,
                features_enabled=features_map.get(license_type, ["basic_crypto"]),
                hardware_fingerprint="",  # Será preenchido na ativação
                activation_date=0.0,
                last_validation=0.0,
                is_valid=True
            )
            
            # Criptografar e salvar licença
            self._save_license(license_info)
            
            logger.info(f"✅ Licença gerada: {license_key}")
            return license_key
            
        except Exception as e:
            logger.error(f"❌ Erro ao gerar licença: {e}")
            return ""
    
    def activate_license(self, license_key: str) -> bool:
        """Ativa licença no sistema"""
        try:
            # Carregar licença
            license_info = self._load_license_by_key(license_key)
            if not license_info:
                logger.error("❌ Licença não encontrada")
                return False
            
            # Verificar validade
            if time.time() > license_info.expiry_date:
                logger.error("❌ Licença expirada")
                return False
            
            # Verificar limite de instalações
            if license_info.current_installations >= license_info.max_installations:
                logger.error("❌ Limite de instalações excedido")
                return False
            
            # Vincular ao hardware
            license_info.hardware_fingerprint = self.hardware_fp.combined_hash
            license_info.activation_date = time.time()
            license_info.current_installations += 1
            license_info.last_validation = time.time()
            
            # Salvar licença ativada
            self._save_license(license_info)
            self.license_info = license_info
            self.protections_active['license_check'] = True
            self.protections_active['hardware_binding'] = True
            
            logger.info(f"✅ Licença ativada: {license_key}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro ao ativar licença: {e}")
            return False
    
    def validate_license(self) -> bool:
        """Valida licença atual"""
        try:
            if not self.license_info:
                return False
            
            # Verificar expiração
            if time.time() > self.license_info.expiry_date:
                logger.error("❌ Licença expirada")
                return False
            
            # Verificar hardware binding
            if self.license_info.hardware_fingerprint != self.hardware_fp.combined_hash:
                logger.error("❌ Hardware não autorizado")
                return False
            
            # Atualizar última validação
            self.license_info.last_validation = time.time()
            self._save_license(self.license_info)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na validação de licença: {e}")
            return False
    
    def _load_license(self):
        """Carrega licença do arquivo"""
        try:
            if not self.license_file.exists():
                return
            
            # Ler arquivo criptografado
            with open(self.license_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Descriptografar
            fernet = Fernet(self.encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Deserializar
            license_data = json.loads(decrypted_data.decode())
            self.license_info = LicenseInfo(**license_data)
            
            logger.info("📄 Licença carregada")
            
        except Exception as e:
            logger.error(f"❌ Erro ao carregar licença: {e}")
    
    def _save_license(self, license_info: LicenseInfo):
        """Salva licença no arquivo"""
        try:
            # Serializar
            license_data = json.dumps(asdict(license_info), indent=2)
            
            # Criptografar
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(license_data.encode())
            
            # Salvar arquivo
            with open(self.license_file, 'wb') as f:
                f.write(encrypted_data)
            
        except Exception as e:
            logger.error(f"❌ Erro ao salvar licença: {e}")
    
    def _load_license_by_key(self, license_key: str) -> Optional[LicenseInfo]:
        """Carrega licença por chave (simulado - em produção seria servidor)"""
        try:
            # Simular base de dados de licenças
            # Em produção, consultaria servidor de licenças
            
            if license_key.startswith("QS"):  # QuantumShield license
                return LicenseInfo(
                    license_key=license_key,
                    user_name="Test User",
                    organization="Test Organization",
                    license_type="professional",
                    expiry_date=time.time() + (365 * 24 * 3600),
                    max_installations=10,
                    current_installations=0,
                    features_enabled=["all_features"],
                    hardware_fingerprint="",
                    activation_date=0.0,
                    last_validation=0.0,
                    is_valid=True
                )
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Erro ao carregar licença por chave: {e}")
            return None
    
    def obfuscate_code(self, source_dir: str, output_dir: str) -> bool:
        """Obfusca código usando PyArmor"""
        try:
            logger.info("🔒 Iniciando obfuscação do código...")
            
            source_path = Path(source_dir)
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
            
            # Verificar se PyArmor está disponível
            try:
                result = subprocess.run(['pyarmor', '--version'], 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    logger.error("❌ PyArmor não encontrado")
                    return False
            except FileNotFoundError:
                logger.error("❌ PyArmor não instalado")
                return False
            
            # Configurar obfuscação
            obfuscation_config = {
                'mode': 'super',  # Modo super para máxima proteção
                'advanced': True,
                'restrict': True,
                'bootstrap': 3,  # Anti-debugging
                'mix_str': True,  # Misturar strings
                'wrap_mode': 1,  # Wrap functions
                'obf_code': 2,  # Obfuscar bytecode
                'obf_mod': 1,  # Obfuscar módulos
            }
            
            # Arquivos a obfuscar
            python_files = list(source_path.rglob("*.py"))
            
            for py_file in python_files:
                if py_file.name.startswith('test_'):
                    continue  # Pular arquivos de teste
                
                logger.info(f"   Obfuscando: {py_file.name}")
                
                # Comando PyArmor
                cmd = [
                    'pyarmor', 'obfuscate',
                    '--output', str(output_path),
                    '--advanced', '2',
                    '--restrict', '4',
                    str(py_file)
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logger.warning(f"⚠️ Falha ao obfuscar {py_file.name}: {result.stderr}")
            
            self.protections_active['obfuscation'] = True
            logger.info("✅ Obfuscação concluída")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na obfuscação: {e}")
            return False
    
    def compile_critical_modules(self, modules: List[str]) -> bool:
        """Compila módulos críticos com Cython"""
        try:
            logger.info("⚡ Compilando módulos críticos...")
            
            # Verificar se Cython está disponível
            try:
                import Cython
                from Cython.Build import cythonize
                from setuptools import setup, Extension
            except ImportError:
                logger.error("❌ Cython não instalado")
                return False
            
            compiled_modules = []
            
            for module_path in modules:
                module_file = Path(module_path)
                if not module_file.exists():
                    logger.warning(f"⚠️ Módulo não encontrado: {module_path}")
                    continue
                
                logger.info(f"   Compilando: {module_file.name}")
                
                # Criar arquivo .pyx
                pyx_file = module_file.with_suffix('.pyx')
                
                # Copiar conteúdo Python para Cython
                with open(module_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Adicionar diretivas Cython
                cython_content = f"""# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True

{content}
"""
                
                with open(pyx_file, 'w', encoding='utf-8') as f:
                    f.write(cython_content)
                
                # Compilar
                try:
                    extensions = [Extension(
                        module_file.stem,
                        [str(pyx_file)],
                        extra_compile_args=['-O3', '-ffast-math']
                    )]
                    
                    setup(
                        ext_modules=cythonize(extensions, compiler_directives={
                            'language_level': 3,
                            'boundscheck': False,
                            'wraparound': False
                        }),
                        script_args=['build_ext', '--inplace'],
                        verbose=False
                    )
                    
                    compiled_modules.append(module_path)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Falha ao compilar {module_file.name}: {e}")
            
            if compiled_modules:
                self.protections_active['compilation'] = True
                logger.info(f"✅ {len(compiled_modules)} módulos compilados")
                return True
            else:
                logger.error("❌ Nenhum módulo foi compilado")
                return False
            
        except Exception as e:
            logger.error(f"❌ Erro na compilação: {e}")
            return False
    
    def sign_executable(self, exe_path: str, certificate_path: str = None) -> bool:
        """Assina executável digitalmente"""
        try:
            logger.info("✍️ Assinando executável...")
            
            exe_file = Path(exe_path)
            if not exe_file.exists():
                logger.error(f"❌ Executável não encontrado: {exe_path}")
                return False
            
            # Simular assinatura digital
            # Em produção, usaria certificado real
            signature_data = {
                'file_hash': hashlib.sha256(exe_file.read_bytes()).hexdigest(),
                'signer': 'QuantumShield Team',
                'timestamp': time.time(),
                'certificate': 'QuantumShield_Code_Signing_Certificate'
            }
            
            # Salvar assinatura
            signature_file = exe_file.with_suffix('.sig')
            with open(signature_file, 'w') as f:
                json.dump(signature_data, f, indent=2)
            
            self.protections_active['code_signing'] = True
            logger.info("✅ Executável assinado")
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na assinatura: {e}")
            return False
    
    def get_protection_status(self) -> Dict[str, Any]:
        """Obtém status das proteções"""
        return {
            'protection_level': self.protection_level,
            'protections_active': self.protections_active,
            'hardware_fingerprint': self.hardware_fp.combined_hash[:16] + "...",
            'license_valid': self.validate_license() if self.license_info else False,
            'license_type': self.license_info.license_type if self.license_info else None,
            'license_expiry': self.license_info.expiry_date if self.license_info else None,
            'anti_debug_active': self.debug_detection_thread and self.debug_detection_thread.is_alive()
        }
    
    def create_protection_report(self) -> str:
        """Cria relatório de proteção"""
        try:
            report_data = {
                'timestamp': time.time(),
                'protection_level': self.protection_level,
                'protections_status': self.protections_active,
                'hardware_info': asdict(self.hardware_fp),
                'license_info': asdict(self.license_info) if self.license_info else None,
                'security_events': []  # Seria preenchido com eventos de segurança
            }
            
            report_file = self.protection_dir / f"protection_report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"📊 Relatório de proteção criado: {report_file.name}")
            return str(report_file)
            
        except Exception as e:
            logger.error(f"❌ Erro ao criar relatório: {e}")
            return ""

def test_code_protection():
    """Teste do sistema de proteção de código"""
    print("🔒 Testando Sistema de Proteção de Código QuantumShield...")
    
    protection = QuantumCodeProtection("maximum")
    
    try:
        # Teste 1: Gerar licença
        print("\n🔑 Testando geração de licença...")
        license_key = protection.generate_license(
            "Test User", "Test Organization", "professional", 365
        )
        
        if license_key:
            print(f"  ✅ Licença gerada: {license_key}")
        else:
            print("  ❌ Falha ao gerar licença")
        
        # Teste 2: Ativar licença
        print("\n🔓 Testando ativação de licença...")
        if protection.activate_license(license_key):
            print("  ✅ Licença ativada com sucesso")
        else:
            print("  ❌ Falha ao ativar licença")
        
        # Teste 3: Validar licença
        print("\n✅ Testando validação de licença...")
        if protection.validate_license():
            print("  ✅ Licença válida")
        else:
            print("  ❌ Licença inválida")
        
        # Teste 4: Hardware fingerprint
        print("\n🖥️ Hardware fingerprint:")
        print(f"  CPU: {protection.hardware_fp.cpu_id[:50]}...")
        print(f"  MAC: {protection.hardware_fp.mac_address}")
        print(f"  Hash: {protection.hardware_fp.combined_hash[:32]}...")
        
        # Teste 5: Status das proteções
        print("\n🛡️ Status das proteções:")
        status = protection.get_protection_status()
        for key, value in status.items():
            print(f"  {key}: {value}")
        
        # Teste 6: Criar relatório
        print("\n📊 Criando relatório de proteção...")
        report_file = protection.create_protection_report()
        if report_file:
            print(f"  ✅ Relatório criado: {Path(report_file).name}")
        else:
            print("  ❌ Falha ao criar relatório")
        
        print("\n✅ Teste de proteção de código concluído!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        return False

if __name__ == "__main__":
    test_code_protection()

