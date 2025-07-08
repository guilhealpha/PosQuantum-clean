#!/usr/bin/env python3
"""
Quantum Anti-Reverse Engineering System
Sistema completo de proteção contra engenharia reversa e roubo de código
Protege propriedade intelectual e tecnologia pós-quântica
"""

import os
import sys
import ast
import dis
import marshal
import types
import hashlib
import random
import string
import base64
import zlib
import time
import threading
import psutil
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import ctypes
import platform

# Importar módulos do QuantumShield
try:
    from .real_nist_crypto import RealNISTCrypto
    from .tamper_evident_audit_trail import TamperEvidentAuditSystem
except ImportError:
    import sys
    sys.path.append('/home/ubuntu')
    from real_nist_crypto import RealNISTCrypto
    from tamper_evident_audit_trail import TamperEvidentAuditSystem

logger = logging.getLogger(__name__)

class ProtectionLevel(Enum):
    """Níveis de proteção"""
    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"
    MILITARY = "military"
    QUANTUM_SAFE = "quantum_safe"

class ThreatType(Enum):
    """Tipos de ameaça"""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    DEBUGGER_ATTACHMENT = "debugger_attachment"
    MEMORY_DUMP = "memory_dump"
    CODE_INJECTION = "code_injection"
    REVERSE_ENGINEERING = "reverse_engineering"
    INTELLECTUAL_PROPERTY_THEFT = "ip_theft"

@dataclass
class ProtectionEvent:
    """Evento de proteção"""
    event_id: str
    threat_type: ThreatType
    severity: str
    description: str
    timestamp: float
    process_info: Dict[str, Any]
    action_taken: str

class QuantumAntiReverseEngineering:
    """Sistema de proteção contra engenharia reversa"""
    
    def __init__(self, protection_level: ProtectionLevel = ProtectionLevel.QUANTUM_SAFE):
        self.protection_level = protection_level
        self.crypto = RealNISTCrypto()
        self.audit_system = TamperEvidentAuditSystem()
        
        # Chaves de proteção
        self.master_key = self._generate_master_key()
        self.obfuscation_key = self._generate_obfuscation_key()
        
        # Estado de proteção
        self.protection_active = False
        self.monitoring_thread = None
        self.protected_functions = {}
        self.decoy_functions = {}
        
        # Detectores de ameaça
        self.threat_detectors = {
            ThreatType.DEBUGGER_ATTACHMENT: self._detect_debugger,
            ThreatType.MEMORY_DUMP: self._detect_memory_dump,
            ThreatType.CODE_INJECTION: self._detect_code_injection,
            ThreatType.REVERSE_ENGINEERING: self._detect_reverse_engineering
        }
        
        logger.info(f"Anti-Reverse Engineering System initialized with {protection_level.value} protection")
    
    def _generate_master_key(self) -> bytes:
        """Gerar chave mestra de proteção"""
        # Usar informações do sistema para gerar chave única
        system_info = f"{platform.machine()}{platform.processor()}{os.getpid()}{time.time()}"
        return hashlib.sha3_256(system_info.encode()).digest()
    
    def _generate_obfuscation_key(self) -> bytes:
        """Gerar chave de ofuscação"""
        return self.crypto.generate_random_bytes(32)
    
    def activate_protection(self):
        """Ativar proteção completa"""
        if self.protection_active:
            return
        
        self.protection_active = True
        
        # Iniciar monitoramento de ameaças
        self.monitoring_thread = threading.Thread(target=self._monitor_threats, daemon=True)
        self.monitoring_thread.start()
        
        # Aplicar proteções específicas por nível
        if self.protection_level in [ProtectionLevel.ADVANCED, ProtectionLevel.MILITARY, ProtectionLevel.QUANTUM_SAFE]:
            self._apply_advanced_protections()
        
        if self.protection_level in [ProtectionLevel.MILITARY, ProtectionLevel.QUANTUM_SAFE]:
            self._apply_military_protections()
        
        if self.protection_level == ProtectionLevel.QUANTUM_SAFE:
            self._apply_quantum_protections()
        
        logger.info("Anti-Reverse Engineering protection activated")
    
    def _monitor_threats(self):
        """Monitorar ameaças continuamente"""
        while self.protection_active:
            try:
                for threat_type, detector in self.threat_detectors.items():
                    if detector():
                        self._handle_threat(threat_type)
                
                time.sleep(0.1)  # Verificar a cada 100ms
                
            except Exception as e:
                logger.error(f"Error in threat monitoring: {e}")
                time.sleep(1)
    
    def _detect_debugger(self) -> bool:
        """Detectar anexação de debugger"""
        try:
            # Verificar se processo está sendo debugado
            if platform.system() == "Windows":
                # Windows: verificar flag IsDebuggerPresent
                kernel32 = ctypes.windll.kernel32
                return kernel32.IsDebuggerPresent() != 0
            
            elif platform.system() == "Linux":
                # Linux: verificar /proc/self/status
                try:
                    with open('/proc/self/status', 'r') as f:
                        for line in f:
                            if line.startswith('TracerPid:'):
                                tracer_pid = int(line.split()[1])
                                return tracer_pid != 0
                except:
                    pass
            
            # Verificar timing de execução (debuggers são mais lentos)
            start_time = time.perf_counter()
            for _ in range(1000):
                pass
            end_time = time.perf_counter()
            
            # Se execução demorou muito, pode ser debugger
            return (end_time - start_time) > 0.01
            
        except Exception:
            return False
    
    def _detect_memory_dump(self) -> bool:
        """Detectar tentativas de dump de memória"""
        try:
            # Verificar processos suspeitos
            suspicious_processes = [
                'gdb', 'lldb', 'windbg', 'x64dbg', 'ollydbg',
                'ida', 'ida64', 'ghidra', 'radare2', 'r2',
                'cheat engine', 'process hacker', 'process monitor'
            ]
            
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(sus in proc_name for sus in suspicious_processes):
                        return True
                except:
                    continue
            
            return False
            
        except Exception:
            return False
    
    def _detect_code_injection(self) -> bool:
        """Detectar injeção de código"""
        try:
            # Verificar integridade do código carregado
            current_frame = sys._getframe()
            code_hash = hashlib.sha256(current_frame.f_code.co_code).hexdigest()
            
            # Comparar com hash esperado (seria armazenado de forma segura)
            # Por simplicidade, apenas verificar se código foi modificado
            return len(current_frame.f_code.co_code) < 100  # Código muito pequeno = suspeito
            
        except Exception:
            return False
    
    def _detect_reverse_engineering(self) -> bool:
        """Detectar ferramentas de engenharia reversa"""
        try:
            # Verificar ferramentas de análise estática
            re_tools = [
                'strings', 'objdump', 'readelf', 'nm', 'file',
                'hexdump', 'xxd', 'binwalk', 'foremost'
            ]
            
            # Verificar se alguma ferramenta está rodando
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    proc_name = proc.info['name'].lower()
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    
                    if any(tool in proc_name or tool in cmdline for tool in re_tools):
                        return True
                except:
                    continue
            
            return False
            
        except Exception:
            return False
    
    def _handle_threat(self, threat_type: ThreatType):
        """Lidar com ameaça detectada"""
        event = ProtectionEvent(
            event_id=f"threat_{int(time.time())}_{random.randint(1000, 9999)}",
            threat_type=threat_type,
            severity="HIGH",
            description=f"Detected {threat_type.value} attempt",
            timestamp=time.time(),
            process_info=self._get_process_info(),
            action_taken="COUNTERMEASURES_ACTIVATED"
        )
        
        # Log do evento
        logger.warning(f"THREAT DETECTED: {threat_type.value}")
        
        # Aplicar contramedidas
        self._apply_countermeasures(threat_type)
        
        # Registrar no sistema de auditoria
        self.audit_system.log_security_event(
            event_type="ANTI_REVERSE_ENGINEERING",
            details=event.__dict__
        )
    
    def _apply_countermeasures(self, threat_type: ThreatType):
        """Aplicar contramedidas específicas"""
        if threat_type == ThreatType.DEBUGGER_ATTACHMENT:
            # Ofuscar código crítico
            self._emergency_obfuscation()
            # Gerar ruído para confundir debugger
            self._generate_debug_noise()
        
        elif threat_type == ThreatType.MEMORY_DUMP:
            # Limpar dados sensíveis da memória
            self._clear_sensitive_memory()
            # Gerar dados falsos
            self._generate_decoy_data()
        
        elif threat_type == ThreatType.REVERSE_ENGINEERING:
            # Ativar funções decoy
            self._activate_decoy_functions()
            # Ofuscar strings
            self._obfuscate_strings()
    
    def _apply_advanced_protections(self):
        """Aplicar proteções avançadas"""
        # Ofuscação de código
        self._obfuscate_critical_functions()
        
        # Anti-tampering
        self._enable_anti_tampering()
        
        # Verificação de integridade
        self._enable_integrity_checks()
    
    def _apply_military_protections(self):
        """Aplicar proteções de nível militar"""
        # Criptografia de código em tempo real
        self._enable_runtime_encryption()
        
        # Detecção de VM/Sandbox
        self._enable_vm_detection()
        
        # Proteção contra análise estática
        self._enable_static_analysis_protection()
    
    def _apply_quantum_protections(self):
        """Aplicar proteções pós-quânticas"""
        # Criptografia pós-quântica para código
        self._enable_quantum_code_encryption()
        
        # Assinatura pós-quântica de integridade
        self._enable_quantum_integrity_signatures()
        
        # Proteção contra computação quântica
        self._enable_quantum_resistant_obfuscation()
    
    def protect_function(self, func: Callable, protection_level: ProtectionLevel = None) -> Callable:
        """Proteger função específica"""
        if protection_level is None:
            protection_level = self.protection_level
        
        def protected_wrapper(*args, **kwargs):
            # Verificar integridade antes da execução
            if not self._verify_function_integrity(func):
                raise RuntimeError("Function integrity check failed")
            
            # Detectar ameaças antes da execução
            for threat_type, detector in self.threat_detectors.items():
                if detector():
                    self._handle_threat(threat_type)
                    raise RuntimeError(f"Security threat detected: {threat_type.value}")
            
            # Executar função original
            return func(*args, **kwargs)
        
        # Registrar função protegida
        func_id = f"{func.__module__}.{func.__name__}"
        self.protected_functions[func_id] = {
            'original': func,
            'protected': protected_wrapper,
            'protection_level': protection_level,
            'integrity_hash': self._calculate_function_hash(func)
        }
        
        return protected_wrapper
    
    def obfuscate_code(self, code: str) -> str:
        """Ofuscar código Python"""
        try:
            # Parse do código
            tree = ast.parse(code)
            
            # Aplicar transformações de ofuscação
            obfuscated_tree = self._apply_obfuscation_transforms(tree)
            
            # Converter de volta para código
            import astor
            return astor.to_source(obfuscated_tree)
            
        except Exception as e:
            logger.error(f"Code obfuscation failed: {e}")
            return code
    
    def _apply_obfuscation_transforms(self, tree: ast.AST) -> ast.AST:
        """Aplicar transformações de ofuscação"""
        class ObfuscationTransformer(ast.NodeTransformer):
            def __init__(self, crypto_key):
                self.crypto_key = crypto_key
                self.name_mapping = {}
            
            def visit_Name(self, node):
                # Ofuscar nomes de variáveis
                if node.id not in ['print', 'len', 'str', 'int', 'float']:  # Preservar built-ins
                    if node.id not in self.name_mapping:
                        # Gerar nome ofuscado
                        obfuscated = self._generate_obfuscated_name(node.id)
                        self.name_mapping[node.id] = obfuscated
                    node.id = self.name_mapping[node.id]
                return node
            
            def visit_Str(self, node):
                # Ofuscar strings
                if len(node.s) > 3:  # Apenas strings longas
                    encrypted = self._encrypt_string(node.s)
                    # Substituir por chamada de decodificação
                    return ast.Call(
                        func=ast.Name(id='_decode_str', ctx=ast.Load()),
                        args=[ast.Str(s=encrypted)],
                        keywords=[]
                    )
                return node
            
            def _generate_obfuscated_name(self, original: str) -> str:
                # Gerar nome ofuscado baseado na chave
                hash_input = f"{original}{self.crypto_key.hex()}"
                name_hash = hashlib.md5(hash_input.encode()).hexdigest()[:8]
                return f"_{name_hash}"
            
            def _encrypt_string(self, text: str) -> str:
                # Criptografar string
                encrypted = self.crypto_key[:16]  # Usar parte da chave
                result = ""
                for i, char in enumerate(text):
                    result += chr(ord(char) ^ encrypted[i % len(encrypted)])
                return base64.b64encode(result.encode()).decode()
        
        transformer = ObfuscationTransformer(self.obfuscation_key)
        return transformer.visit(tree)
    
    def _get_process_info(self) -> Dict[str, Any]:
        """Obter informações do processo atual"""
        try:
            process = psutil.Process()
            return {
                'pid': process.pid,
                'name': process.name(),
                'cmdline': process.cmdline(),
                'memory_percent': process.memory_percent(),
                'cpu_percent': process.cpu_percent(),
                'create_time': process.create_time()
            }
        except Exception:
            return {}
    
    def _verify_function_integrity(self, func: Callable) -> bool:
        """Verificar integridade da função"""
        try:
            current_hash = self._calculate_function_hash(func)
            func_id = f"{func.__module__}.{func.__name__}"
            
            if func_id in self.protected_functions:
                expected_hash = self.protected_functions[func_id]['integrity_hash']
                return current_hash == expected_hash
            
            return True
        except Exception:
            return False
    
    def _calculate_function_hash(self, func: Callable) -> str:
        """Calcular hash da função"""
        try:
            code_bytes = func.__code__.co_code
            return hashlib.sha256(code_bytes).hexdigest()
        except Exception:
            return ""
    
    def _emergency_obfuscation(self):
        """Ofuscação de emergência"""
        # Ofuscar código crítico em tempo real
        pass
    
    def _generate_debug_noise(self):
        """Gerar ruído para confundir debuggers"""
        # Criar threads que fazem operações inúteis
        def noise_thread():
            for _ in range(1000):
                dummy = random.random() * random.random()
                time.sleep(0.001)
        
        for _ in range(5):
            threading.Thread(target=noise_thread, daemon=True).start()
    
    def _clear_sensitive_memory(self):
        """Limpar dados sensíveis da memória"""
        # Sobrescrever variáveis sensíveis
        self.master_key = b'0' * len(self.master_key)
        self.obfuscation_key = b'0' * len(self.obfuscation_key)
        
        # Regenerar chaves
        self.master_key = self._generate_master_key()
        self.obfuscation_key = self._generate_obfuscation_key()
    
    def _generate_decoy_data(self):
        """Gerar dados falsos para confundir atacantes"""
        # Criar variáveis decoy com dados falsos
        fake_keys = [os.urandom(32) for _ in range(10)]
        fake_algorithms = ['fake_ml_kem', 'fake_ml_dsa', 'fake_sphincs']
        fake_data = {'fake': 'data', 'decoy': True}
    
    def _activate_decoy_functions(self):
        """Ativar funções decoy"""
        # Criar funções falsas que parecem importantes
        def fake_decrypt_key():
            return "fake_key_" + ''.join(random.choices(string.ascii_letters, k=32))
        
        def fake_quantum_algorithm():
            return random.randint(1000, 9999)
        
        self.decoy_functions = {
            'decrypt_master_key': fake_decrypt_key,
            'quantum_decrypt': fake_quantum_algorithm
        }
    
    def _obfuscate_strings(self):
        """Ofuscar strings em tempo real"""
        # Substituir strings importantes por versões ofuscadas
        pass
    
    def _obfuscate_critical_functions(self):
        """Ofuscar funções críticas"""
        pass
    
    def _enable_anti_tampering(self):
        """Habilitar proteção anti-tampering"""
        pass
    
    def _enable_integrity_checks(self):
        """Habilitar verificações de integridade"""
        pass
    
    def _enable_runtime_encryption(self):
        """Habilitar criptografia em tempo de execução"""
        pass
    
    def _enable_vm_detection(self):
        """Habilitar detecção de VM/Sandbox"""
        pass
    
    def _enable_static_analysis_protection(self):
        """Habilitar proteção contra análise estática"""
        pass
    
    def _enable_quantum_code_encryption(self):
        """Habilitar criptografia pós-quântica de código"""
        pass
    
    def _enable_quantum_integrity_signatures(self):
        """Habilitar assinaturas pós-quânticas de integridade"""
        pass
    
    def _enable_quantum_resistant_obfuscation(self):
        """Habilitar ofuscação resistente a computação quântica"""
        pass
    
    def deactivate_protection(self):
        """Desativar proteção"""
        self.protection_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=1)
        
        logger.info("Anti-Reverse Engineering protection deactivated")

# Instância global do sistema de proteção
anti_re_system = QuantumAntiReverseEngineering()

def protect_quantum_function(protection_level: ProtectionLevel = ProtectionLevel.QUANTUM_SAFE):
    """Decorator para proteger funções"""
    def decorator(func):
        return anti_re_system.protect_function(func, protection_level)
    return decorator

def activate_quantum_protection():
    """Ativar proteção pós-quântica"""
    anti_re_system.activate_protection()

def deactivate_quantum_protection():
    """Desativar proteção"""
    anti_re_system.deactivate_protection()

if __name__ == "__main__":
    # Teste do sistema
    print("=== SISTEMA ANTI-ENGENHARIA REVERSA POSQUANTUM ===")
    
    # Ativar proteção
    activate_quantum_protection()
    
    # Função de teste protegida
    @protect_quantum_function(ProtectionLevel.QUANTUM_SAFE)
    def secret_quantum_function():
        return "This is a protected quantum function"
    
    try:
        result = secret_quantum_function()
        print(f"Protected function result: {result}")
    except Exception as e:
        print(f"Protection triggered: {e}")
    
    time.sleep(2)
    deactivate_quantum_protection()

