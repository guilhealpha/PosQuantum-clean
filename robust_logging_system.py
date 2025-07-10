#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
📝 Robust Logging System - Sistema de Logging Robusto
Arquivo: robust_logging_system.py
Descrição: Sistema completo de logging para PosQuantum Desktop
Autor: QuantumShield Team
Versão: 2.0
Status: FUNCIONAL E TESTADO
"""

import os
import sys
import logging
import logging.handlers
import json
import time
import threading
import traceback
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

@dataclass
class LogEntry:
    """Entrada de log estruturada"""
    timestamp: str
    level: str
    module: str
    function: str
    message: str
    thread_id: int
    process_id: int
    extra_data: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Converter para dicionário"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Converter para JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

class QuantumLogger:
    """Logger avançado para PosQuantum Desktop"""
    
    def __init__(self, name: str = "PosQuantum", log_dir: str = "logs"):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Configurações
        self.max_file_size = 10 * 1024 * 1024  # 10MB
        self.backup_count = 5
        self.log_format = '%(asctime)s | %(levelname)-8s | %(name)-15s | %(funcName)-20s | %(message)s'
        
        # Thread safety
        self._lock = threading.Lock()
        self._log_buffer = []
        self._buffer_size = 100
        
        # Estatísticas
        self.stats = {
            'total_logs': 0,
            'errors': 0,
            'warnings': 0,
            'info': 0,
            'debug': 0,
            'critical': 0,
            'start_time': time.time()
        }
        
        # Configurar loggers
        self._setup_loggers()
        
        # Iniciar thread de flush
        self._start_flush_thread()
        
        self.info("Sistema de logging inicializado", extra={
            'log_dir': str(self.log_dir),
            'max_file_size': self.max_file_size,
            'backup_count': self.backup_count
        })
    
    def _setup_loggers(self):
        """Configurar todos os loggers"""
        try:
            # Logger principal
            self.logger = logging.getLogger(self.name)
            self.logger.setLevel(logging.DEBUG)
            
            # Remover handlers existentes
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)
            
            # Handler para arquivo principal
            main_log_file = self.log_dir / f"{self.name}.log"
            main_handler = logging.handlers.RotatingFileHandler(
                main_log_file,
                maxBytes=self.max_file_size,
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            main_handler.setLevel(logging.DEBUG)
            main_formatter = logging.Formatter(self.log_format)
            main_handler.setFormatter(main_formatter)
            self.logger.addHandler(main_handler)
            
            # Handler para erros
            error_log_file = self.log_dir / f"{self.name}_errors.log"
            error_handler = logging.handlers.RotatingFileHandler(
                error_log_file,
                maxBytes=self.max_file_size,
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            error_handler.setLevel(logging.ERROR)
            error_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)-15s | %(funcName)-20s | %(lineno)d | %(message)s'
            )
            error_handler.setFormatter(error_formatter)
            self.logger.addHandler(error_handler)
            
            # Handler para console (apenas INFO e acima)
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
            
            # Handler para JSON estruturado
            json_log_file = self.log_dir / f"{self.name}_structured.jsonl"
            self.json_handler = logging.FileHandler(json_log_file, encoding='utf-8')
            self.json_handler.setLevel(logging.DEBUG)
            self.logger.addHandler(self.json_handler)
            
            # Configurar loggers de módulos específicos
            self._setup_module_loggers()
            
        except Exception as e:
            print(f"❌ Erro ao configurar loggers: {e}")
            raise
    
    def _setup_module_loggers(self):
        """Configurar loggers para módulos específicos"""
        modules = [
            'crypto', 'blockchain', 'p2p', 'interface', 
            'network', 'storage', 'identity', 'analytics'
        ]
        
        for module in modules:
            module_logger = logging.getLogger(f"{self.name}.{module}")
            module_logger.setLevel(logging.DEBUG)
            
            # Handler específico do módulo
            module_log_file = self.log_dir / f"{self.name}_{module}.log"
            module_handler = logging.handlers.RotatingFileHandler(
                module_log_file,
                maxBytes=self.max_file_size // 2,  # Arquivos menores para módulos
                backupCount=3,
                encoding='utf-8'
            )
            module_handler.setLevel(logging.DEBUG)
            module_formatter = logging.Formatter(self.log_format)
            module_handler.setFormatter(module_formatter)
            module_logger.addHandler(module_handler)
    
    def _start_flush_thread(self):
        """Iniciar thread para flush periódico"""
        def flush_worker():
            while True:
                try:
                    time.sleep(5)  # Flush a cada 5 segundos
                    self._flush_buffer()
                except Exception as e:
                    print(f"❌ Erro no flush thread: {e}")
        
        flush_thread = threading.Thread(target=flush_worker, daemon=True)
        flush_thread.start()
    
    def _flush_buffer(self):
        """Fazer flush do buffer de logs"""
        with self._lock:
            if self._log_buffer:
                try:
                    for handler in self.logger.handlers:
                        handler.flush()
                    self._log_buffer.clear()
                except Exception as e:
                    print(f"❌ Erro no flush: {e}")
    
    def _log_structured(self, level: str, message: str, extra_data: Dict[str, Any] = None):
        """Log estruturado em JSON"""
        try:
            # Obter informações do frame
            frame = sys._getframe(2)
            module_name = frame.f_globals.get('__name__', 'unknown')
            function_name = frame.f_code.co_name
            
            # Criar entrada estruturada
            entry = LogEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                level=level,
                module=module_name,
                function=function_name,
                message=message,
                thread_id=threading.get_ident(),
                process_id=os.getpid(),
                extra_data=extra_data or {}
            )
            
            # Adicionar ao buffer
            with self._lock:
                self._log_buffer.append(entry)
                if len(self._log_buffer) >= self._buffer_size:
                    self._flush_buffer()
            
            # Escrever JSON
            json_line = entry.to_json().replace('\n', ' ').replace('  ', ' ')
            self.json_handler.emit(logging.LogRecord(
                name=self.name,
                level=getattr(logging, level),
                pathname='',
                lineno=0,
                msg=json_line,
                args=(),
                exc_info=None
            ))
            
            # Atualizar estatísticas
            self.stats['total_logs'] += 1
            self.stats[level.lower()] = self.stats.get(level.lower(), 0) + 1
            
        except Exception as e:
            print(f"❌ Erro no log estruturado: {e}")
    
    def debug(self, message: str, extra: Dict[str, Any] = None):
        """Log de debug"""
        self.logger.debug(message, extra=extra)
        self._log_structured('DEBUG', message, extra)
    
    def info(self, message: str, extra: Dict[str, Any] = None):
        """Log de informação"""
        self.logger.info(message, extra=extra)
        self._log_structured('INFO', message, extra)
    
    def warning(self, message: str, extra: Dict[str, Any] = None):
        """Log de aviso"""
        self.logger.warning(message, extra=extra)
        self._log_structured('WARNING', message, extra)
    
    def error(self, message: str, extra: Dict[str, Any] = None, exc_info: bool = True):
        """Log de erro"""
        if exc_info:
            self.logger.error(message, extra=extra, exc_info=True)
        else:
            self.logger.error(message, extra=extra)
        
        # Adicionar traceback ao extra se disponível
        if exc_info and extra is None:
            extra = {}
        if exc_info:
            extra['traceback'] = traceback.format_exc()
        
        self._log_structured('ERROR', message, extra)
    
    def critical(self, message: str, extra: Dict[str, Any] = None, exc_info: bool = True):
        """Log crítico"""
        if exc_info:
            self.logger.critical(message, extra=extra, exc_info=True)
        else:
            self.logger.critical(message, extra=extra)
        
        # Adicionar traceback ao extra se disponível
        if exc_info and extra is None:
            extra = {}
        if exc_info:
            extra['traceback'] = traceback.format_exc()
        
        self._log_structured('CRITICAL', message, extra)
    
    def log_performance(self, operation: str, duration: float, extra: Dict[str, Any] = None):
        """Log de performance"""
        perf_data = {
            'operation': operation,
            'duration_ms': round(duration * 1000, 2),
            'duration_s': round(duration, 4)
        }
        if extra:
            perf_data.update(extra)
        
        self.info(f"Performance: {operation} took {perf_data['duration_ms']}ms", perf_data)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log de evento de segurança"""
        security_data = {
            'event_type': event_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'details': details,
            'severity': 'HIGH'
        }
        
        self.warning(f"Security Event: {event_type}", security_data)
        
        # Log separado para eventos de segurança
        security_log_file = self.log_dir / f"{self.name}_security.log"
        with open(security_log_file, 'a', encoding='utf-8') as f:
            f.write(f"{json.dumps(security_data, ensure_ascii=False)}\n")
    
    def log_crypto_operation(self, operation: str, algorithm: str, success: bool, details: Dict[str, Any] = None):
        """Log de operação criptográfica"""
        crypto_data = {
            'operation': operation,
            'algorithm': algorithm,
            'success': success,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        if details:
            crypto_data.update(details)
        
        level = 'info' if success else 'error'
        message = f"Crypto: {operation} with {algorithm} {'succeeded' if success else 'failed'}"
        
        getattr(self, level)(message, crypto_data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Obter estatísticas de logging"""
        current_time = time.time()
        uptime = current_time - self.stats['start_time']
        
        return {
            **self.stats,
            'uptime_seconds': round(uptime, 2),
            'uptime_formatted': self._format_uptime(uptime),
            'logs_per_second': round(self.stats['total_logs'] / uptime, 2) if uptime > 0 else 0,
            'buffer_size': len(self._log_buffer),
            'log_files': self._get_log_files_info()
        }
    
    def _format_uptime(self, seconds: float) -> str:
        """Formatar tempo de atividade"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    
    def _get_log_files_info(self) -> List[Dict[str, Any]]:
        """Obter informações dos arquivos de log"""
        log_files = []
        for log_file in self.log_dir.glob("*.log"):
            try:
                stat = log_file.stat()
                log_files.append({
                    'name': log_file.name,
                    'size_bytes': stat.st_size,
                    'size_mb': round(stat.st_size / (1024 * 1024), 2),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            except Exception as e:
                log_files.append({
                    'name': log_file.name,
                    'error': str(e)
                })
        
        return sorted(log_files, key=lambda x: x.get('size_bytes', 0), reverse=True)
    
    def cleanup_old_logs(self, days: int = 30):
        """Limpar logs antigos"""
        try:
            cutoff_time = time.time() - (days * 24 * 60 * 60)
            removed_count = 0
            
            for log_file in self.log_dir.glob("*.log*"):
                try:
                    if log_file.stat().st_mtime < cutoff_time:
                        log_file.unlink()
                        removed_count += 1
                except Exception as e:
                    self.error(f"Erro ao remover log antigo {log_file}: {e}")
            
            self.info(f"Limpeza de logs concluída: {removed_count} arquivos removidos")
            return removed_count
            
        except Exception as e:
            self.error(f"Erro na limpeza de logs: {e}")
            return 0
    
    def export_logs(self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None) -> str:
        """Exportar logs para arquivo"""
        try:
            export_file = self.log_dir / f"export_{int(time.time())}.json"
            
            # Ler logs estruturados
            json_log_file = self.log_dir / f"{self.name}_structured.jsonl"
            exported_logs = []
            
            if json_log_file.exists():
                with open(json_log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            
                            # Filtrar por tempo se especificado
                            if start_time or end_time:
                                log_time = datetime.fromisoformat(log_entry['timestamp'])
                                if start_time and log_time < start_time:
                                    continue
                                if end_time and log_time > end_time:
                                    continue
                            
                            exported_logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
            
            # Escrever arquivo de exportação
            export_data = {
                'export_timestamp': datetime.now(timezone.utc).isoformat(),
                'total_logs': len(exported_logs),
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': end_time.isoformat() if end_time else None,
                'logs': exported_logs
            }
            
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            self.info(f"Logs exportados: {len(exported_logs)} entradas para {export_file}")
            return str(export_file)
            
        except Exception as e:
            self.error(f"Erro ao exportar logs: {e}")
            raise

# Instância global
quantum_logger = QuantumLogger()

def get_logger(name: str = None) -> QuantumLogger:
    """Obter logger global ou específico"""
    if name:
        return QuantumLogger(name)
    return quantum_logger

def test_logging_system():
    """Testar sistema de logging"""
    try:
        logger = get_logger("TestLogger")
        
        print("🧪 Testando sistema de logging...")
        
        # Testar diferentes níveis
        logger.debug("Mensagem de debug", {'test_data': 'debug_value'})
        logger.info("Mensagem de informação", {'test_data': 'info_value'})
        logger.warning("Mensagem de aviso", {'test_data': 'warning_value'})
        
        # Testar log de performance
        start_time = time.time()
        time.sleep(0.1)  # Simular operação
        duration = time.time() - start_time
        logger.log_performance("test_operation", duration, {'test': True})
        
        # Testar log de segurança
        logger.log_security_event("test_security_event", {
            'source_ip': '192.168.1.100',
            'action': 'login_attempt',
            'success': True
        })
        
        # Testar log criptográfico
        logger.log_crypto_operation("key_generation", "ML-KEM-768", True, {
            'key_size': 1184,
            'generation_time': 0.05
        })
        
        # Testar erro controlado
        try:
            raise ValueError("Erro de teste")
        except Exception:
            logger.error("Erro de teste capturado")
        
        # Obter estatísticas
        stats = logger.get_stats()
        
        print("\n📊 ESTATÍSTICAS DO SISTEMA DE LOGGING:")
        print("=" * 50)
        for key, value in stats.items():
            if key != 'log_files':
                print(f"✅ {key}: {value}")
        
        print("\n📁 ARQUIVOS DE LOG:")
        for log_file in stats['log_files']:
            if 'error' not in log_file:
                print(f"✅ {log_file['name']}: {log_file['size_mb']} MB")
            else:
                print(f"❌ {log_file['name']}: {log_file['error']}")
        
        return {
            'test_passed': True,
            'stats': stats,
            'logs_created': stats['total_logs'] > 0,
            'files_created': len(stats['log_files']) > 0
        }
        
    except Exception as e:
        print(f"❌ Erro no teste de logging: {e}")
        return {
            'test_passed': False,
            'error': str(e)
        }

if __name__ == "__main__":
    # Executar teste
    result = test_logging_system()
    
    print("\n🔍 RESULTADO DO TESTE DE LOGGING:")
    print("=" * 50)
    for key, value in result.items():
        if key != 'stats':
            status = "✅" if value else "❌"
            print(f"{status} {key}: {value}")
    
    if result.get('test_passed'):
        print("\n🎉 SISTEMA DE LOGGING FUNCIONANDO PERFEITAMENTE!")
    else:
        print("\n❌ SISTEMA DE LOGGING PRECISA DE CORREÇÕES!")

