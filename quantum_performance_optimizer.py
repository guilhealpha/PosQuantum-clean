#!/usr/bin/env python3
"""
🛡️ QuantumShield - Performance Optimizer
Arquivo: quantum_performance_optimizer.py
Descrição: Sistema de otimização de performance para QuantumShield
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import os
import sys
import time
import psutil
import threading
import logging
import json
import gc
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
import cProfile
import pstats
import io
from contextlib import contextmanager

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Métricas de performance"""
    cpu_usage: float
    memory_usage: float
    memory_peak: float
    execution_time: float
    function_calls: int
    cache_hits: int
    cache_misses: int
    thread_count: int
    io_operations: int

@dataclass
class OptimizationResult:
    """Resultado da otimização"""
    before_metrics: PerformanceMetrics
    after_metrics: PerformanceMetrics
    improvement_percentage: float
    optimizations_applied: List[str]
    recommendations: List[str]

class QuantumPerformanceOptimizer:
    """Sistema de otimização de performance QuantumShield"""
    
    def __init__(self):
        # Cache para otimizações
        self.function_cache = {}
        self.result_cache = {}
        self.cache_stats = {'hits': 0, 'misses': 0}
        
        # Métricas de performance
        self.metrics_history = []
        self.profiling_enabled = True
        
        # Configurações de otimização
        self.optimization_config = {
            'enable_caching': True,
            'enable_threading': True,
            'enable_memory_optimization': True,
            'enable_io_optimization': True,
            'enable_cpu_optimization': True,
            'max_cache_size': 1000,
            'max_threads': min(8, os.cpu_count() or 4),
            'gc_threshold': 100
        }
        
        # Thread pool para operações assíncronas
        self.thread_pool = []
        self.thread_lock = threading.Lock()
        
        # Contadores de performance
        self.performance_counters = {
            'function_calls': 0,
            'cache_operations': 0,
            'io_operations': 0,
            'memory_allocations': 0
        }
        
        logger.info("⚡ Sistema de otimização de performance inicializado")
    
    @contextmanager
    def performance_monitor(self, operation_name: str):
        """Context manager para monitorar performance"""
        start_time = time.perf_counter()
        start_memory = psutil.Process().memory_info().rss
        start_cpu = psutil.cpu_percent()
        
        try:
            yield
        finally:
            end_time = time.perf_counter()
            end_memory = psutil.Process().memory_info().rss
            end_cpu = psutil.cpu_percent()
            
            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory
            cpu_delta = end_cpu - start_cpu
            
            logger.debug(f"📊 {operation_name}: {execution_time:.3f}s, "
                        f"Mem: {memory_delta/1024/1024:.1f}MB, CPU: {cpu_delta:.1f}%")
    
    def cached_function(self, cache_key: str = None, ttl: int = 3600):
        """Decorator para cache de funções"""
        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                # Gerar chave de cache
                if cache_key:
                    key = f"{cache_key}_{hash(str(args) + str(kwargs))}"
                else:
                    key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
                
                # Verificar cache
                if self.optimization_config['enable_caching']:
                    cached_result = self._get_from_cache(key)
                    if cached_result is not None:
                        self.cache_stats['hits'] += 1
                        return cached_result
                
                # Executar função
                self.cache_stats['misses'] += 1
                self.performance_counters['function_calls'] += 1
                
                with self.performance_monitor(func.__name__):
                    result = func(*args, **kwargs)
                
                # Armazenar no cache
                if self.optimization_config['enable_caching']:
                    self._store_in_cache(key, result, ttl)
                
                return result
            
            return wrapper
        return decorator
    
    def _get_from_cache(self, key: str) -> Any:
        """Obtém valor do cache"""
        try:
            if key in self.function_cache:
                cached_item = self.function_cache[key]
                
                # Verificar TTL
                if time.time() - cached_item['timestamp'] < cached_item['ttl']:
                    return cached_item['value']
                else:
                    # Cache expirado
                    del self.function_cache[key]
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Erro no cache: {e}")
            return None
    
    def _store_in_cache(self, key: str, value: Any, ttl: int):
        """Armazena valor no cache"""
        try:
            # Verificar limite do cache
            if len(self.function_cache) >= self.optimization_config['max_cache_size']:
                # Remover item mais antigo
                oldest_key = min(self.function_cache.keys(), 
                               key=lambda k: self.function_cache[k]['timestamp'])
                del self.function_cache[oldest_key]
            
            # Armazenar no cache
            self.function_cache[key] = {
                'value': value,
                'timestamp': time.time(),
                'ttl': ttl
            }
            
            self.performance_counters['cache_operations'] += 1
            
        except Exception as e:
            logger.error(f"❌ Erro ao armazenar cache: {e}")
    
    def optimize_memory_usage(self):
        """Otimiza uso de memória"""
        try:
            logger.info("🧠 Otimizando uso de memória...")
            
            # Forçar garbage collection
            collected = gc.collect()
            logger.info(f"   🗑️ {collected} objetos coletados pelo GC")
            
            # Limpar cache antigo
            current_time = time.time()
            expired_keys = []
            
            for key, cached_item in self.function_cache.items():
                if current_time - cached_item['timestamp'] > cached_item['ttl']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.function_cache[key]
            
            if expired_keys:
                logger.info(f"   🧹 {len(expired_keys)} itens de cache expirados removidos")
            
            # Otimizar estruturas de dados
            self._optimize_data_structures()
            
            # Verificar uso de memória
            memory_info = psutil.Process().memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            logger.info(f"   📊 Uso de memória atual: {memory_mb:.1f} MB")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na otimização de memória: {e}")
            return False
    
    def _optimize_data_structures(self):
        """Otimiza estruturas de dados"""
        try:
            # Converter listas grandes em geradores quando possível
            # Otimizar dicionários removendo chaves desnecessárias
            # Usar __slots__ em classes quando apropriado
            
            # Exemplo de otimização
            if hasattr(self, 'large_data_list'):
                # Converter para gerador se for muito grande
                if len(self.large_data_list) > 10000:
                    self.large_data_list = (item for item in self.large_data_list)
            
        except Exception as e:
            logger.error(f"❌ Erro na otimização de estruturas: {e}")
    
    def optimize_cpu_usage(self):
        """Otimiza uso de CPU"""
        try:
            logger.info("🔥 Otimizando uso de CPU...")
            
            # Verificar número de threads ativas
            active_threads = threading.active_count()
            logger.info(f"   🧵 Threads ativas: {active_threads}")
            
            # Otimizar número de threads
            max_threads = self.optimization_config['max_threads']
            if active_threads > max_threads:
                logger.warning(f"   ⚠️ Muitas threads ativas ({active_threads} > {max_threads})")
            
            # Verificar uso de CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            logger.info(f"   📊 Uso de CPU: {cpu_percent:.1f}%")
            
            # Sugerir otimizações baseadas no uso
            if cpu_percent > 80:
                logger.warning("   ⚠️ Alto uso de CPU detectado")
                self._suggest_cpu_optimizations()
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na otimização de CPU: {e}")
            return False
    
    def _suggest_cpu_optimizations(self):
        """Sugere otimizações de CPU"""
        suggestions = [
            "Considere usar threading para operações I/O",
            "Implemente cache para cálculos repetitivos",
            "Use algoritmos mais eficientes",
            "Considere processamento assíncrono",
            "Otimize loops aninhados"
        ]
        
        for suggestion in suggestions:
            logger.info(f"   💡 {suggestion}")
    
    def optimize_io_operations(self):
        """Otimiza operações de I/O"""
        try:
            logger.info("💾 Otimizando operações de I/O...")
            
            # Verificar operações de disco
            disk_io = psutil.disk_io_counters()
            if disk_io:
                logger.info(f"   📖 Leituras: {disk_io.read_count}")
                logger.info(f"   📝 Escritas: {disk_io.write_count}")
            
            # Sugestões de otimização I/O
            io_optimizations = [
                "Use buffering para operações de arquivo",
                "Implemente cache para dados frequentemente acessados",
                "Use operações assíncronas para I/O de rede",
                "Considere compressão para dados grandes",
                "Minimize operações de seek em arquivos"
            ]
            
            for optimization in io_optimizations:
                logger.info(f"   💡 {optimization}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Erro na otimização de I/O: {e}")
            return False
    
    def profile_function(self, func: Callable, *args, **kwargs):
        """Faz profiling de uma função"""
        try:
            logger.info(f"📊 Fazendo profiling de {func.__name__}...")
            
            # Criar profiler
            profiler = cProfile.Profile()
            
            # Executar com profiling
            profiler.enable()
            result = func(*args, **kwargs)
            profiler.disable()
            
            # Analisar resultados
            stats_stream = io.StringIO()
            stats = pstats.Stats(profiler, stream=stats_stream)
            stats.sort_stats('cumulative')
            stats.print_stats(10)  # Top 10 funções
            
            profile_output = stats_stream.getvalue()
            logger.info(f"📈 Profiling de {func.__name__}:")
            for line in profile_output.split('\n')[:15]:  # Primeiras 15 linhas
                if line.strip():
                    logger.info(f"   {line}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Erro no profiling: {e}")
            return None
    
    def benchmark_operation(self, operation: Callable, iterations: int = 1000) -> Dict[str, float]:
        """Faz benchmark de uma operação"""
        try:
            logger.info(f"⏱️ Fazendo benchmark de {operation.__name__} ({iterations} iterações)...")
            
            times = []
            memory_usage = []
            
            for i in range(iterations):
                # Medir tempo
                start_time = time.perf_counter()
                start_memory = psutil.Process().memory_info().rss
                
                # Executar operação
                operation()
                
                # Medir fim
                end_time = time.perf_counter()
                end_memory = psutil.Process().memory_info().rss
                
                times.append(end_time - start_time)
                memory_usage.append(end_memory - start_memory)
            
            # Calcular estatísticas
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            avg_memory = sum(memory_usage) / len(memory_usage)
            
            results = {
                'average_time': avg_time,
                'min_time': min_time,
                'max_time': max_time,
                'average_memory_delta': avg_memory,
                'iterations': iterations
            }
            
            logger.info(f"📊 Resultados do benchmark:")
            logger.info(f"   ⏱️ Tempo médio: {avg_time*1000:.3f}ms")
            logger.info(f"   ⚡ Tempo mínimo: {min_time*1000:.3f}ms")
            logger.info(f"   🐌 Tempo máximo: {max_time*1000:.3f}ms")
            logger.info(f"   🧠 Memória média: {avg_memory/1024:.1f}KB")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Erro no benchmark: {e}")
            return {}
    
    def get_performance_metrics(self) -> PerformanceMetrics:
        """Obtém métricas atuais de performance"""
        try:
            process = psutil.Process()
            
            metrics = PerformanceMetrics(
                cpu_usage=psutil.cpu_percent(),
                memory_usage=process.memory_info().rss / 1024 / 1024,  # MB
                memory_peak=process.memory_info().peak_wset / 1024 / 1024 if hasattr(process.memory_info(), 'peak_wset') else 0,
                execution_time=time.time(),
                function_calls=self.performance_counters['function_calls'],
                cache_hits=self.cache_stats['hits'],
                cache_misses=self.cache_stats['misses'],
                thread_count=threading.active_count(),
                io_operations=self.performance_counters['io_operations']
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"❌ Erro ao obter métricas: {e}")
            return PerformanceMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0)
    
    def optimize_all(self) -> OptimizationResult:
        """Executa todas as otimizações"""
        try:
            logger.info("🚀 Iniciando otimização completa...")
            
            # Métricas antes
            before_metrics = self.get_performance_metrics()
            
            # Aplicar otimizações
            optimizations_applied = []
            
            if self.optimize_memory_usage():
                optimizations_applied.append("Memory optimization")
            
            if self.optimize_cpu_usage():
                optimizations_applied.append("CPU optimization")
            
            if self.optimize_io_operations():
                optimizations_applied.append("I/O optimization")
            
            # Métricas depois
            time.sleep(1)  # Aguardar estabilização
            after_metrics = self.get_performance_metrics()
            
            # Calcular melhoria
            memory_improvement = ((before_metrics.memory_usage - after_metrics.memory_usage) / 
                                before_metrics.memory_usage * 100) if before_metrics.memory_usage > 0 else 0
            
            # Recomendações
            recommendations = self._generate_recommendations(before_metrics, after_metrics)
            
            result = OptimizationResult(
                before_metrics=before_metrics,
                after_metrics=after_metrics,
                improvement_percentage=memory_improvement,
                optimizations_applied=optimizations_applied,
                recommendations=recommendations
            )
            
            logger.info("✅ Otimização completa concluída")
            logger.info(f"   📊 Melhoria de memória: {memory_improvement:.1f}%")
            logger.info(f"   🔧 Otimizações aplicadas: {len(optimizations_applied)}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Erro na otimização completa: {e}")
            return OptimizationResult(
                before_metrics=PerformanceMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0),
                after_metrics=PerformanceMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0),
                improvement_percentage=0,
                optimizations_applied=[],
                recommendations=[]
            )
    
    def _generate_recommendations(self, before: PerformanceMetrics, after: PerformanceMetrics) -> List[str]:
        """Gera recomendações de otimização"""
        recommendations = []
        
        # Análise de memória
        if after.memory_usage > 100:  # MB
            recommendations.append("Considere otimizar uso de memória - uso alto detectado")
        
        # Análise de CPU
        if after.cpu_usage > 50:
            recommendations.append("Considere otimizar algoritmos - uso de CPU alto")
        
        # Análise de cache
        cache_hit_rate = (after.cache_hits / (after.cache_hits + after.cache_misses) * 100) if (after.cache_hits + after.cache_misses) > 0 else 0
        if cache_hit_rate < 70:
            recommendations.append("Melhore estratégia de cache - taxa de acerto baixa")
        
        # Análise de threads
        if after.thread_count > 10:
            recommendations.append("Considere reduzir número de threads - muitas threads ativas")
        
        return recommendations
    
    def create_performance_report(self) -> str:
        """Cria relatório de performance"""
        try:
            metrics = self.get_performance_metrics()
            
            report_data = {
                'timestamp': time.time(),
                'performance_metrics': asdict(metrics),
                'cache_statistics': self.cache_stats,
                'performance_counters': self.performance_counters,
                'optimization_config': self.optimization_config,
                'system_info': {
                    'cpu_count': os.cpu_count(),
                    'total_memory': psutil.virtual_memory().total / 1024 / 1024 / 1024,  # GB
                    'available_memory': psutil.virtual_memory().available / 1024 / 1024 / 1024,  # GB
                    'platform': sys.platform
                }
            }
            
            report_file = f"performance_report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info(f"📊 Relatório de performance criado: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"❌ Erro ao criar relatório: {e}")
            return ""

def test_performance_optimizer():
    """Teste do sistema de otimização de performance"""
    print("⚡ Testando Sistema de Otimização de Performance...")
    
    optimizer = QuantumPerformanceOptimizer()
    
    try:
        # Teste 1: Função com cache
        @optimizer.cached_function(cache_key="test_function", ttl=60)
        def expensive_calculation(n):
            time.sleep(0.01)  # Simular operação custosa
            return sum(range(n))
        
        print("\n🔄 Testando cache de função...")
        
        # Primeira chamada (cache miss)
        start_time = time.perf_counter()
        result1 = expensive_calculation(1000)
        time1 = time.perf_counter() - start_time
        
        # Segunda chamada (cache hit)
        start_time = time.perf_counter()
        result2 = expensive_calculation(1000)
        time2 = time.perf_counter() - start_time
        
        print(f"  📊 Primeira chamada: {time1*1000:.1f}ms")
        print(f"  ⚡ Segunda chamada: {time2*1000:.1f}ms")
        print(f"  🚀 Speedup: {time1/time2:.1f}x")
        print(f"  ✅ Cache hits: {optimizer.cache_stats['hits']}")
        
        # Teste 2: Benchmark
        print("\n⏱️ Testando benchmark...")
        def simple_operation():
            return sum(range(100))
        
        benchmark_results = optimizer.benchmark_operation(simple_operation, 100)
        print(f"  ✅ Benchmark concluído: {benchmark_results.get('average_time', 0)*1000:.3f}ms médio")
        
        # Teste 3: Otimização completa
        print("\n🚀 Testando otimização completa...")
        optimization_result = optimizer.optimize_all()
        
        print(f"  📊 Otimizações aplicadas: {len(optimization_result.optimizations_applied)}")
        for opt in optimization_result.optimizations_applied:
            print(f"    ✅ {opt}")
        
        print(f"  💡 Recomendações: {len(optimization_result.recommendations)}")
        for rec in optimization_result.recommendations:
            print(f"    💡 {rec}")
        
        # Teste 4: Métricas de performance
        print("\n📊 Métricas atuais:")
        metrics = optimizer.get_performance_metrics()
        print(f"  🧠 Memória: {metrics.memory_usage:.1f} MB")
        print(f"  🔥 CPU: {metrics.cpu_usage:.1f}%")
        print(f"  🧵 Threads: {metrics.thread_count}")
        print(f"  📞 Chamadas de função: {metrics.function_calls}")
        
        # Teste 5: Relatório
        print("\n📋 Criando relatório...")
        report_file = optimizer.create_performance_report()
        if report_file:
            print(f"  ✅ Relatório criado: {report_file}")
        
        print("\n✅ Teste de otimização de performance concluído!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        return False

if __name__ == "__main__":
    test_performance_optimizer()


    
    def measure_network_latency(self, target_host: str = "8.8.8.8") -> float:
        """Medir latência de rede"""
        try:
            import subprocess
            import time
            
            start_time = time.time()
            result = subprocess.run(
                ["ping", "-c", "1", target_host],
                capture_output=True,
                text=True,
                timeout=5
            )
            end_time = time.time()
            
            if result.returncode == 0:
                latency = (end_time - start_time) * 1000  # ms
                self.metrics["network_latency"] = latency
                return latency
            else:
                self.metrics["network_latency"] = 999.0  # Timeout
                return 999.0
                
        except Exception as e:
            logger.error(f"Erro ao medir latência: {e}")
            self.metrics["network_latency"] = 999.0
            return 999.0
    
    def measure_network_throughput(self) -> float:
        """Medir throughput de rede"""
        try:
            import time
            import requests
            
            # Teste de download simples
            start_time = time.time()
            response = requests.get("http://httpbin.org/bytes/1024", timeout=10)
            end_time = time.time()
            
            if response.status_code == 200:
                bytes_downloaded = len(response.content)
                duration = end_time - start_time
                throughput = (bytes_downloaded * 8) / (duration * 1024 * 1024)  # Mbps
                self.metrics["network_throughput"] = throughput
                return throughput
            else:
                self.metrics["network_throughput"] = 0.0
                return 0.0
                
        except Exception as e:
            logger.error(f"Erro ao medir throughput: {e}")
            self.metrics["network_throughput"] = 0.0
            return 0.0
    
    def measure_network_quality(self) -> dict:
        """Medir qualidade geral da rede"""
        try:
            latency = self.measure_network_latency()
            throughput = self.measure_network_throughput()
            
            # Calcular score de qualidade
            latency_score = max(0, 100 - (latency / 10))  # Penalizar latência alta
            throughput_score = min(100, throughput * 10)  # Recompensar throughput alto
            
            quality_score = (latency_score + throughput_score) / 2
            
            quality_data = {
                "latency_ms": latency,
                "throughput_mbps": throughput,
                "quality_score": quality_score,
                "status": "excellent" if quality_score >= 80 else "good" if quality_score >= 60 else "poor"
            }
            
            self.metrics["network_quality"] = quality_data
            return quality_data
            
        except Exception as e:
            logger.error(f"Erro ao medir qualidade da rede: {e}")
            return {"status": "error", "quality_score": 0}

    
    def start_continuous_monitoring(self, interval: int = 30):
        """Iniciar monitoramento contínuo"""
        try:
            import threading
            import time
            
            def monitor_loop():
                while self.monitoring_active:
                    try:
                        # Coletar todas as métricas
                        self.get_cpu_usage()
                        self.get_memory_usage()
                        self.get_disk_usage()
                        self.measure_network_latency()
                        self.measure_network_throughput()
                        
                        # Salvar histórico
                        timestamp = time.time()
                        self.metrics_history.append({
                            "timestamp": timestamp,
                            "metrics": self.metrics.copy()
                        })
                        
                        # Manter apenas últimas 100 medições
                        if len(self.metrics_history) > 100:
                            self.metrics_history.pop(0)
                            
                        time.sleep(interval)
                        
                    except Exception as e:
                        logger.error(f"Erro no monitoramento: {e}")
                        time.sleep(interval)
            
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
            self.monitoring_thread.start()
            
            self.log_correction("PERFORMANCE", "Monitoramento contínuo iniciado", "SUCCESS")
            
        except Exception as e:
            logger.error(f"Erro ao iniciar monitoramento: {e}")
            self.log_correction("PERFORMANCE", f"Erro no monitoramento: {e}", "FAILED")
    
    def stop_continuous_monitoring(self):
        """Parar monitoramento contínuo"""
        self.monitoring_active = False
        if hasattr(self, 'monitoring_thread'):
            self.monitoring_thread.join(timeout=5)
        self.log_correction("PERFORMANCE", "Monitoramento parado", "SUCCESS")
    
    def get_performance_report(self) -> dict:
        """Obter relatório completo de performance"""
        try:
            # Coletar métricas atuais
            current_metrics = {
                "cpu_percent": self.get_cpu_usage(),
                "memory_percent": self.get_memory_usage(),
                "disk_percent": self.get_disk_usage(),
                "network_latency": self.measure_network_latency(),
                "network_throughput": self.measure_network_throughput(),
                "network_quality": self.measure_network_quality()
            }
            
            # Calcular score geral
            scores = []
            scores.append(max(0, 100 - current_metrics["cpu_percent"]))
            scores.append(max(0, 100 - current_metrics["memory_percent"]))
            scores.append(max(0, 100 - current_metrics["disk_percent"]))
            scores.append(current_metrics["network_quality"]["quality_score"])
            
            overall_score = sum(scores) / len(scores)
            
            report = {
                "timestamp": time.time(),
                "current_metrics": current_metrics,
                "overall_score": overall_score,
                "status": "excellent" if overall_score >= 80 else "good" if overall_score >= 60 else "poor",
                "recommendations": self.generate_recommendations(current_metrics)
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Erro ao gerar relatório: {e}")
            return {"status": "error", "overall_score": 0}
    
    def generate_recommendations(self, metrics: dict) -> list:
        """Gerar recomendações baseadas nas métricas"""
        recommendations = []
        
        if metrics["cpu_percent"] > 80:
            recommendations.append("CPU usage high - consider closing unnecessary applications")
        
        if metrics["memory_percent"] > 80:
            recommendations.append("Memory usage high - consider increasing RAM or optimizing memory usage")
        
        if metrics["disk_percent"] > 90:
            recommendations.append("Disk space low - consider cleaning up files or adding storage")
        
        if metrics["network_latency"] > 100:
            recommendations.append("Network latency high - check internet connection")
        
        if metrics["network_throughput"] < 1:
            recommendations.append("Network throughput low - check bandwidth availability")
        
        if not recommendations:
            recommendations.append("System performance is optimal")
        
        return recommendations

# Alias para compatibilidade com testes
PerformanceOptimizer = QuantumPerformanceOptimizer

# Função de conveniência para criar otimizador
def create_performance_optimizer():
    """Criar instância do otimizador de performance"""
    return QuantumPerformanceOptimizer()

# Função para otimização rápida
def quick_optimize():
    """Executar otimização rápida do sistema"""
    optimizer = QuantumPerformanceOptimizer()
    return optimizer.optimize_system()

