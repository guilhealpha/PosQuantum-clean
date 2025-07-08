#!/usr/bin/env python3
"""
🛡️ QuantumShield - Distributed Hash Table (DHT)
Arquivo: quantum_dht.py
Descrição: Sistema DHT para descoberta e roteamento de peers P2P
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import hashlib
import json
import time
import socket
import threading
import random
import struct
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import asyncio
import aiohttp
import netifaces

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class DHTNode:
    """Nó da DHT"""
    node_id: str
    ip_address: str
    port: int
    public_key: str
    last_seen: float
    distance: int = 0
    capabilities: List[str] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []

@dataclass
class DHTEntry:
    """Entrada na DHT"""
    key: str
    value: str
    node_id: str
    timestamp: float
    ttl: int = 3600  # 1 hora por padrão

class QuantumDHT:
    """Sistema DHT pós-quântico para QuantumShield"""
    
    def __init__(self, port: int = 8888, node_id: str = None):
        self.port = port
        self.node_id = node_id or self.generate_node_id()
        
        # Tabela de roteamento Kademlia
        self.k_bucket_size = 20
        self.routing_table = {}  # distance -> [nodes]
        self.data_store = {}     # key -> DHTEntry
        
        # Configurações de rede
        self.bootstrap_nodes = [
            # Nós públicos para bootstrap inicial
            ("dht.quantumshield.network", 8888),
            ("bootstrap1.quantumshield.io", 8888),
            ("bootstrap2.quantumshield.io", 8888),
        ]
        
        # Fallback para DHTs públicas
        self.fallback_dhts = [
            ("router.bittorrent.com", 6881),
            ("dht.transmissionbt.com", 6881),
        ]
        
        # Estado da rede
        self.running = False
        self.server_socket = None
        self.known_peers = set()
        self.local_ip = self.get_local_ip()
        
        # Threads
        self.server_thread = None
        self.maintenance_thread = None
        
        # Estatísticas
        self.stats = {
            'nodes_discovered': 0,
            'queries_sent': 0,
            'queries_received': 0,
            'data_stored': 0,
            'uptime_start': time.time()
        }
        
    def generate_node_id(self) -> str:
        """Gera ID único do nó"""
        # Usar informações do sistema para gerar ID único
        system_info = f"{socket.gethostname()}{time.time()}{random.random()}"
        node_hash = hashlib.sha256(system_info.encode()).digest()
        return node_hash.hex()[:40]  # 160 bits como Kademlia
    
    def get_local_ip(self) -> str:
        """Obtém IP local da máquina"""
        try:
            # Tentar obter IP da interface padrão
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                if interface.startswith(('eth', 'wlan', 'en')):
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_INET in addrs:
                        return addrs[netifaces.AF_INET][0]['addr']
            
            # Fallback: conectar a servidor externo
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
                
        except Exception as e:
            logger.warning(f"Erro ao obter IP local: {e}")
            return "127.0.0.1"
    
    def calculate_distance(self, node_id1: str, node_id2: str) -> int:
        """Calcula distância XOR entre dois nós"""
        id1_bytes = bytes.fromhex(node_id1)
        id2_bytes = bytes.fromhex(node_id2)
        
        distance = 0
        for b1, b2 in zip(id1_bytes, id2_bytes):
            distance = (distance << 8) | (b1 ^ b2)
        
        return distance
    
    def get_bucket_index(self, distance: int) -> int:
        """Obtém índice do bucket baseado na distância"""
        if distance == 0:
            return 0
        return distance.bit_length() - 1
    
    def add_node(self, node: DHTNode):
        """Adiciona nó à tabela de roteamento"""
        if node.node_id == self.node_id:
            return  # Não adicionar a si mesmo
        
        distance = self.calculate_distance(self.node_id, node.node_id)
        bucket_index = self.get_bucket_index(distance)
        
        if bucket_index not in self.routing_table:
            self.routing_table[bucket_index] = []
        
        bucket = self.routing_table[bucket_index]
        
        # Verificar se nó já existe
        for i, existing_node in enumerate(bucket):
            if existing_node.node_id == node.node_id:
                # Atualizar nó existente
                bucket[i] = node
                return
        
        # Adicionar novo nó
        if len(bucket) < self.k_bucket_size:
            bucket.append(node)
            self.stats['nodes_discovered'] += 1
            logger.info(f"Nó adicionado: {node.node_id[:16]}... ({node.ip_address}:{node.port})")
        else:
            # Bucket cheio, implementar estratégia de substituição
            # Por simplicidade, substituir o mais antigo
            oldest_node = min(bucket, key=lambda n: n.last_seen)
            if node.last_seen > oldest_node.last_seen:
                bucket.remove(oldest_node)
                bucket.append(node)
    
    def find_closest_nodes(self, target_id: str, count: int = 20) -> List[DHTNode]:
        """Encontra nós mais próximos de um ID alvo"""
        all_nodes = []
        
        for bucket in self.routing_table.values():
            all_nodes.extend(bucket)
        
        # Calcular distâncias e ordenar
        nodes_with_distance = []
        for node in all_nodes:
            distance = self.calculate_distance(target_id, node.node_id)
            nodes_with_distance.append((distance, node))
        
        nodes_with_distance.sort(key=lambda x: x[0])
        
        return [node for _, node in nodes_with_distance[:count]]
    
    def store_data(self, key: str, value: str, ttl: int = 3600):
        """Armazena dados na DHT"""
        entry = DHTEntry(
            key=key,
            value=value,
            node_id=self.node_id,
            timestamp=time.time(),
            ttl=ttl
        )
        
        self.data_store[key] = entry
        self.stats['data_stored'] += 1
        logger.info(f"Dados armazenados: {key[:16]}...")
    
    def get_data(self, key: str) -> Optional[str]:
        """Obtém dados da DHT local"""
        if key in self.data_store:
            entry = self.data_store[key]
            
            # Verificar TTL
            if time.time() - entry.timestamp < entry.ttl:
                return entry.value
            else:
                # Dados expirados
                del self.data_store[key]
        
        return None
    
    def create_message(self, msg_type: str, data: Dict) -> bytes:
        """Cria mensagem DHT"""
        message = {
            'type': msg_type,
            'node_id': self.node_id,
            'timestamp': time.time(),
            'data': data
        }
        
        return json.dumps(message).encode('utf-8')
    
    def parse_message(self, data: bytes) -> Optional[Dict]:
        """Analisa mensagem DHT recebida"""
        try:
            message = json.loads(data.decode('utf-8'))
            
            # Validar estrutura básica
            required_fields = ['type', 'node_id', 'timestamp', 'data']
            if all(field in message for field in required_fields):
                return message
            
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning(f"Erro ao analisar mensagem: {e}")
        
        return None
    
    def handle_ping(self, message: Dict, addr: Tuple[str, int]) -> bytes:
        """Processa ping de outro nó"""
        # Adicionar nó remetente
        sender_node = DHTNode(
            node_id=message['node_id'],
            ip_address=addr[0],
            port=addr[1],
            public_key="",  # TODO: Implementar troca de chaves
            last_seen=time.time()
        )
        self.add_node(sender_node)
        
        # Responder com pong
        response_data = {
            'ip': self.local_ip,
            'port': self.port,
            'capabilities': ['blockchain', 'vpn', 'chat', 'storage']
        }
        
        return self.create_message('pong', response_data)
    
    def handle_find_node(self, message: Dict, addr: Tuple[str, int]) -> bytes:
        """Processa busca por nós"""
        target_id = message['data'].get('target_id')
        if not target_id:
            return self.create_message('error', {'message': 'target_id required'})
        
        # Encontrar nós mais próximos
        closest_nodes = self.find_closest_nodes(target_id)
        
        # Converter para formato serializável
        nodes_data = []
        for node in closest_nodes:
            nodes_data.append({
                'node_id': node.node_id,
                'ip': node.ip_address,
                'port': node.port,
                'last_seen': node.last_seen
            })
        
        response_data = {
            'nodes': nodes_data
        }
        
        return self.create_message('nodes', response_data)
    
    def handle_get_value(self, message: Dict, addr: Tuple[str, int]) -> bytes:
        """Processa busca por valor"""
        key = message['data'].get('key')
        if not key:
            return self.create_message('error', {'message': 'key required'})
        
        # Buscar valor local
        value = self.get_data(key)
        
        if value:
            response_data = {
                'key': key,
                'value': value,
                'found': True
            }
        else:
            # Retornar nós mais próximos da chave
            closest_nodes = self.find_closest_nodes(key)
            nodes_data = []
            for node in closest_nodes:
                nodes_data.append({
                    'node_id': node.node_id,
                    'ip': node.ip_address,
                    'port': node.port
                })
            
            response_data = {
                'key': key,
                'found': False,
                'nodes': nodes_data
            }
        
        return self.create_message('value', response_data)
    
    def handle_store(self, message: Dict, addr: Tuple[str, int]) -> bytes:
        """Processa armazenamento de dados"""
        data = message['data']
        key = data.get('key')
        value = data.get('value')
        ttl = data.get('ttl', 3600)
        
        if not key or not value:
            return self.create_message('error', {'message': 'key and value required'})
        
        # Armazenar dados
        self.store_data(key, value, ttl)
        
        response_data = {
            'key': key,
            'stored': True
        }
        
        return self.create_message('stored', response_data)
    
    def start_server(self):
        """Inicia servidor DHT"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            
            logger.info(f"Servidor DHT iniciado em {self.local_ip}:{self.port}")
            
            while self.running:
                try:
                    data, addr = self.server_socket.recvfrom(4096)
                    self.stats['queries_received'] += 1
                    
                    # Processar mensagem em thread separada
                    threading.Thread(
                        target=self.process_message,
                        args=(data, addr),
                        daemon=True
                    ).start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Erro no servidor DHT: {e}")
                        
        except Exception as e:
            logger.error(f"Erro ao iniciar servidor DHT: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def process_message(self, data: bytes, addr: Tuple[str, int]):
        """Processa mensagem recebida"""
        message = self.parse_message(data)
        if not message:
            return
        
        msg_type = message['type']
        response = None
        
        try:
            if msg_type == 'ping':
                response = self.handle_ping(message, addr)
            elif msg_type == 'find_node':
                response = self.handle_find_node(message, addr)
            elif msg_type == 'get_value':
                response = self.handle_get_value(message, addr)
            elif msg_type == 'store':
                response = self.handle_store(message, addr)
            else:
                logger.warning(f"Tipo de mensagem desconhecido: {msg_type}")
                return
            
            # Enviar resposta
            if response:
                self.server_socket.sendto(response, addr)
                
        except Exception as e:
            logger.error(f"Erro ao processar mensagem {msg_type}: {e}")
    
    def send_message(self, target_ip: str, target_port: int, message: bytes) -> Optional[bytes]:
        """Envia mensagem para outro nó"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5.0)  # 5 segundos timeout
                sock.sendto(message, (target_ip, target_port))
                
                self.stats['queries_sent'] += 1
                
                # Aguardar resposta
                response, addr = sock.recvfrom(4096)
                return response
                
        except socket.timeout:
            logger.warning(f"Timeout ao contactar {target_ip}:{target_port}")
        except Exception as e:
            logger.warning(f"Erro ao enviar mensagem para {target_ip}:{target_port}: {e}")
        
        return None
    
    def ping_node(self, ip: str, port: int) -> bool:
        """Faz ping em um nó"""
        ping_msg = self.create_message('ping', {})
        response = self.send_message(ip, port, ping_msg)
        
        if response:
            message = self.parse_message(response)
            if message and message['type'] == 'pong':
                # Adicionar nó à tabela de roteamento
                node = DHTNode(
                    node_id=message['node_id'],
                    ip_address=ip,
                    port=port,
                    public_key="",
                    last_seen=time.time(),
                    capabilities=message['data'].get('capabilities', [])
                )
                self.add_node(node)
                return True
        
        return False
    
    def bootstrap(self):
        """Faz bootstrap da DHT"""
        logger.info("Iniciando bootstrap da DHT...")
        
        # Tentar nós bootstrap do QuantumShield
        for host, port in self.bootstrap_nodes:
            try:
                # Resolver DNS
                ip = socket.gethostbyname(host)
                if self.ping_node(ip, port):
                    logger.info(f"Bootstrap bem-sucedido com {host}")
                    break
            except socket.gaierror:
                logger.warning(f"Não foi possível resolver {host}")
                continue
        
        # Se não conseguiu bootstrap, tentar DHTs públicas
        if not self.routing_table:
            logger.info("Tentando bootstrap com DHTs públicas...")
            for host, port in self.fallback_dhts:
                try:
                    ip = socket.gethostbyname(host)
                    if self.ping_node(ip, port):
                        logger.info(f"Bootstrap com DHT pública: {host}")
                        break
                except Exception as e:
                    logger.warning(f"Erro no bootstrap com {host}: {e}")
        
        # Buscar nós próximos ao nosso ID
        if self.routing_table:
            self.find_nodes(self.node_id)
    
    def find_nodes(self, target_id: str) -> List[DHTNode]:
        """Busca nós próximos a um ID alvo"""
        if not self.routing_table:
            return []
        
        # Começar com nós conhecidos mais próximos
        closest_nodes = self.find_closest_nodes(target_id, 3)
        
        for node in closest_nodes:
            try:
                find_msg = self.create_message('find_node', {'target_id': target_id})
                response = self.send_message(node.ip_address, node.port, find_msg)
                
                if response:
                    message = self.parse_message(response)
                    if message and message['type'] == 'nodes':
                        # Adicionar nós descobertos
                        for node_data in message['data']['nodes']:
                            new_node = DHTNode(
                                node_id=node_data['node_id'],
                                ip_address=node_data['ip'],
                                port=node_data['port'],
                                public_key="",
                                last_seen=time.time()
                            )
                            self.add_node(new_node)
                            
            except Exception as e:
                logger.warning(f"Erro ao buscar nós via {node.ip_address}: {e}")
        
        return self.find_closest_nodes(target_id)
    
    def maintenance_loop(self):
        """Loop de manutenção da DHT"""
        while self.running:
            try:
                # Limpar dados expirados
                current_time = time.time()
                expired_keys = []
                
                for key, entry in self.data_store.items():
                    if current_time - entry.timestamp > entry.ttl:
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self.data_store[key]
                
                # Verificar nós ativos
                inactive_nodes = []
                for bucket in self.routing_table.values():
                    for node in bucket:
                        if current_time - node.last_seen > 300:  # 5 minutos
                            if not self.ping_node(node.ip_address, node.port):
                                inactive_nodes.append(node)
                
                # Remover nós inativos
                for node in inactive_nodes:
                    for bucket in self.routing_table.values():
                        if node in bucket:
                            bucket.remove(node)
                
                # Buscar novos nós periodicamente
                if random.random() < 0.1:  # 10% de chance
                    random_id = hashlib.sha256(str(random.random()).encode()).hexdigest()[:40]
                    self.find_nodes(random_id)
                
                time.sleep(30)  # Manutenção a cada 30 segundos
                
            except Exception as e:
                logger.error(f"Erro na manutenção DHT: {e}")
                time.sleep(60)
    
    def start(self):
        """Inicia a DHT"""
        if self.running:
            return
        
        self.running = True
        
        # Iniciar servidor
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()
        
        # Aguardar servidor iniciar
        time.sleep(1)
        
        # Fazer bootstrap
        bootstrap_thread = threading.Thread(target=self.bootstrap, daemon=True)
        bootstrap_thread.start()
        
        # Iniciar manutenção
        self.maintenance_thread = threading.Thread(target=self.maintenance_loop, daemon=True)
        self.maintenance_thread.start()
        
        logger.info(f"DHT iniciada - Node ID: {self.node_id[:16]}...")
    
    def stop(self):
        """Para a DHT"""
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        logger.info("DHT parada")
    
    def get_stats(self) -> Dict:
        """Obtém estatísticas da DHT"""
        uptime = time.time() - self.stats['uptime_start']
        
        return {
            'node_id': self.node_id[:16] + "...",
            'local_ip': self.local_ip,
            'port': self.port,
            'uptime_seconds': int(uptime),
            'nodes_in_routing_table': sum(len(bucket) for bucket in self.routing_table.values()),
            'data_entries': len(self.data_store),
            'nodes_discovered': self.stats['nodes_discovered'],
            'queries_sent': self.stats['queries_sent'],
            'queries_received': self.stats['queries_received'],
            'data_stored': self.stats['data_stored']
        }
    
    def announce_service(self, service_type: str, service_data: Dict):
        """Anuncia serviço na DHT"""
        key = f"service:{service_type}:{self.node_id}"
        value = json.dumps({
            'node_id': self.node_id,
            'ip': self.local_ip,
            'port': self.port,
            'service_data': service_data,
            'timestamp': time.time()
        })
        
        self.store_data(key, value, ttl=1800)  # 30 minutos
        logger.info(f"Serviço anunciado: {service_type}")
    
    def find_services(self, service_type: str) -> List[Dict]:
        """Busca serviços na DHT"""
        services = []
        
        # Buscar em dados locais
        for key, entry in self.data_store.items():
            if key.startswith(f"service:{service_type}:"):
                try:
                    service_data = json.loads(entry.value)
                    services.append(service_data)
                except json.JSONDecodeError:
                    continue
        
        return services

def test_quantum_dht():
    """Teste do sistema DHT"""
    print("🛡️ Testando QuantumDHT...")
    
    # Criar duas instâncias DHT
    dht1 = QuantumDHT(port=8888)
    dht2 = QuantumDHT(port=8889)
    
    try:
        # Iniciar DHTs
        print("\n🚀 Iniciando DHTs...")
        dht1.start()
        time.sleep(2)
        dht2.start()
        time.sleep(3)
        
        # Fazer DHT2 se conectar com DHT1
        print("\n🔗 Conectando DHTs...")
        if dht2.ping_node(dht1.local_ip, dht1.port):
            print("✅ Conexão estabelecida")
        
        # Armazenar dados
        print("\n💾 Armazenando dados...")
        dht1.store_data("test_key", "test_value", ttl=300)
        
        # Buscar dados
        print("\n🔍 Buscando dados...")
        value = dht1.get_data("test_key")
        print(f"Valor encontrado: {value}")
        
        # Anunciar serviço
        print("\n📢 Anunciando serviço...")
        dht1.announce_service("blockchain", {
            "coin_types": ["QTC", "QTG", "QTS"],
            "mining_active": True
        })
        
        # Buscar serviços
        print("\n🔍 Buscando serviços...")
        services = dht1.find_services("blockchain")
        print(f"Serviços encontrados: {len(services)}")
        
        # Estatísticas
        print("\n📊 Estatísticas DHT1:")
        stats1 = dht1.get_stats()
        for key, value in stats1.items():
            print(f"  {key}: {value}")
        
        print("\n📊 Estatísticas DHT2:")
        stats2 = dht2.get_stats()
        for key, value in stats2.items():
            print(f"  {key}: {value}")
        
        print("\n✅ Teste DHT concluído com sucesso!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        return False
    finally:
        dht1.stop()
        dht2.stop()

if __name__ == "__main__":
    test_quantum_dht()

