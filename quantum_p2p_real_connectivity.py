#!/usr/bin/env python3
"""
🛡️ QuantumShield - P2P Real Connectivity System
Arquivo: quantum_p2p_real_connectivity.py
Descrição: Sistema de conectividade P2P real para testes entre máquinas
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import socket
import threading
import time
import json
import logging
import netifaces
import requests
import subprocess
import platform
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import secrets
import ipaddress

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class NetworkInterface:
    """Interface de rede detectada"""
    name: str
    ip_address: str
    netmask: str
    broadcast: str
    is_active: bool
    is_wireless: bool
    mac_address: str

@dataclass
class ExternalConnectivity:
    """Informações de conectividade externa"""
    public_ip: str
    country: str
    isp: str
    nat_type: str
    upnp_available: bool
    port_forwarding_possible: bool

@dataclass
class P2PTestResult:
    """Resultado de teste P2P"""
    test_type: str
    success: bool
    latency_ms: float
    bandwidth_mbps: float
    error_message: str = ""
    details: Dict = None

class QuantumP2PRealConnectivity:
    """Sistema de conectividade P2P real"""
    
    def __init__(self, test_port: int = 8888):
        self.test_port = test_port
        self.local_interfaces = []
        self.external_info = None
        self.test_results = []
        
        # Servidores de teste públicos
        self.test_servers = [
            ("8.8.8.8", 53),      # Google DNS
            ("1.1.1.1", 53),      # Cloudflare DNS
            ("208.67.222.222", 53) # OpenDNS
        ]
        
        # Servidores STUN para teste NAT
        self.stun_servers = [
            "stun.l.google.com:19302",
            "stun1.l.google.com:19302",
            "stun2.l.google.com:19302",
            "stun.cloudflare.com:3478"
        ]
        
        self.initialize_network_detection()
    
    def initialize_network_detection(self):
        """Inicializa detecção de rede"""
        try:
            self.detect_network_interfaces()
            self.detect_external_connectivity()
            logger.info("Detecção de rede inicializada com sucesso")
        except Exception as e:
            logger.error(f"Erro na inicialização de rede: {e}")
    
    def detect_network_interfaces(self):
        """Detecta interfaces de rede disponíveis"""
        try:
            self.local_interfaces = []
            
            for interface_name in netifaces.interfaces():
                try:
                    # Obter informações da interface
                    addrs = netifaces.ifaddresses(interface_name)
                    
                    # Verificar se tem IPv4
                    if netifaces.AF_INET in addrs:
                        ipv4_info = addrs[netifaces.AF_INET][0]
                        
                        # Verificar se tem MAC address
                        mac_address = ""
                        if netifaces.AF_LINK in addrs:
                            mac_address = addrs[netifaces.AF_LINK][0].get('addr', '')
                        
                        # Verificar se interface está ativa
                        is_active = self.is_interface_active(interface_name)
                        
                        # Detectar se é wireless
                        is_wireless = self.is_wireless_interface(interface_name)
                        
                        interface = NetworkInterface(
                            name=interface_name,
                            ip_address=ipv4_info['addr'],
                            netmask=ipv4_info['netmask'],
                            broadcast=ipv4_info.get('broadcast', ''),
                            is_active=is_active,
                            is_wireless=is_wireless,
                            mac_address=mac_address
                        )
                        
                        # Filtrar loopback e interfaces inativas
                        if (interface.ip_address != '127.0.0.1' and 
                            interface.is_active and 
                            not interface.ip_address.startswith('169.254')):
                            self.local_interfaces.append(interface)
                            
                except Exception as e:
                    logger.warning(f"Erro ao processar interface {interface_name}: {e}")
            
            logger.info(f"Detectadas {len(self.local_interfaces)} interfaces ativas")
            
        except Exception as e:
            logger.error(f"Erro na detecção de interfaces: {e}")
    
    def is_interface_active(self, interface_name: str) -> bool:
        """Verifica se interface está ativa"""
        try:
            if platform.system() == "Linux":
                result = subprocess.run(
                    ["cat", f"/sys/class/net/{interface_name}/operstate"],
                    capture_output=True, text=True, timeout=5
                )
                return result.stdout.strip() == "up"
            elif platform.system() == "Windows":
                # Para Windows, assumir ativo se tem IP
                return True
            else:
                return True
        except:
            return True
    
    def is_wireless_interface(self, interface_name: str) -> bool:
        """Detecta se interface é wireless"""
        try:
            wireless_indicators = ['wlan', 'wifi', 'wl', 'ath', 'ra']
            return any(indicator in interface_name.lower() for indicator in wireless_indicators)
        except:
            return False
    
    def detect_external_connectivity(self):
        """Detecta conectividade externa e informações públicas"""
        try:
            # Obter IP público
            public_ip = self.get_public_ip()
            
            # Obter informações geográficas
            geo_info = self.get_geo_info(public_ip)
            
            # Detectar tipo de NAT
            nat_type = self.detect_nat_type()
            
            # Verificar UPnP
            upnp_available = self.check_upnp_availability()
            
            self.external_info = ExternalConnectivity(
                public_ip=public_ip,
                country=geo_info.get('country', 'Unknown'),
                isp=geo_info.get('isp', 'Unknown'),
                nat_type=nat_type,
                upnp_available=upnp_available,
                port_forwarding_possible=upnp_available or nat_type in ['Full Cone', 'Restricted Cone']
            )
            
            logger.info(f"IP público: {public_ip}, NAT: {nat_type}")
            
        except Exception as e:
            logger.error(f"Erro na detecção de conectividade externa: {e}")
            self.external_info = ExternalConnectivity(
                public_ip="Unknown",
                country="Unknown",
                isp="Unknown",
                nat_type="Unknown",
                upnp_available=False,
                port_forwarding_possible=False
            )
    
    def get_public_ip(self) -> str:
        """Obtém IP público"""
        services = [
            "https://api.ipify.org",
            "https://ipinfo.io/ip",
            "https://icanhazip.com"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # Validar se é um IP válido
                    ipaddress.ip_address(ip)
                    return ip
            except Exception as e:
                logger.warning(f"Falha ao obter IP de {service}: {e}")
        
        return "Unknown"
    
    def get_geo_info(self, ip: str) -> Dict:
        """Obtém informações geográficas do IP"""
        try:
            if ip == "Unknown":
                return {}
            
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.warning(f"Falha ao obter geo info: {e}")
        
        return {}
    
    def detect_nat_type(self) -> str:
        """Detecta tipo de NAT usando STUN"""
        try:
            # Implementação simplificada de detecção NAT
            # Em produção, usaria biblioteca STUN completa
            
            for stun_server in self.stun_servers:
                try:
                    host, port = stun_server.split(':')
                    port = int(port)
                    
                    # Teste básico de conectividade STUN
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(5)
                    
                    # Enviar request STUN básico
                    stun_request = b'\x00\x01\x00\x00' + secrets.token_bytes(16)
                    sock.sendto(stun_request, (host, port))
                    
                    # Receber resposta
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    
                    # Se recebeu resposta, NAT permite UDP
                    return "Cone NAT (UDP OK)"
                    
                except Exception as e:
                    continue
            
            return "Symmetric NAT (Restritivo)"
            
        except Exception as e:
            logger.warning(f"Erro na detecção NAT: {e}")
            return "Unknown NAT"
    
    def check_upnp_availability(self) -> bool:
        """Verifica disponibilidade UPnP"""
        try:
            # Enviar descoberta UPnP SSDP
            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "ST: upnp:rootdevice\r\n"
                "MX: 3\r\n\r\n"
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(ssdp_request.encode(), ('239.255.255.250', 1900))
            
            # Tentar receber resposta
            data, addr = sock.recvfrom(1024)
            sock.close()
            
            return True
            
        except Exception as e:
            logger.debug(f"UPnP não disponível: {e}")
            return False
    
    def test_connectivity_to_peer(self, peer_ip: str, peer_port: int) -> P2PTestResult:
        """Testa conectividade com peer específico"""
        start_time = time.perf_counter()
        
        try:
            # Teste TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            result = sock.connect_ex((peer_ip, peer_port))
            
            if result == 0:
                # Conexão bem-sucedida
                latency = (time.perf_counter() - start_time) * 1000
                
                # Teste de bandwidth básico
                test_data = b"QUANTUMSHIELD_BANDWIDTH_TEST" * 100
                sock.send(test_data)
                
                bandwidth_start = time.perf_counter()
                sock.recv(1024)
                bandwidth_time = time.perf_counter() - bandwidth_start
                bandwidth_mbps = (len(test_data) * 8) / (bandwidth_time * 1000000)
                
                sock.close()
                
                return P2PTestResult(
                    test_type="TCP Direct",
                    success=True,
                    latency_ms=latency,
                    bandwidth_mbps=bandwidth_mbps,
                    details={"peer_ip": peer_ip, "peer_port": peer_port}
                )
            else:
                sock.close()
                return P2PTestResult(
                    test_type="TCP Direct",
                    success=False,
                    latency_ms=0,
                    bandwidth_mbps=0,
                    error_message=f"Conexão falhou: {result}",
                    details={"peer_ip": peer_ip, "peer_port": peer_port}
                )
                
        except Exception as e:
            return P2PTestResult(
                test_type="TCP Direct",
                success=False,
                latency_ms=0,
                bandwidth_mbps=0,
                error_message=str(e),
                details={"peer_ip": peer_ip, "peer_port": peer_port}
            )
    
    def test_hole_punching(self, peer_ip: str, peer_port: int) -> P2PTestResult:
        """Testa hole punching UDP"""
        try:
            # Implementação básica de hole punching
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', self.test_port))
            sock.settimeout(10)
            
            # Enviar pacotes para "furar" NAT
            punch_message = b"QUANTUMSHIELD_HOLE_PUNCH"
            
            for i in range(5):
                sock.sendto(punch_message, (peer_ip, peer_port))
                time.sleep(0.1)
            
            # Tentar receber resposta
            start_time = time.perf_counter()
            data, addr = sock.recvfrom(1024)
            latency = (time.perf_counter() - start_time) * 1000
            
            sock.close()
            
            if data == punch_message:
                return P2PTestResult(
                    test_type="UDP Hole Punching",
                    success=True,
                    latency_ms=latency,
                    bandwidth_mbps=0,  # Não testado para UDP
                    details={"peer_ip": peer_ip, "peer_port": peer_port}
                )
            else:
                return P2PTestResult(
                    test_type="UDP Hole Punching",
                    success=False,
                    latency_ms=0,
                    bandwidth_mbps=0,
                    error_message="Resposta inválida",
                    details={"peer_ip": peer_ip, "peer_port": peer_port}
                )
                
        except Exception as e:
            return P2PTestResult(
                test_type="UDP Hole Punching",
                success=False,
                latency_ms=0,
                bandwidth_mbps=0,
                error_message=str(e),
                details={"peer_ip": peer_ip, "peer_port": peer_port}
            )
    
    def start_test_server(self):
        """Inicia servidor de teste para receber conexões"""
        def server_thread():
            try:
                # Servidor TCP
                tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp_server.bind(('0.0.0.0', self.test_port))
                tcp_server.listen(5)
                tcp_server.settimeout(1)
                
                logger.info(f"Servidor de teste TCP iniciado na porta {self.test_port}")
                
                while True:
                    try:
                        client_sock, client_addr = tcp_server.accept()
                        logger.info(f"Conexão TCP recebida de {client_addr}")
                        
                        # Echo server simples
                        data = client_sock.recv(1024)
                        client_sock.send(data)
                        client_sock.close()
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Erro no servidor TCP: {e}")
                        break
                        
            except Exception as e:
                logger.error(f"Erro ao iniciar servidor TCP: {e}")
        
        def udp_server_thread():
            try:
                # Servidor UDP
                udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_server.bind(('0.0.0.0', self.test_port + 1))
                udp_server.settimeout(1)
                
                logger.info(f"Servidor de teste UDP iniciado na porta {self.test_port + 1}")
                
                while True:
                    try:
                        data, addr = udp_server.recvfrom(1024)
                        logger.info(f"Pacote UDP recebido de {addr}")
                        
                        # Echo UDP
                        udp_server.sendto(data, addr)
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Erro no servidor UDP: {e}")
                        break
                        
            except Exception as e:
                logger.error(f"Erro ao iniciar servidor UDP: {e}")
        
        # Iniciar servidores em threads separadas
        tcp_thread = threading.Thread(target=server_thread, daemon=True)
        udp_thread = threading.Thread(target=udp_server_thread, daemon=True)
        
        tcp_thread.start()
        udp_thread.start()
        
        return tcp_thread, udp_thread
    
    def run_comprehensive_test(self, peer_ip: str, peer_port: int) -> Dict:
        """Executa teste abrangente de conectividade"""
        results = {
            'timestamp': time.time(),
            'local_interfaces': [asdict(iface) for iface in self.local_interfaces],
            'external_info': asdict(self.external_info) if self.external_info else None,
            'tests': []
        }
        
        # Teste 1: Conectividade TCP direta
        tcp_result = self.test_connectivity_to_peer(peer_ip, peer_port)
        results['tests'].append(asdict(tcp_result))
        
        # Teste 2: Hole punching UDP
        udp_result = self.test_hole_punching(peer_ip, peer_port + 1)
        results['tests'].append(asdict(udp_result))
        
        # Teste 3: Conectividade com servidores públicos
        for server_ip, server_port in self.test_servers:
            public_result = self.test_connectivity_to_peer(server_ip, server_port)
            public_result.test_type = f"Public Server ({server_ip})"
            results['tests'].append(asdict(public_result))
        
        return results
    
    def get_network_summary(self) -> Dict:
        """Retorna resumo da configuração de rede"""
        return {
            'local_interfaces_count': len(self.local_interfaces),
            'active_interfaces': [iface.name for iface in self.local_interfaces if iface.is_active],
            'wireless_interfaces': [iface.name for iface in self.local_interfaces if iface.is_wireless],
            'public_ip': self.external_info.public_ip if self.external_info else "Unknown",
            'nat_type': self.external_info.nat_type if self.external_info else "Unknown",
            'upnp_available': self.external_info.upnp_available if self.external_info else False,
            'p2p_ready': self.is_p2p_ready()
        }
    
    def is_p2p_ready(self) -> bool:
        """Verifica se sistema está pronto para P2P"""
        if not self.local_interfaces:
            return False
        
        if not self.external_info:
            return False
        
        # Verificar se tem pelo menos uma interface ativa
        active_interfaces = [iface for iface in self.local_interfaces if iface.is_active]
        if not active_interfaces:
            return False
        
        # Verificar se NAT permite P2P
        if self.external_info.nat_type in ['Unknown NAT', 'Symmetric NAT (Restritivo)']:
            return self.external_info.upnp_available
        
        return True

def main():
    """Função principal para testes"""
    print("🌐 QuantumShield - Teste de Conectividade P2P Real")
    print("=" * 50)
    
    # Inicializar sistema
    connectivity = QuantumP2PRealConnectivity()
    
    # Mostrar resumo da rede
    summary = connectivity.get_network_summary()
    print(f"📊 Resumo da Rede:")
    print(f"   Interfaces ativas: {summary['active_interfaces']}")
    print(f"   IP público: {summary['public_ip']}")
    print(f"   Tipo NAT: {summary['nat_type']}")
    print(f"   UPnP disponível: {summary['upnp_available']}")
    print(f"   Pronto para P2P: {summary['p2p_ready']}")
    print()
    
    # Iniciar servidores de teste
    print("🚀 Iniciando servidores de teste...")
    tcp_thread, udp_thread = connectivity.start_test_server()
    
    print(f"✅ Servidores iniciados:")
    print(f"   TCP: porta {connectivity.test_port}")
    print(f"   UDP: porta {connectivity.test_port + 1}")
    print()
    
    # Aguardar conexões
    print("⏳ Aguardando conexões de teste...")
    print("   Para testar de outra máquina, use:")
    print(f"   telnet {summary['public_ip']} {connectivity.test_port}")
    print()
    
    # Manter servidores rodando
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Teste interrompido pelo usuário")

if __name__ == "__main__":
    main()

