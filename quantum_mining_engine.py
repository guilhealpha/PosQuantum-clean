#!/usr/bin/env python3
"""
🛡️ QuantumShield - Engine de Mineração QuantumCoin
Arquivo: quantum_mining_engine.py
Descrição: Sistema de mineração real para as 3 criptomoedas QuantumShield
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import hashlib
import json
import time
import threading
import multiprocessing
import os
import sqlite3
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from decimal import Decimal, getcontext
from pathlib import Path
import logging
from enum import Enum
import random
import struct

# Configurar precisão decimal
getcontext().prec = 18

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CoinType(Enum):
    """Tipos de criptomoedas QuantumShield"""
    QTC = "QTC"  # QuantumCoin - $1.00 USD
    QTG = "QTG"  # QuantumGold - $0.50 USD  
    QTS = "QTS"  # QuantumSilver - $0.01 USD

@dataclass
class MiningConfig:
    """Configuração de mineração"""
    coin_type: CoinType
    difficulty: int = 4
    block_reward: Decimal = Decimal('50.0')
    target_block_time: int = 60  # segundos
    max_threads: int = 2
    enabled: bool = True

@dataclass
class MiningStats:
    """Estatísticas de mineração"""
    hashrate: float = 0.0
    blocks_mined: int = 0
    total_rewards: Decimal = Decimal('0.0')
    uptime: float = 0.0
    last_block_time: float = 0.0
    difficulty: int = 4
    threads_active: int = 0

class QuantumProofOfWork:
    """Sistema de Proof-of-Work pós-quântico"""
    
    def __init__(self, difficulty: int = 4):
        self.difficulty = difficulty
        self.target = "0" * difficulty
        
    def calculate_hash(self, block_data: str, nonce: int) -> str:
        """Calcula hash do bloco com nonce"""
        data = f"{block_data}{nonce}"
        
        # Usar múltiplos algoritmos de hash para segurança pós-quântica
        sha3_hash = hashlib.sha3_256(data.encode()).hexdigest()
        blake2_hash = hashlib.blake2b(data.encode(), digest_size=32).hexdigest()
        
        # Combinar hashes para maior segurança
        combined = f"{sha3_hash}{blake2_hash}"
        final_hash = hashlib.sha3_512(combined.encode()).hexdigest()
        
        return final_hash
    
    def is_valid_hash(self, hash_value: str) -> bool:
        """Verifica se o hash atende à dificuldade"""
        return hash_value.startswith(self.target)
    
    def mine_block(self, block_data: str, max_nonce: int = 1000000) -> Tuple[Optional[int], Optional[str]]:
        """Minera um bloco procurando nonce válido"""
        for nonce in range(max_nonce):
            hash_value = self.calculate_hash(block_data, nonce)
            if self.is_valid_hash(hash_value):
                return nonce, hash_value
        return None, None
    
    def adjust_difficulty(self, actual_time: float, target_time: float) -> int:
        """Ajusta dificuldade baseado no tempo de mineração"""
        if actual_time < target_time * 0.5:
            return min(self.difficulty + 1, 10)  # Aumentar dificuldade
        elif actual_time > target_time * 2:
            return max(self.difficulty - 1, 1)   # Diminuir dificuldade
        return self.difficulty

class QuantumMiningEngine:
    """Engine principal de mineração QuantumCoin"""
    
    def __init__(self, wallet_address: str, data_dir: str = "blockchain_data"):
        self.wallet_address = wallet_address
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Configurações de mineração para cada moeda
        self.mining_configs = {
            CoinType.QTC: MiningConfig(
                coin_type=CoinType.QTC,
                difficulty=4,
                block_reward=Decimal('50.0'),
                target_block_time=60,
                max_threads=2
            ),
            CoinType.QTG: MiningConfig(
                coin_type=CoinType.QTG,
                difficulty=3,
                block_reward=Decimal('25.0'),
                target_block_time=45,
                max_threads=1
            ),
            CoinType.QTS: MiningConfig(
                coin_type=CoinType.QTS,
                difficulty=2,
                block_reward=Decimal('100.0'),
                target_block_time=30,
                max_threads=1
            )
        }
        
        # Estatísticas de mineração
        self.mining_stats = {
            coin_type: MiningStats() for coin_type in CoinType
        }
        
        # Sistemas de PoW para cada moeda
        self.pow_systems = {
            coin_type: QuantumProofOfWork(config.difficulty)
            for coin_type, config in self.mining_configs.items()
        }
        
        # Controle de threads
        self.mining_threads = {}
        self.stop_mining = threading.Event()
        self.mining_active = False
        
        # Blockchain storage
        self.init_blockchain_storage()
        
        # Métricas
        self.start_time = time.time()
        self.hash_count = 0
        self.last_hash_time = time.time()
        
    def init_blockchain_storage(self):
        """Inicializa armazenamento do blockchain"""
        self.db_path = self.data_dir / "quantum_blockchain.db"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Tabela de blocos
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    coin_type TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    previous_hash TEXT NOT NULL,
                    merkle_root TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    nonce INTEGER NOT NULL,
                    hash TEXT NOT NULL,
                    difficulty INTEGER NOT NULL,
                    miner_address TEXT NOT NULL,
                    reward DECIMAL NOT NULL,
                    transactions_count INTEGER DEFAULT 0,
                    block_size INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(coin_type, block_number)
                )
            """)
            
            # Tabela de transações
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    coin_type TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    transaction_id TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    amount DECIMAL NOT NULL,
                    fee DECIMAL DEFAULT 0,
                    timestamp REAL NOT NULL,
                    signature TEXT NOT NULL,
                    status TEXT DEFAULT 'confirmed',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(transaction_id)
                )
            """)
            
            # Tabela de carteiras
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    coin_type TEXT NOT NULL,
                    balance DECIMAL DEFAULT 0,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(address, coin_type)
                )
            """)
            
            # Tabela de estatísticas de mineração
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mining_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    coin_type TEXT NOT NULL,
                    date DATE NOT NULL,
                    blocks_mined INTEGER DEFAULT 0,
                    total_rewards DECIMAL DEFAULT 0,
                    average_hashrate REAL DEFAULT 0,
                    uptime_seconds INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(coin_type, date)
                )
            """)
            
            conn.commit()
            
        # Criar blocos genesis se necessário
        self.create_genesis_blocks()
        
    def create_genesis_blocks(self):
        """Cria blocos genesis para cada criptomoeda"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for coin_type in CoinType:
                # Verificar se já existe bloco genesis
                cursor.execute(
                    "SELECT COUNT(*) FROM blocks WHERE coin_type = ? AND block_number = 0",
                    (coin_type.value,)
                )
                
                if cursor.fetchone()[0] == 0:
                    # Criar bloco genesis
                    genesis_block = self.create_genesis_block(coin_type)
                    self.save_block_to_db(genesis_block, coin_type)
                    
                    # Criar carteira inicial com recompensa genesis
                    self.update_wallet_balance(
                        self.wallet_address,
                        coin_type,
                        genesis_block['reward']
                    )
                    
                    logger.info(f"Bloco genesis criado para {coin_type.value}")
    
    def create_genesis_block(self, coin_type: CoinType) -> Dict:
        """Cria bloco genesis para uma criptomoeda"""
        timestamp = time.time()
        
        # Recompensa inicial especial
        initial_rewards = {
            CoinType.QTC: Decimal('1000.0'),  # 1000 QTC inicial
            CoinType.QTG: Decimal('500.0'),   # 500 QTG inicial  
            CoinType.QTS: Decimal('10000.0')  # 10000 QTS inicial
        }
        
        genesis_data = {
            'block_number': 0,
            'previous_hash': '0' * 64,
            'merkle_root': hashlib.sha3_256(f"genesis_{coin_type.value}".encode()).hexdigest(),
            'timestamp': timestamp,
            'miner_address': self.wallet_address,
            'reward': initial_rewards[coin_type],
            'transactions': [],
            'difficulty': 1
        }
        
        # Minerar bloco genesis (fácil)
        block_data_for_mining = {
            k: (float(v) if isinstance(v, Decimal) else v) 
            for k, v in genesis_data.items()
        }
        block_data = json.dumps(block_data_for_mining, sort_keys=True)
        nonce, block_hash = self.pow_systems[coin_type].mine_block(block_data, max_nonce=10000)
        
        genesis_data.update({
            'nonce': nonce or 0,
            'hash': block_hash or hashlib.sha3_256(block_data.encode()).hexdigest()
        })
        
        return genesis_data
    
    def save_block_to_db(self, block: Dict, coin_type: CoinType):
        """Salva bloco no banco de dados"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Converter Decimal para float para serialização
            block_for_size = {
                k: (float(v) if isinstance(v, Decimal) else v) 
                for k, v in block.items()
            }
            
            cursor.execute("""
                INSERT OR REPLACE INTO blocks (
                    coin_type, block_number, previous_hash, merkle_root,
                    timestamp, nonce, hash, difficulty, miner_address,
                    reward, transactions_count, block_size
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                coin_type.value,
                block['block_number'],
                block['previous_hash'],
                block['merkle_root'],
                block['timestamp'],
                block['nonce'],
                block['hash'],
                block['difficulty'],
                block['miner_address'],
                float(block['reward']),
                len(block.get('transactions', [])),
                len(json.dumps(block_for_size))
            ))
            
            conn.commit()
    
    def update_wallet_balance(self, address: str, coin_type: CoinType, amount: Decimal):
        """Atualiza saldo da carteira"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Obter saldo atual
            cursor.execute(
                "SELECT balance FROM wallets WHERE address = ? AND coin_type = ?",
                (address, coin_type.value)
            )
            
            result = cursor.fetchone()
            current_balance = Decimal(str(result[0])) if result else Decimal('0')
            new_balance = current_balance + amount
            
            # Atualizar ou inserir
            cursor.execute("""
                INSERT OR REPLACE INTO wallets (address, coin_type, balance, last_updated)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """, (address, coin_type.value, float(new_balance)))
            
            conn.commit()
            
            logger.info(f"Carteira {address} atualizada: {coin_type.value} = {new_balance}")
    
    def get_wallet_balance(self, address: str, coin_type: CoinType) -> Decimal:
        """Obtém saldo da carteira"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT balance FROM wallets WHERE address = ? AND coin_type = ?",
                (address, coin_type.value)
            )
            
            result = cursor.fetchone()
            return Decimal(str(result[0])) if result else Decimal('0')
    
    def get_latest_block(self, coin_type: CoinType) -> Optional[Dict]:
        """Obtém último bloco de uma criptomoeda"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM blocks 
                WHERE coin_type = ? 
                ORDER BY block_number DESC 
                LIMIT 1
            """, (coin_type.value,))
            
            result = cursor.fetchone()
            if result:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, result))
            return None
    
    def start_mining(self, coin_types: List[CoinType] = None):
        """Inicia mineração para as criptomoedas especificadas"""
        if coin_types is None:
            coin_types = list(CoinType)
        
        if self.mining_active:
            logger.warning("Mineração já está ativa")
            return
        
        self.mining_active = True
        self.stop_mining.clear()
        
        logger.info(f"Iniciando mineração para: {[ct.value for ct in coin_types]}")
        
        # Iniciar thread de mineração para cada moeda
        for coin_type in coin_types:
            if self.mining_configs[coin_type].enabled:
                thread = threading.Thread(
                    target=self._mining_worker,
                    args=(coin_type,),
                    daemon=True
                )
                thread.start()
                self.mining_threads[coin_type] = thread
                
                logger.info(f"Thread de mineração iniciada para {coin_type.value}")
        
        # Thread de monitoramento
        monitor_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        monitor_thread.start()
        
    def stop_mining_process(self):
        """Para o processo de mineração"""
        if not self.mining_active:
            return
        
        logger.info("Parando mineração...")
        self.stop_mining.set()
        self.mining_active = False
        
        # Aguardar threads terminarem
        for coin_type, thread in self.mining_threads.items():
            if thread.is_alive():
                thread.join(timeout=5)
                logger.info(f"Thread de mineração {coin_type.value} finalizada")
        
        self.mining_threads.clear()
        logger.info("Mineração parada")
    
    def _mining_worker(self, coin_type: CoinType):
        """Worker de mineração para uma criptomoeda"""
        config = self.mining_configs[coin_type]
        pow_system = self.pow_systems[coin_type]
        stats = self.mining_stats[coin_type]
        
        stats.threads_active = 1
        
        while not self.stop_mining.is_set():
            try:
                # Obter último bloco
                latest_block = self.get_latest_block(coin_type)
                if not latest_block:
                    logger.error(f"Não foi possível obter último bloco para {coin_type.value}")
                    time.sleep(5)
                    continue
                
                # Criar novo bloco
                new_block = self._create_new_block(coin_type, latest_block)
                
                # Minerar bloco
                start_time = time.time()
                block_data_for_mining = {
                    k: (float(v) if isinstance(v, Decimal) else v) 
                    for k, v in new_block.items() 
                    if k not in ['nonce', 'hash']
                }
                block_data = json.dumps(block_data_for_mining, sort_keys=True)
                
                nonce, block_hash = pow_system.mine_block(block_data, max_nonce=100000)
                mining_time = time.time() - start_time
                
                if nonce is not None and block_hash is not None:
                    # Bloco minerado com sucesso
                    new_block['nonce'] = nonce
                    new_block['hash'] = block_hash
                    
                    # Salvar bloco
                    self.save_block_to_db(new_block, coin_type)
                    
                    # Atualizar carteira do minerador
                    self.update_wallet_balance(
                        self.wallet_address,
                        coin_type,
                        config.block_reward
                    )
                    
                    # Atualizar estatísticas
                    stats.blocks_mined += 1
                    stats.total_rewards += config.block_reward
                    stats.last_block_time = time.time()
                    
                    # Ajustar dificuldade
                    new_difficulty = pow_system.adjust_difficulty(
                        mining_time, 
                        config.target_block_time
                    )
                    if new_difficulty != pow_system.difficulty:
                        pow_system.difficulty = new_difficulty
                        config.difficulty = new_difficulty
                        logger.info(f"Dificuldade {coin_type.value} ajustada para {new_difficulty}")
                    
                    logger.info(
                        f"Bloco {new_block['block_number']} minerado para {coin_type.value} "
                        f"em {mining_time:.2f}s (nonce: {nonce})"
                    )
                    
                    # Aguardar antes do próximo bloco
                    time.sleep(config.target_block_time)
                else:
                    # Não conseguiu minerar, tentar novamente
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Erro na mineração {coin_type.value}: {e}")
                time.sleep(5)
        
        stats.threads_active = 0
    
    def _create_new_block(self, coin_type: CoinType, previous_block: Dict) -> Dict:
        """Cria novo bloco para mineração"""
        timestamp = time.time()
        config = self.mining_configs[coin_type]
        
        new_block = {
            'block_number': previous_block['block_number'] + 1,
            'previous_hash': previous_block['hash'],
            'merkle_root': hashlib.sha3_256(f"block_{timestamp}".encode()).hexdigest(),
            'timestamp': timestamp,
            'miner_address': self.wallet_address,
            'reward': config.block_reward,
            'transactions': [],  # TODO: Adicionar transações pendentes
            'difficulty': config.difficulty
        }
        
        return new_block
    
    def _monitoring_worker(self):
        """Worker de monitoramento de mineração"""
        while not self.stop_mining.is_set():
            try:
                # Calcular hashrate
                current_time = time.time()
                time_diff = current_time - self.last_hash_time
                
                if time_diff >= 5:  # Atualizar a cada 5 segundos
                    hashrate = self.hash_count / time_diff if time_diff > 0 else 0
                    
                    # Atualizar estatísticas
                    for coin_type in CoinType:
                        stats = self.mining_stats[coin_type]
                        stats.hashrate = hashrate / len(CoinType)  # Dividir entre moedas
                        stats.uptime = current_time - self.start_time
                    
                    self.hash_count = 0
                    self.last_hash_time = current_time
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Erro no monitoramento: {e}")
                time.sleep(5)
    
    def get_mining_stats(self) -> Dict[str, MiningStats]:
        """Obtém estatísticas de mineração"""
        return {coin_type.value: stats for coin_type, stats in self.mining_stats.items()}
    
    def get_blockchain_info(self, coin_type: CoinType) -> Dict:
        """Obtém informações do blockchain"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Contar blocos
            cursor.execute(
                "SELECT COUNT(*) FROM blocks WHERE coin_type = ?",
                (coin_type.value,)
            )
            block_count = cursor.fetchone()[0]
            
            # Último bloco
            latest_block = self.get_latest_block(coin_type)
            
            # Total de recompensas
            cursor.execute(
                "SELECT SUM(reward) FROM blocks WHERE coin_type = ? AND miner_address = ?",
                (coin_type.value, self.wallet_address)
            )
            total_rewards = cursor.fetchone()[0] or 0
            
            return {
                'coin_type': coin_type.value,
                'block_count': block_count,
                'latest_block': latest_block,
                'total_rewards': float(total_rewards),
                'difficulty': self.mining_configs[coin_type].difficulty,
                'mining_active': coin_type in self.mining_threads
            }
    
    def get_all_balances(self) -> Dict[str, Decimal]:
        """Obtém saldos de todas as criptomoedas"""
        balances = {}
        for coin_type in CoinType:
            balances[coin_type.value] = self.get_wallet_balance(self.wallet_address, coin_type)
        return balances

def test_mining_engine():
    """Teste do engine de mineração"""
    print("🛡️ Testando QuantumMining Engine...")
    
    # Criar engine
    wallet_address = "QTC1234567890abcdef"
    engine = QuantumMiningEngine(wallet_address, "test_blockchain")
    
    try:
        # Verificar saldos iniciais
        print("\n💰 Saldos iniciais:")
        balances = engine.get_all_balances()
        for coin, balance in balances.items():
            print(f"  {coin}: {balance}")
        
        # Informações do blockchain
        print("\n⛓️ Informações do blockchain:")
        for coin_type in CoinType:
            info = engine.get_blockchain_info(coin_type)
            print(f"  {coin_type.value}: {info['block_count']} blocos, dificuldade {info['difficulty']}")
        
        # Iniciar mineração por 10 segundos
        print("\n⛏️ Iniciando mineração por 10 segundos...")
        engine.start_mining()
        time.sleep(10)
        
        # Verificar estatísticas
        print("\n📊 Estatísticas de mineração:")
        stats = engine.get_mining_stats()
        for coin, stat in stats.items():
            print(f"  {coin}: {stat.blocks_mined} blocos, {stat.hashrate:.2f} H/s")
        
        # Parar mineração
        engine.stop_mining_process()
        
        # Verificar saldos finais
        print("\n💰 Saldos finais:")
        balances = engine.get_all_balances()
        for coin, balance in balances.items():
            print(f"  {coin}: {balance}")
        
        print("\n✅ Teste do mining engine concluído com sucesso!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        return False
    finally:
        engine.stop_mining_process()

if __name__ == "__main__":
    test_mining_engine()

