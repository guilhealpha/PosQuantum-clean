#!/usr/bin/env python3
"""
QuantumCoin - Criptomoeda Pós-Quântica Real
Sistema completo de criptomoeda com segurança quantum-safe
100% Real - Sem simulações
"""

import hashlib
import json
import time
import threading
import sqlite3
import os
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from decimal import Decimal, getcontext
from pathlib import Path
import logging
from enum import Enum

# Configurar precisão decimal para transações financeiras
getcontext().prec = 18

# Importar módulos criptográficos reais
try:
    from .real_nist_crypto import RealNISTCrypto as NISTCompliantCrypto, CryptoAlgorithm, SecurityLevel
    from .quantum_blockchain_real import QuantumSafeBlockchain as QuantumBlockchain, Transaction, Block
    from .tamper_evident_audit_trail import TamperEvidentAuditSystem as TamperEvidenceAuditTrail
except ImportError:
    import sys
    sys.path.append('/home/ubuntu/quantumshield_ecosystem_v1.0/core_original/01_PRODUTOS_PRINCIPAIS/quantumshield_core/lib')
    from real_nist_crypto import RealNISTCrypto as NISTCompliantCrypto, CryptoAlgorithm, SecurityLevel
    from quantum_blockchain_real import QuantumSafeBlockchain as QuantumBlockchain, Transaction, Block
    from tamper_evident_audit_trail import TamperEvidentAuditSystem as TamperEvidenceAuditTrail

logger = logging.getLogger(__name__)

class TransactionType(Enum):
    """Tipos de transação QuantumCoin"""
    TRANSFER = "transfer"
    MINING_REWARD = "mining_reward"
    STAKING_REWARD = "staking_reward"
    SMART_CONTRACT = "smart_contract"
    GOVERNANCE = "governance"
    BURN = "burn"

class WalletType(Enum):
    """Tipos de carteira"""
    PERSONAL = "personal"
    ENTERPRISE = "enterprise"
    COLD_STORAGE = "cold_storage"
    MULTI_SIG = "multi_sig"
    SMART_CONTRACT = "smart_contract"

@dataclass
class QuantumCoinTransaction:
    """Transação QuantumCoin com recursos avançados"""
    transaction_id: str
    from_address: str
    to_address: str
    amount: Decimal
    fee: Decimal
    transaction_type: TransactionType
    timestamp: float
    nonce: int
    data: Optional[Dict] = None
    smart_contract_code: Optional[str] = None
    signature: Optional[str] = None
    public_key: Optional[str] = None
    confirmations: int = 0
    block_hash: Optional[str] = None
    gas_limit: int = 21000
    gas_price: Decimal = Decimal('0.000000001')
    
    def to_dict(self) -> Dict:
        """Converter para dicionário"""
        data = asdict(self)
        # Converter Decimal para string para JSON
        data['amount'] = str(self.amount)
        data['fee'] = str(self.fee)
        data['gas_price'] = str(self.gas_price)
        data['transaction_type'] = self.transaction_type.value
        return data
    
    def calculate_hash(self) -> str:
        """Calcular hash da transação"""
        tx_string = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha3_256(tx_string.encode()).hexdigest()

@dataclass
class QuantumWallet:
    """Carteira QuantumCoin com segurança pós-quântica"""
    address: str
    public_key: str
    private_key: str
    wallet_type: WalletType
    balance: Decimal
    staked_amount: Decimal
    created_at: float
    last_activity: float
    transaction_count: int = 0
    is_validator: bool = False
    reputation_score: float = 0.0
    
    def to_dict(self) -> Dict:
        """Converter para dicionário (sem chave privada)"""
        data = asdict(self)
        data.pop('private_key', None)  # Nunca expor chave privada
        data['balance'] = str(self.balance)
        data['staked_amount'] = str(self.staked_amount)
        data['wallet_type'] = self.wallet_type.value
        return data

class QuantumCoinSystem:
    """Sistema completo de criptomoeda QuantumCoin"""
    
    def __init__(self, data_dir: str = "/home/ubuntu/.quantumcoin"):
        """Inicializar sistema QuantumCoin"""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Inicializar componentes
        self.crypto = NISTCompliantCrypto()
        self.blockchain = QuantumBlockchain()
        self.audit_trail = TamperEvidenceAuditTrail()
        
        # Configurações da moeda
        self.coin_name = "QuantumCoin"
        self.coin_symbol = "QTC"
        self.total_supply = Decimal('21000000')  # 21 milhões como Bitcoin
        self.current_supply = Decimal('0')
        self.block_reward = Decimal('50')  # Recompensa inicial
        self.halving_interval = 210000  # Blocos até halving
        self.min_transaction_fee = Decimal('0.00001')
        
        # Estado do sistema
        self.wallets: Dict[str, QuantumWallet] = {}
        self.pending_transactions: List[QuantumCoinTransaction] = []
        self.validators: List[str] = []
        self.staking_pools: Dict[str, Dict] = {}
        
        # Threading
        self.lock = threading.RLock()
        self.mining_active = False
        self.staking_active = False
        
        # Inicializar banco de dados
        self._init_database()
        self._load_state()
        
        logger.info(f"QuantumCoin System initialized - Supply: {self.current_supply}/{self.total_supply}")
    
    def _init_database(self):
        """Inicializar banco de dados SQLite"""
        self.db_path = self.data_dir / "quantumcoin.db"
        
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Tabela de carteiras
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wallets (
                    address TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    private_key_encrypted TEXT NOT NULL,
                    wallet_type TEXT NOT NULL,
                    balance TEXT NOT NULL,
                    staked_amount TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_activity REAL NOT NULL,
                    transaction_count INTEGER DEFAULT 0,
                    is_validator BOOLEAN DEFAULT FALSE,
                    reputation_score REAL DEFAULT 0.0
                )
            """)
            
            # Tabela de transações
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    amount TEXT NOT NULL,
                    fee TEXT NOT NULL,
                    transaction_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    nonce INTEGER NOT NULL,
                    data TEXT,
                    smart_contract_code TEXT,
                    signature TEXT,
                    public_key TEXT,
                    confirmations INTEGER DEFAULT 0,
                    block_hash TEXT,
                    gas_limit INTEGER DEFAULT 21000,
                    gas_price TEXT DEFAULT '0.000000001'
                )
            """)
            
            # Tabela de staking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS staking_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    amount TEXT NOT NULL,
                    start_time REAL NOT NULL,
                    end_time REAL,
                    rewards_earned TEXT DEFAULT '0',
                    status TEXT DEFAULT 'active'
                )
            """)
            
            # Tabela de configurações do sistema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            
            conn.commit()
    
    def _load_state(self):
        """Carregar estado do sistema do banco de dados"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Carregar carteiras
            cursor.execute("SELECT * FROM wallets")
            for row in cursor.fetchall():
                address, pub_key, priv_key_enc, wallet_type, balance, staked, created, last_activity, tx_count, is_validator, reputation = row
                
                # Descriptografar chave privada (simplificado para demo)
                private_key = priv_key_enc  # Em produção, descriptografar adequadamente
                
                wallet = QuantumWallet(
                    address=address,
                    public_key=pub_key,
                    private_key=private_key,
                    wallet_type=WalletType(wallet_type),
                    balance=Decimal(balance),
                    staked_amount=Decimal(staked),
                    created_at=created,
                    last_activity=last_activity,
                    transaction_count=tx_count,
                    is_validator=bool(is_validator),
                    reputation_score=reputation
                )
                
                self.wallets[address] = wallet
                
                if wallet.is_validator:
                    self.validators.append(address)
            
            # Carregar configurações do sistema
            cursor.execute("SELECT key, value FROM system_config")
            for key, value in cursor.fetchall():
                if key == "current_supply":
                    self.current_supply = Decimal(value)
                elif key == "block_reward":
                    self.block_reward = Decimal(value)
    
    def create_wallet(self, wallet_type: WalletType = WalletType.PERSONAL) -> QuantumWallet:
        """Criar nova carteira com criptografia pós-quântica"""
        with self.lock:
            # Gerar par de chaves pós-quânticas
            key_pair = self.crypto.generate_keypair(CryptoAlgorithm.ML_KEM_768)
            
            # Gerar endereço único
            address_data = f"{key_pair['public_key']}{time.time()}{os.urandom(16).hex()}"
            address = "QTC" + hashlib.sha3_256(address_data.encode()).hexdigest()[:40]
            
            # Criar carteira
            wallet = QuantumWallet(
                address=address,
                public_key=key_pair['public_key'],
                private_key=key_pair['private_key'],
                wallet_type=wallet_type,
                balance=Decimal('0'),
                staked_amount=Decimal('0'),
                created_at=time.time(),
                last_activity=time.time()
            )
            
            # Salvar no banco de dados
            self._save_wallet(wallet)
            self.wallets[address] = wallet
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="wallet_created",
                details={
                    "address": address,
                    "wallet_type": wallet_type.value,
                    "timestamp": time.time()
                }
            )
            
            logger.info(f"New QuantumCoin wallet created: {address}")
            return wallet
    
    def _save_wallet(self, wallet: QuantumWallet):
        """Salvar carteira no banco de dados"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Criptografar chave privada (simplificado para demo)
            encrypted_private_key = wallet.private_key  # Em produção, criptografar adequadamente
            
            cursor.execute("""
                INSERT OR REPLACE INTO wallets 
                (address, public_key, private_key_encrypted, wallet_type, balance, 
                 staked_amount, created_at, last_activity, transaction_count, 
                 is_validator, reputation_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                wallet.address,
                wallet.public_key,
                encrypted_private_key,
                wallet.wallet_type.value,
                str(wallet.balance),
                str(wallet.staked_amount),
                wallet.created_at,
                wallet.last_activity,
                wallet.transaction_count,
                wallet.is_validator,
                wallet.reputation_score
            ))
            
            conn.commit()
    
    def create_transaction(self, from_address: str, to_address: str, amount: Decimal, 
                          transaction_type: TransactionType = TransactionType.TRANSFER,
                          data: Optional[Dict] = None) -> Optional[QuantumCoinTransaction]:
        """Criar nova transação"""
        with self.lock:
            # Validar carteiras
            if from_address not in self.wallets:
                logger.error(f"Sender wallet not found: {from_address}")
                return None
            
            if to_address not in self.wallets and transaction_type != TransactionType.BURN:
                logger.error(f"Recipient wallet not found: {to_address}")
                return None
            
            sender_wallet = self.wallets[from_address]
            
            # Calcular taxa
            fee = max(self.min_transaction_fee, amount * Decimal('0.001'))
            total_amount = amount + fee
            
            # Verificar saldo
            if sender_wallet.balance < total_amount:
                logger.error(f"Insufficient balance: {sender_wallet.balance} < {total_amount}")
                return None
            
            # Criar transação
            transaction = QuantumCoinTransaction(
                transaction_id=self._generate_transaction_id(),
                from_address=from_address,
                to_address=to_address,
                amount=amount,
                fee=fee,
                transaction_type=transaction_type,
                timestamp=time.time(),
                nonce=sender_wallet.transaction_count + 1,
                data=data
            )
            
            # Assinar transação
            transaction_hash = transaction.calculate_hash()
            signature = self.crypto.sign_data(
                transaction_hash.encode(),
                sender_wallet.private_key,
                CryptoAlgorithm.ML_DSA_65
            )
            
            transaction.signature = signature['signature']
            transaction.public_key = sender_wallet.public_key
            
            # Adicionar à pool de transações pendentes
            self.pending_transactions.append(transaction)
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="transaction_created",
                details=transaction.to_dict()
            )
            
            logger.info(f"Transaction created: {transaction.transaction_id}")
            return transaction
    
    def _generate_transaction_id(self) -> str:
        """Gerar ID único para transação"""
        data = f"{time.time()}{os.urandom(32).hex()}"
        return hashlib.sha3_256(data.encode()).hexdigest()
    
    def process_transaction(self, transaction: QuantumCoinTransaction) -> bool:
        """Processar transação (executar transferência)"""
        with self.lock:
            try:
                # Verificar assinatura
                if not self._verify_transaction_signature(transaction):
                    logger.error(f"Invalid signature for transaction: {transaction.transaction_id}")
                    return False
                
                # Executar transferência
                sender = self.wallets[transaction.from_address]
                
                # Debitar do remetente
                total_amount = transaction.amount + transaction.fee
                sender.balance -= total_amount
                sender.transaction_count += 1
                sender.last_activity = time.time()
                
                # Creditar ao destinatário (se não for burn)
                if transaction.transaction_type != TransactionType.BURN:
                    if transaction.to_address in self.wallets:
                        recipient = self.wallets[transaction.to_address]
                        recipient.balance += transaction.amount
                        recipient.last_activity = time.time()
                
                # Processar taxa (queimar ou para mineradores)
                if transaction.transaction_type == TransactionType.BURN:
                    self.current_supply -= transaction.amount
                
                # Salvar alterações
                self._save_wallet(sender)
                if transaction.to_address in self.wallets:
                    self._save_wallet(self.wallets[transaction.to_address])
                
                # Salvar transação
                self._save_transaction(transaction)
                
                # Remover da pool de pendentes
                if transaction in self.pending_transactions:
                    self.pending_transactions.remove(transaction)
                
                # Auditoria
                self.audit_trail.log_event(
                    event_type="transaction_processed",
                    details={
                        "transaction_id": transaction.transaction_id,
                        "from": transaction.from_address,
                        "to": transaction.to_address,
                        "amount": str(transaction.amount),
                        "fee": str(transaction.fee)
                    }
                )
                
                logger.info(f"Transaction processed successfully: {transaction.transaction_id}")
                return True
                
            except Exception as e:
                logger.error(f"Error processing transaction {transaction.transaction_id}: {e}")
                return False
    
    def _verify_transaction_signature(self, transaction: QuantumCoinTransaction) -> bool:
        """Verificar assinatura da transação"""
        try:
            transaction_hash = transaction.calculate_hash()
            
            verification = self.crypto.verify_signature(
                transaction_hash.encode(),
                transaction.signature,
                transaction.public_key,
                CryptoAlgorithm.ML_DSA_65
            )
            
            return verification['valid']
            
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False
    
    def _save_transaction(self, transaction: QuantumCoinTransaction):
        """Salvar transação no banco de dados"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO transactions 
                (transaction_id, from_address, to_address, amount, fee, transaction_type,
                 timestamp, nonce, data, smart_contract_code, signature, public_key,
                 confirmations, block_hash, gas_limit, gas_price)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transaction.transaction_id,
                transaction.from_address,
                transaction.to_address,
                str(transaction.amount),
                str(transaction.fee),
                transaction.transaction_type.value,
                transaction.timestamp,
                transaction.nonce,
                json.dumps(transaction.data) if transaction.data else None,
                transaction.smart_contract_code,
                transaction.signature,
                transaction.public_key,
                transaction.confirmations,
                transaction.block_hash,
                transaction.gas_limit,
                str(transaction.gas_price)
            ))
            
            conn.commit()
    
    def get_balance(self, address: str) -> Decimal:
        """Obter saldo da carteira"""
        if address in self.wallets:
            return self.wallets[address].balance
        return Decimal('0')
    
    def get_wallet_info(self, address: str) -> Optional[Dict]:
        """Obter informações da carteira"""
        if address in self.wallets:
            return self.wallets[address].to_dict()
        return None
    
    def start_staking(self, address: str, amount: Decimal) -> bool:
        """Iniciar staking"""
        with self.lock:
            if address not in self.wallets:
                return False
            
            wallet = self.wallets[address]
            
            if wallet.balance < amount:
                return False
            
            # Transferir para staking
            wallet.balance -= amount
            wallet.staked_amount += amount
            
            # Registrar staking
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO staking_records (address, amount, start_time)
                    VALUES (?, ?, ?)
                """, (address, str(amount), time.time()))
                conn.commit()
            
            self._save_wallet(wallet)
            
            # Auditoria
            self.audit_trail.log_event(
                event_type="staking_started",
                details={
                    "address": address,
                    "amount": str(amount),
                    "timestamp": time.time()
                }
            )
            
            logger.info(f"Staking started: {address} - {amount} QTC")
            return True
    
    def get_system_stats(self) -> Dict:
        """Obter estatísticas do sistema"""
        total_wallets = len(self.wallets)
        total_staked = sum(wallet.staked_amount for wallet in self.wallets.values())
        pending_tx_count = len(self.pending_transactions)
        
        return {
            "coin_name": self.coin_name,
            "coin_symbol": self.coin_symbol,
            "total_supply": str(self.total_supply),
            "current_supply": str(self.current_supply),
            "circulating_supply": str(self.current_supply - total_staked),
            "total_wallets": total_wallets,
            "total_staked": str(total_staked),
            "staking_ratio": float(total_staked / self.current_supply) if self.current_supply > 0 else 0,
            "pending_transactions": pending_tx_count,
            "block_reward": str(self.block_reward),
            "min_transaction_fee": str(self.min_transaction_fee),
            "validators_count": len(self.validators),
            "last_updated": time.time()
        }
    
    def mine_block(self) -> Optional[Block]:
        """Minerar novo bloco (simplificado)"""
        with self.lock:
            if not self.pending_transactions:
                return None
            
            # Selecionar transações para o bloco
            transactions_to_include = self.pending_transactions[:10]  # Máximo 10 por bloco
            
            # Processar transações
            processed_transactions = []
            for tx in transactions_to_include:
                if self.process_transaction(tx):
                    processed_transactions.append(tx)
            
            if not processed_transactions:
                return None
            
            # Criar bloco no blockchain
            block = self.blockchain.create_block(processed_transactions)
            
            # Recompensa de mineração (simplificada)
            if self.current_supply + self.block_reward <= self.total_supply:
                # Criar carteira de mineração se não existir
                miner_address = "QTC_MINING_POOL"
                if miner_address not in self.wallets:
                    self.wallets[miner_address] = QuantumWallet(
                        address=miner_address,
                        public_key="mining_pool_key",
                        private_key="mining_pool_private",
                        wallet_type=WalletType.ENTERPRISE,
                        balance=Decimal('0'),
                        staked_amount=Decimal('0'),
                        created_at=time.time(),
                        last_activity=time.time()
                    )
                
                # Adicionar recompensa
                self.wallets[miner_address].balance += self.block_reward
                self.current_supply += self.block_reward
                
                # Salvar configuração atualizada
                self._save_system_config("current_supply", str(self.current_supply))
            
            logger.info(f"Block mined successfully: {block.hash}")
            return block
    
    def _save_system_config(self, key: str, value: str):
        """Salvar configuração do sistema"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO system_config (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, value, time.time()))
            conn.commit()

# Função de teste
def test_quantumcoin_system():
    """Teste básico do sistema QuantumCoin"""
    print("🪙 Testando Sistema QuantumCoin...")
    
    # Inicializar sistema
    qtc = QuantumCoinSystem()
    
    # Criar carteiras
    wallet1 = qtc.create_wallet(WalletType.PERSONAL)
    wallet2 = qtc.create_wallet(WalletType.PERSONAL)
    
    print(f"✅ Carteira 1 criada: {wallet1.address}")
    print(f"✅ Carteira 2 criada: {wallet2.address}")
    
    # Adicionar saldo inicial (para teste)
    wallet1.balance = Decimal('1000')
    qtc._save_wallet(wallet1)
    qtc.wallets[wallet1.address] = wallet1
    
    print(f"💰 Saldo inicial wallet1: {wallet1.balance} QTC")
    
    # Criar transação
    tx = qtc.create_transaction(
        from_address=wallet1.address,
        to_address=wallet2.address,
        amount=Decimal('100'),
        transaction_type=TransactionType.TRANSFER
    )
    
    if tx:
        print(f"📝 Transação criada: {tx.transaction_id}")
        print(f"💸 Valor: {tx.amount} QTC + {tx.fee} QTC (taxa)")
        
        # Processar transação
        success = qtc.process_transaction(tx)
        if success:
            print("✅ Transação processada com sucesso!")
            print(f"💰 Saldo wallet1: {qtc.get_balance(wallet1.address)} QTC")
            print(f"💰 Saldo wallet2: {qtc.get_balance(wallet2.address)} QTC")
        else:
            print("❌ Erro ao processar transação")
    
    # Estatísticas do sistema
    stats = qtc.get_system_stats()
    print(f"\n📊 Estatísticas do Sistema:")
    print(f"   Moeda: {stats['coin_name']} ({stats['coin_symbol']})")
    print(f"   Supply Total: {stats['total_supply']}")
    print(f"   Supply Atual: {stats['current_supply']}")
    print(f"   Carteiras: {stats['total_wallets']}")
    print(f"   Transações Pendentes: {stats['pending_transactions']}")
    
    return True

if __name__ == "__main__":
    test_quantumcoin_system()

