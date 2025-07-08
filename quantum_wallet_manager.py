#!/usr/bin/env python3
"""
🛡️ QuantumShield - Gerenciador de Carteiras QuantumCoin
Arquivo: quantum_wallet_manager.py
Descrição: Sistema completo de carteiras para as 3 criptomoedas
Autor: QuantumShield Team
Versão: 2.0
Data: 03/07/2025
"""

import hashlib
import json
import time
import os
import sqlite3
import secrets
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from decimal import Decimal, getcontext
from pathlib import Path
import logging
from enum import Enum
import base64
import qrcode
from io import BytesIO

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
class WalletInfo:
    """Informações da carteira"""
    address: str
    label: str
    created_at: float
    encrypted_private_key: str
    public_key: str
    is_default: bool = False
    is_watch_only: bool = False

@dataclass
class TransactionRecord:
    """Registro de transação"""
    transaction_id: str
    coin_type: str
    from_address: str
    to_address: str
    amount: Decimal
    fee: Decimal
    timestamp: float
    status: str
    block_number: Optional[int] = None
    confirmations: int = 0

@dataclass
class AddressBalance:
    """Saldo de endereço"""
    address: str
    coin_type: str
    balance: Decimal
    pending_balance: Decimal = Decimal('0')
    last_updated: float = 0.0

class QuantumWalletManager:
    """Gerenciador de carteiras QuantumCoin"""
    
    def __init__(self, data_dir: str = "wallet_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # Valores USD das criptomoedas
        self.coin_values_usd = {
            CoinType.QTC: Decimal('1.00'),
            CoinType.QTG: Decimal('0.50'),
            CoinType.QTS: Decimal('0.01')
        }
        
        # Taxas de transação
        self.transaction_fees = {
            CoinType.QTC: Decimal('0.001'),
            CoinType.QTG: Decimal('0.0005'),
            CoinType.QTS: Decimal('0.00001')
        }
        
        # Inicializar banco de dados
        self.init_wallet_database()
        
        # Carteira padrão
        self.default_wallet = None
        self.load_default_wallet()
    
    def init_wallet_database(self):
        """Inicializa banco de dados das carteiras"""
        self.db_path = self.data_dir / "quantum_wallets.db"
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Tabela de carteiras
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    encrypted_private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    is_default BOOLEAN DEFAULT FALSE,
                    is_watch_only BOOLEAN DEFAULT FALSE,
                    backup_phrase TEXT,
                    last_used REAL DEFAULT 0,
                    created_at_datetime DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tabela de saldos
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS balances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    coin_type TEXT NOT NULL,
                    balance DECIMAL DEFAULT 0,
                    pending_balance DECIMAL DEFAULT 0,
                    last_updated REAL NOT NULL,
                    last_updated_datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(address, coin_type)
                )
            """)
            
            # Tabela de transações
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id TEXT NOT NULL UNIQUE,
                    coin_type TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    amount DECIMAL NOT NULL,
                    fee DECIMAL DEFAULT 0,
                    timestamp REAL NOT NULL,
                    status TEXT DEFAULT 'pending',
                    block_number INTEGER,
                    confirmations INTEGER DEFAULT 0,
                    memo TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tabela de endereços de recebimento
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS receiving_addresses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet_address TEXT NOT NULL,
                    receiving_address TEXT NOT NULL,
                    label TEXT,
                    used BOOLEAN DEFAULT FALSE,
                    created_at REAL NOT NULL,
                    created_at_datetime DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (wallet_address) REFERENCES wallets (address)
                )
            """)
            
            # Tabela de configurações
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS wallet_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    setting_key TEXT NOT NULL UNIQUE,
                    setting_value TEXT NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    
    def generate_wallet_address(self) -> str:
        """Gera endereço único de carteira"""
        # Gerar chave privada segura
        private_key = secrets.token_bytes(32)
        
        # Gerar chave pública (simulada)
        public_key = hashlib.sha3_256(private_key).digest()
        
        # Gerar endereço
        address_hash = hashlib.sha3_256(public_key).digest()
        
        # Formato do endereço: QTC + base58 dos primeiros 20 bytes
        address_bytes = address_hash[:20]
        address = "QTC" + base64.b32encode(address_bytes).decode().rstrip('=')
        
        return address
    
    def create_wallet(self, label: str, password: str = "") -> WalletInfo:
        """Cria nova carteira"""
        # Gerar endereço único
        address = self.generate_wallet_address()
        
        # Gerar chaves (simuladas para este exemplo)
        private_key = secrets.token_hex(32)
        public_key = hashlib.sha3_256(private_key.encode()).hexdigest()
        
        # Criptografar chave privada (simulado)
        encrypted_private_key = self._encrypt_private_key(private_key, password)
        
        # Criar registro da carteira
        wallet_info = WalletInfo(
            address=address,
            label=label,
            created_at=time.time(),
            encrypted_private_key=encrypted_private_key,
            public_key=public_key,
            is_default=(self.default_wallet is None)
        )
        
        # Salvar no banco de dados
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO wallets (
                    address, label, encrypted_private_key, public_key,
                    created_at, is_default, is_watch_only
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                wallet_info.address,
                wallet_info.label,
                wallet_info.encrypted_private_key,
                wallet_info.public_key,
                wallet_info.created_at,
                wallet_info.is_default,
                wallet_info.is_watch_only
            ))
            
            conn.commit()
        
        # Inicializar saldos para todas as moedas
        for coin_type in CoinType:
            self.update_balance(address, coin_type, Decimal('0'))
        
        # Definir como carteira padrão se for a primeira
        if self.default_wallet is None:
            self.default_wallet = wallet_info
            
        logger.info(f"Carteira criada: {address} ({label})")
        return wallet_info
    
    def _encrypt_private_key(self, private_key: str, password: str) -> str:
        """Criptografa chave privada (simulado)"""
        # Em implementação real, usar AES ou similar
        if password:
            combined = f"{private_key}:{password}"
            return base64.b64encode(combined.encode()).decode()
        return base64.b64encode(private_key.encode()).decode()
    
    def _decrypt_private_key(self, encrypted_key: str, password: str) -> str:
        """Descriptografa chave privada (simulado)"""
        try:
            decoded = base64.b64decode(encrypted_key.encode()).decode()
            if ':' in decoded and password:
                private_key, stored_password = decoded.split(':', 1)
                if stored_password == password:
                    return private_key
                else:
                    raise ValueError("Senha incorreta")
            return decoded
        except Exception as e:
            raise ValueError(f"Erro ao descriptografar chave: {e}")
    
    def load_default_wallet(self):
        """Carrega carteira padrão"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT address, label, encrypted_private_key, public_key, created_at, is_default, is_watch_only
                FROM wallets 
                WHERE is_default = TRUE
                LIMIT 1
            """)
            
            result = cursor.fetchone()
            if result:
                self.default_wallet = WalletInfo(
                    address=result[0],
                    label=result[1],
                    encrypted_private_key=result[2],
                    public_key=result[3],
                    created_at=result[4],
                    is_default=result[5],
                    is_watch_only=result[6]
                )
                logger.info(f"Carteira padrão carregada: {self.default_wallet.address}")
    
    def get_wallet_list(self) -> List[WalletInfo]:
        """Obtém lista de todas as carteiras"""
        wallets = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT address, label, encrypted_private_key, public_key, 
                       created_at, is_default, is_watch_only
                FROM wallets 
                ORDER BY is_default DESC, created_at DESC
            """)
            
            for row in cursor.fetchall():
                wallets.append(WalletInfo(
                    address=row[0],
                    label=row[1],
                    encrypted_private_key=row[2],
                    public_key=row[3],
                    created_at=row[4],
                    is_default=row[5],
                    is_watch_only=row[6]
                ))
        
        return wallets
    
    def update_balance(self, address: str, coin_type: CoinType, balance: Decimal):
        """Atualiza saldo de uma carteira"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO balances (
                    address, coin_type, balance, last_updated
                ) VALUES (?, ?, ?, ?)
            """, (address, coin_type.value, float(balance), time.time()))
            
            conn.commit()
    
    def get_balance(self, address: str, coin_type: CoinType) -> Decimal:
        """Obtém saldo de uma carteira"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT balance FROM balances 
                WHERE address = ? AND coin_type = ?
            """, (address, coin_type.value))
            
            result = cursor.fetchone()
            return Decimal(str(result[0])) if result else Decimal('0')
    
    def get_all_balances(self, address: str) -> Dict[str, Decimal]:
        """Obtém saldos de todas as moedas para uma carteira"""
        balances = {}
        for coin_type in CoinType:
            balances[coin_type.value] = self.get_balance(address, coin_type)
        return balances
    
    def get_total_portfolio_value_usd(self, address: str) -> Decimal:
        """Calcula valor total do portfólio em USD"""
        total_usd = Decimal('0')
        
        for coin_type in CoinType:
            balance = self.get_balance(address, coin_type)
            coin_value = self.coin_values_usd[coin_type]
            total_usd += balance * coin_value
        
        return total_usd
    
    def create_transaction(self, from_address: str, to_address: str, 
                          coin_type: CoinType, amount: Decimal, 
                          password: str = "", memo: str = "") -> str:
        """Cria nova transação"""
        
        # Verificar saldo suficiente
        current_balance = self.get_balance(from_address, coin_type)
        fee = self.transaction_fees[coin_type]
        total_needed = amount + fee
        
        if current_balance < total_needed:
            raise ValueError(f"Saldo insuficiente. Necessário: {total_needed}, Disponível: {current_balance}")
        
        # Gerar ID da transação
        transaction_id = hashlib.sha3_256(
            f"{from_address}{to_address}{amount}{time.time()}".encode()
        ).hexdigest()
        
        # Criar registro da transação
        transaction = TransactionRecord(
            transaction_id=transaction_id,
            coin_type=coin_type.value,
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            fee=fee,
            timestamp=time.time(),
            status='pending'
        )
        
        # Salvar no banco de dados
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO transactions (
                    transaction_id, coin_type, from_address, to_address,
                    amount, fee, timestamp, status, memo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                transaction.transaction_id,
                transaction.coin_type,
                transaction.from_address,
                transaction.to_address,
                float(transaction.amount),
                float(transaction.fee),
                transaction.timestamp,
                transaction.status,
                memo
            ))
            
            conn.commit()
        
        # Atualizar saldos (simulado)
        new_balance = current_balance - total_needed
        self.update_balance(from_address, coin_type, new_balance)
        
        # Atualizar saldo do destinatário (se for carteira local)
        if self.is_local_address(to_address):
            recipient_balance = self.get_balance(to_address, coin_type)
            self.update_balance(to_address, coin_type, recipient_balance + amount)
        
        logger.info(f"Transação criada: {transaction_id} ({amount} {coin_type.value})")
        return transaction_id
    
    def is_local_address(self, address: str) -> bool:
        """Verifica se endereço pertence a uma carteira local"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM wallets WHERE address = ?", (address,))
            return cursor.fetchone()[0] > 0
    
    def get_transaction_history(self, address: str, limit: int = 50) -> List[TransactionRecord]:
        """Obtém histórico de transações"""
        transactions = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT transaction_id, coin_type, from_address, to_address,
                       amount, fee, timestamp, status, block_number, confirmations
                FROM transactions 
                WHERE from_address = ? OR to_address = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (address, address, limit))
            
            for row in cursor.fetchall():
                transactions.append(TransactionRecord(
                    transaction_id=row[0],
                    coin_type=row[1],
                    from_address=row[2],
                    to_address=row[3],
                    amount=Decimal(str(row[4])),
                    fee=Decimal(str(row[5])),
                    timestamp=row[6],
                    status=row[7],
                    block_number=row[8],
                    confirmations=row[9] or 0
                ))
        
        return transactions
    
    def generate_receiving_address(self, wallet_address: str, label: str = "") -> str:
        """Gera novo endereço de recebimento"""
        # Para simplicidade, usar o próprio endereço da carteira
        # Em implementação real, geraria endereços derivados
        receiving_address = wallet_address
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO receiving_addresses (
                    wallet_address, receiving_address, label, created_at
                ) VALUES (?, ?, ?, ?)
            """, (wallet_address, receiving_address, label, time.time()))
            
            conn.commit()
        
        return receiving_address
    
    def generate_qr_code(self, address: str, amount: Decimal = None, 
                        coin_type: CoinType = None) -> str:
        """Gera QR code para recebimento"""
        # Formato: quantumcoin:address?amount=X&coin=Y
        qr_data = f"quantumcoin:{address}"
        
        params = []
        if amount:
            params.append(f"amount={amount}")
        if coin_type:
            params.append(f"coin={coin_type.value}")
        
        if params:
            qr_data += "?" + "&".join(params)
        
        # Gerar QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        # Converter para base64
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return qr_base64
    
    def backup_wallet(self, address: str, password: str = "") -> Dict:
        """Cria backup da carteira"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT address, label, encrypted_private_key, public_key, created_at
                FROM wallets WHERE address = ?
            """, (address,))
            
            wallet_data = cursor.fetchone()
            if not wallet_data:
                raise ValueError("Carteira não encontrada")
            
            # Obter saldos
            balances = self.get_all_balances(address)
            
            # Obter transações
            transactions = self.get_transaction_history(address)
            
            backup_data = {
                'wallet': {
                    'address': wallet_data[0],
                    'label': wallet_data[1],
                    'encrypted_private_key': wallet_data[2],
                    'public_key': wallet_data[3],
                    'created_at': wallet_data[4]
                },
                'balances': {coin: float(balance) for coin, balance in balances.items()},
                'transactions': [asdict(tx) for tx in transactions],
                'backup_timestamp': time.time(),
                'version': '2.0'
            }
            
            return backup_data
    
    def restore_wallet(self, backup_data: Dict, password: str = "") -> str:
        """Restaura carteira do backup"""
        wallet_data = backup_data['wallet']
        
        # Verificar se carteira já existe
        if self.is_local_address(wallet_data['address']):
            raise ValueError("Carteira já existe")
        
        # Restaurar carteira
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO wallets (
                    address, label, encrypted_private_key, public_key, created_at
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                wallet_data['address'],
                wallet_data['label'],
                wallet_data['encrypted_private_key'],
                wallet_data['public_key'],
                wallet_data['created_at']
            ))
            
            conn.commit()
        
        # Restaurar saldos
        for coin_type_str, balance in backup_data['balances'].items():
            coin_type = CoinType(coin_type_str)
            self.update_balance(wallet_data['address'], coin_type, Decimal(str(balance)))
        
        logger.info(f"Carteira restaurada: {wallet_data['address']}")
        return wallet_data['address']
    
    def get_wallet_summary(self, address: str) -> Dict:
        """Obtém resumo completo da carteira"""
        # Informações básicas
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT label, created_at, is_default 
                FROM wallets WHERE address = ?
            """, (address,))
            
            wallet_info = cursor.fetchone()
            if not wallet_info:
                raise ValueError("Carteira não encontrada")
        
        # Saldos
        balances = self.get_all_balances(address)
        
        # Valor total em USD
        total_usd = self.get_total_portfolio_value_usd(address)
        
        # Transações recentes
        recent_transactions = self.get_transaction_history(address, limit=10)
        
        # Estatísticas
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM transactions 
                WHERE from_address = ? OR to_address = ?
            """, (address, address))
            total_transactions = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT SUM(amount) FROM transactions 
                WHERE from_address = ? AND status = 'confirmed'
            """, (address,))
            total_sent = cursor.fetchone()[0] or 0
            
            cursor.execute("""
                SELECT SUM(amount) FROM transactions 
                WHERE to_address = ? AND status = 'confirmed'
            """, (address,))
            total_received = cursor.fetchone()[0] or 0
        
        return {
            'address': address,
            'label': wallet_info[0],
            'created_at': wallet_info[1],
            'is_default': wallet_info[2],
            'balances': {coin: float(balance) for coin, balance in balances.items()},
            'total_value_usd': float(total_usd),
            'statistics': {
                'total_transactions': total_transactions,
                'total_sent': float(total_sent),
                'total_received': float(total_received)
            },
            'recent_transactions': [asdict(tx) for tx in recent_transactions]
        }

def test_wallet_manager():
    """Teste do gerenciador de carteiras"""
    print("🛡️ Testando QuantumWallet Manager...")
    
    # Criar gerenciador
    manager = QuantumWalletManager("test_wallets")
    
    try:
        # Criar carteira
        print("\n💼 Criando carteira...")
        wallet = manager.create_wallet("Carteira Principal", "senha123")
        print(f"Carteira criada: {wallet.address}")
        
        # Simular saldos iniciais
        print("\n💰 Adicionando saldos iniciais...")
        manager.update_balance(wallet.address, CoinType.QTC, Decimal('100.0'))
        manager.update_balance(wallet.address, CoinType.QTG, Decimal('200.0'))
        manager.update_balance(wallet.address, CoinType.QTS, Decimal('1000.0'))
        
        # Verificar saldos
        print("\n📊 Saldos atuais:")
        balances = manager.get_all_balances(wallet.address)
        for coin, balance in balances.items():
            print(f"  {coin}: {balance}")
        
        # Valor total em USD
        total_usd = manager.get_total_portfolio_value_usd(wallet.address)
        print(f"\n💵 Valor total: ${total_usd}")
        
        # Criar segunda carteira
        wallet2 = manager.create_wallet("Carteira Secundária")
        
        # Fazer transação
        print(f"\n💸 Enviando 10 QTC para {wallet2.address}...")
        tx_id = manager.create_transaction(
            wallet.address, 
            wallet2.address, 
            CoinType.QTC, 
            Decimal('10.0'),
            memo="Teste de transação"
        )
        print(f"Transação criada: {tx_id}")
        
        # Verificar histórico
        print("\n📋 Histórico de transações:")
        transactions = manager.get_transaction_history(wallet.address, limit=5)
        for tx in transactions:
            print(f"  {tx.transaction_id[:16]}... {tx.amount} {tx.coin_type} -> {tx.to_address[:16]}...")
        
        # Resumo da carteira
        print("\n📊 Resumo da carteira:")
        summary = manager.get_wallet_summary(wallet.address)
        print(f"  Endereço: {summary['address']}")
        print(f"  Label: {summary['label']}")
        print(f"  Valor total: ${summary['total_value_usd']}")
        print(f"  Transações: {summary['statistics']['total_transactions']}")
        
        # Gerar QR code
        print("\n📱 Gerando QR code...")
        qr_code = manager.generate_qr_code(wallet.address, Decimal('50.0'), CoinType.QTC)
        print(f"QR code gerado: {len(qr_code)} bytes")
        
        print("\n✅ Teste do wallet manager concluído com sucesso!")
        return True
        
    except Exception as e:
        print(f"\n❌ Erro no teste: {e}")
        return False

if __name__ == "__main__":
    test_wallet_manager()

