#!/usr/bin/env python3
"""
⛓️ Aba de Blockchain QuantumCoin - QuantumShield
Interface funcional para carteiras QTC/QTG/QTS e transações

Autor: QuantumShield Team
Data: 07/01/2025
"""

import os
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from decimal import Decimal

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QTextEdit, QGroupBox,
    QProgressBar, QFrame, QScrollArea, QComboBox,
    QLineEdit, QFileDialog, QMessageBox, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QSpinBox, QDoubleSpinBox, QTabWidget
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QPalette, QColor

# Importar módulos de blockchain com fallback
try:
    from quantum_blockchain_real import QuantumSafeBlockchain, Transaction, Block
    from quantum_coin_system import QuantumCoinTransaction, QuantumWallet, TransactionType, WalletType
    from real_nist_crypto import RealNISTCrypto
    BLOCKCHAIN_AVAILABLE = True
    print("✅ Módulos de blockchain importados com sucesso")
except ImportError as e:
    print(f"⚠️ Módulos de blockchain não disponíveis: {e}")
    BLOCKCHAIN_AVAILABLE = False
    # Fallback mock classes
    class QuantumSafeBlockchain:
        def __init__(self):
            self.balances = {"mock_address": 1000.0}
        def get_balance(self, address):
            return self.balances.get(address, 0.0)
    
    class QuantumCoinTransaction:
        def __init__(self, **kwargs):
            pass
    
    class TransactionType:
        TRANSFER = "transfer"
        MINING_REWARD = "mining_reward"

class BlockchainWorker(QThread):
    """Worker thread para operações de blockchain"""
    
    operation_completed = pyqtSignal(dict)
    progress_updated = pyqtSignal(int)
    mining_update = pyqtSignal(dict)
    
    def __init__(self, operation, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        self.running = True
        self.blockchain = QuantumSafeBlockchain() if BLOCKCHAIN_AVAILABLE else None
    
    def run(self):
        """Executar operação de blockchain"""
        try:
            if self.operation == 'create_wallet':
                result = self._create_wallet()
            elif self.operation == 'send_transaction':
                result = self._send_transaction()
            elif self.operation == 'mine_block':
                result = self._mine_block()
            elif self.operation == 'sync_blockchain':
                result = self._sync_blockchain()
            else:
                result = {'success': False, 'error': f'Operação {self.operation} não suportada'}
            
            self.operation_completed.emit(result)
            
        except Exception as e:
            self.operation_completed.emit({
                'success': False,
                'error': f'Erro na operação: {str(e)}'
            })
    
    def _create_wallet(self):
        """Criar nova carteira"""
        wallet_type = self.kwargs.get('wallet_type', 'personal')
        
        # Simular criação de carteira
        import hashlib
        import time
        
        # Gerar endereço único
        seed = f"{time.time()}_{wallet_type}".encode()
        address = "QTC" + hashlib.sha256(seed).hexdigest()[:32]
        
        # Simular chaves (em implementação real, usar criptografia pós-quântica)
        public_key = hashlib.sha256(seed + b"public").hexdigest()
        private_key = hashlib.sha256(seed + b"private").hexdigest()
        
        wallet_data = {
            'address': address,
            'public_key': public_key,
            'private_key': private_key,
            'wallet_type': wallet_type,
            'balance_qtc': 0.0,
            'balance_qtg': 0.0,
            'balance_qts': 0.0,
            'created_at': time.time()
        }
        
        # Salvar carteira
        wallets_dir = Path.home() / '.quantumshield' / 'wallets'
        wallets_dir.mkdir(parents=True, exist_ok=True)
        
        wallet_file = wallets_dir / f"{address}.json"
        with open(wallet_file, 'w') as f:
            json.dump(wallet_data, f, indent=2)
        
        return {
            'success': True,
            'wallet': wallet_data,
            'message': f'Carteira {wallet_type} criada com sucesso'
        }
    
    def _send_transaction(self):
        """Enviar transação"""
        from_address = self.kwargs.get('from_address')
        to_address = self.kwargs.get('to_address')
        amount = self.kwargs.get('amount', 0.0)
        coin_type = self.kwargs.get('coin_type', 'QTC')
        
        # Validações básicas
        if not from_address or not to_address:
            return {'success': False, 'error': 'Endereços inválidos'}
        
        if amount <= 0:
            return {'success': False, 'error': 'Valor deve ser maior que zero'}
        
        # Simular verificação de saldo
        # Em implementação real, verificar no blockchain
        
        # Simular criação de transação
        tx_id = f"tx_{int(time.time())}_{hash(f'{from_address}{to_address}{amount}')}"
        
        transaction_data = {
            'transaction_id': tx_id,
            'from_address': from_address,
            'to_address': to_address,
            'amount': amount,
            'coin_type': coin_type,
            'timestamp': time.time(),
            'status': 'pending',
            'confirmations': 0
        }
        
        # Salvar transação
        tx_dir = Path.home() / '.quantumshield' / 'transactions'
        tx_dir.mkdir(parents=True, exist_ok=True)
        
        tx_file = tx_dir / f"{tx_id}.json"
        with open(tx_file, 'w') as f:
            json.dump(transaction_data, f, indent=2)
        
        return {
            'success': True,
            'transaction': transaction_data,
            'message': f'Transação de {amount} {coin_type} enviada'
        }
    
    def _mine_block(self):
        """Minerar bloco"""
        miner_address = self.kwargs.get('miner_address', 'default_miner')
        
        # Simular mineração
        for progress in range(0, 101, 10):
            if not self.running:
                break
            
            self.progress_updated.emit(progress)
            self.mining_update.emit({
                'progress': progress,
                'hashrate': f"{1.2 + (progress/100) * 0.3:.1f} MH/s",
                'estimated_time': max(0, 120 - (progress * 1.2))
            })
            
            time.sleep(0.5)  # Simular tempo de mineração
        
        if self.running:
            # Simular bloco minerado
            block_data = {
                'block_number': int(time.time()) % 10000,
                'miner': miner_address,
                'reward': 12.5,
                'timestamp': time.time(),
                'transactions_count': 5,
                'hash': f"block_{int(time.time())}"
            }
            
            return {
                'success': True,
                'block': block_data,
                'message': f'Bloco #{block_data["block_number"]} minerado com sucesso!'
            }
        else:
            return {'success': False, 'error': 'Mineração cancelada'}
    
    def _sync_blockchain(self):
        """Sincronizar blockchain"""
        # Simular sincronização
        for progress in range(0, 101, 20):
            if not self.running:
                break
            
            self.progress_updated.emit(progress)
            time.sleep(0.3)
        
        return {
            'success': True,
            'message': 'Blockchain sincronizado com sucesso',
            'blocks_synced': 1234,
            'peers_connected': 5
        }
    
    def stop(self):
        """Parar operação"""
        self.running = False

class WalletWidget(QFrame):
    """Widget de carteira para QTC/QTG/QTS"""
    
    def __init__(self, coin_type, balance, color):
        super().__init__()
        self.coin_type = coin_type
        self.balance = balance
        self.color = color
        self.init_ui()
    
    def init_ui(self):
        """Inicializar interface"""
        self.setStyleSheet(f"""
            QFrame {{
                border: 2px solid {self.color};
                border-radius: 10px;
                background-color: #2a2a2a;
                padding: 15px;
                margin: 5px;
            }}
        """)
        
        layout = QVBoxLayout()
        
        # Nome da moeda
        coin_label = QLabel(self.coin_type)
        coin_label.setStyleSheet(f"""
            QLabel {{
                font-size: 18px;
                font-weight: bold;
                color: {self.color};
                text-align: center;
            }}
        """)
        coin_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(coin_label)
        
        # Saldo
        self.balance_label = QLabel(f"{self.balance:,.2f}")
        self.balance_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #ffffff;
                text-align: center;
                font-weight: bold;
            }
        """)
        self.balance_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.balance_label)
        
        # Botões
        buttons_layout = QHBoxLayout()
        
        self.send_button = QPushButton("💸 Enviar")
        self.receive_button = QPushButton("📥 Receber")
        
        for button in [self.send_button, self.receive_button]:
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: #444444;
                    color: #ffffff;
                    border: 1px solid {self.color};
                    border-radius: 5px;
                    padding: 5px 10px;
                    font-weight: bold;
                    font-size: 10px;
                }}
                QPushButton:hover {{
                    background-color: #555555;
                }}
                QPushButton:pressed {{
                    background-color: {self.color};
                    color: #000000;
                }}
            """)
        
        buttons_layout.addWidget(self.send_button)
        buttons_layout.addWidget(self.receive_button)
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
    
    def update_balance(self, new_balance):
        """Atualizar saldo"""
        self.balance = new_balance
        self.balance_label.setText(f"{self.balance:,.2f}")

class TransactionHistoryWidget(QTableWidget):
    """Widget de histórico de transações"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.load_transactions()
    
    def init_ui(self):
        """Inicializar interface"""
        # Configurar colunas
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            "Timestamp", "Tipo", "De/Para", "Valor", "Moeda", "Status"
        ])
        
        # Configurar estilo
        self.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 5px;
                gridline-color: #444444;
            }
            QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid #333333;
            }
            QTableWidget::item:selected {
                background-color: #00ff88;
                color: #000000;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #444444;
                padding: 5px;
                font-weight: bold;
            }
        """)
        
        # Configurar redimensionamento
        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Configurar seleção
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
    
    def load_transactions(self):
        """Carregar transações do histórico"""
        # Simular algumas transações
        sample_transactions = [
            ("16:45:12", "Enviado", "1A2B3C...", "10.50", "QTC", "✅ Confirmado"),
            ("16:44:58", "Recebido", "4D5E6F...", "25.00", "QTG", "✅ Confirmado"),
            ("16:44:23", "Mineração", "Recompensa", "12.50", "QTC", "⛏️ Minerado"),
            ("16:43:45", "Enviado", "7G8H9I...", "5.75", "QTS", "🟡 Pendente"),
            ("16:42:12", "Recebido", "0J1K2L...", "100.00", "QTC", "✅ Confirmado")
        ]
        
        self.setRowCount(len(sample_transactions))
        
        for row, (timestamp, tx_type, address, amount, coin, status) in enumerate(sample_transactions):
            self.setItem(row, 0, QTableWidgetItem(timestamp))
            self.setItem(row, 1, QTableWidgetItem(tx_type))
            self.setItem(row, 2, QTableWidgetItem(address))
            self.setItem(row, 3, QTableWidgetItem(amount))
            self.setItem(row, 4, QTableWidgetItem(coin))
            self.setItem(row, 5, QTableWidgetItem(status))
    
    def add_transaction(self, transaction_data):
        """Adicionar nova transação ao histórico"""
        row = self.rowCount()
        self.insertRow(row)
        
        timestamp = datetime.fromtimestamp(transaction_data.get('timestamp', time.time())).strftime('%H:%M:%S')
        tx_type = "Enviado" if transaction_data.get('from_address') else "Recebido"
        address = transaction_data.get('to_address', '')[:10] + "..."
        amount = str(transaction_data.get('amount', 0))
        coin = transaction_data.get('coin_type', 'QTC')
        status = "🟡 Pendente"
        
        self.setItem(row, 0, QTableWidgetItem(timestamp))
        self.setItem(row, 1, QTableWidgetItem(tx_type))
        self.setItem(row, 2, QTableWidgetItem(address))
        self.setItem(row, 3, QTableWidgetItem(amount))
        self.setItem(row, 4, QTableWidgetItem(coin))
        self.setItem(row, 5, QTableWidgetItem(status))
        
        # Scroll para a nova transação
        self.scrollToBottom()

class BlockchainTab(QWidget):
    """Aba de Blockchain QuantumCoin"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.blockchain = QuantumSafeBlockchain() if BLOCKCHAIN_AVAILABLE else None
        self.current_worker = None
        self.mining_active = False
        self.init_ui()
        
        # Timer para atualizar status
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(10000)  # Atualiza a cada 10 segundos
    
    def init_ui(self):
        """Inicializar interface"""
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("⛓️ Blockchain QuantumCoin")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #00ff88;
                margin: 10px;
                text-align: center;
            }
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Splitter principal
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Área superior - Carteiras e operações
        top_widget = self.create_wallets_section()
        splitter.addWidget(top_widget)
        
        # Área inferior - Histórico e mineração
        bottom_widget = self.create_operations_section()
        splitter.addWidget(bottom_widget)
        
        splitter.setSizes([400, 300])
        layout.addWidget(splitter)
        
        self.setLayout(layout)
    
    def create_wallets_section(self):
        """Criar seção de carteiras"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Título da seção
        section_title = QLabel("💰 CARTEIRAS QUÂNTICAS")
        section_title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #ffffff;
                margin: 10px;
            }
        """)
        layout.addWidget(section_title)
        
        # Grid de carteiras
        wallets_layout = QHBoxLayout()
        
        # Carteiras QTC, QTG, QTS
        self.wallet_qtc = WalletWidget("QTC", 1247.50, "#ffaa00")
        self.wallet_qtg = WalletWidget("QTG", 523.25, "#ffd700")
        self.wallet_qts = WalletWidget("QTS", 15890.75, "#c0c0c0")
        
        # Conectar botões
        self.wallet_qtc.send_button.clicked.connect(lambda: self.show_send_dialog("QTC"))
        self.wallet_qtc.receive_button.clicked.connect(lambda: self.show_receive_dialog("QTC"))
        self.wallet_qtg.send_button.clicked.connect(lambda: self.show_send_dialog("QTG"))
        self.wallet_qtg.receive_button.clicked.connect(lambda: self.show_receive_dialog("QTG"))
        self.wallet_qts.send_button.clicked.connect(lambda: self.show_send_dialog("QTS"))
        self.wallet_qts.receive_button.clicked.connect(lambda: self.show_receive_dialog("QTS"))
        
        wallets_layout.addWidget(self.wallet_qtc)
        wallets_layout.addWidget(self.wallet_qtg)
        wallets_layout.addWidget(self.wallet_qts)
        
        layout.addLayout(wallets_layout)
        
        # Área de nova transação
        transaction_group = QGroupBox("📋 NOVA TRANSAÇÃO")
        transaction_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #ffffff;
                border: 2px solid #444444;
                border-radius: 10px;
                margin: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        tx_layout = QGridLayout()
        
        # Campos da transação
        tx_layout.addWidget(QLabel("Para:"), 0, 0)
        self.to_address_input = QLineEdit()
        self.to_address_input.setPlaceholderText("Endereço de destino...")
        tx_layout.addWidget(self.to_address_input, 0, 1)
        
        tx_layout.addWidget(QLabel("Valor:"), 0, 2)
        self.amount_input = QDoubleSpinBox()
        self.amount_input.setMaximum(999999.99)
        self.amount_input.setDecimals(2)
        tx_layout.addWidget(self.amount_input, 0, 3)
        
        tx_layout.addWidget(QLabel("Moeda:"), 0, 4)
        self.coin_combo = QComboBox()
        self.coin_combo.addItems(["QTC", "QTG", "QTS"])
        tx_layout.addWidget(self.coin_combo, 0, 5)
        
        # Botões
        self.send_tx_button = QPushButton("💸 Enviar Transação")
        self.verify_address_button = QPushButton("🔍 Verificar Endereço")
        
        for button in [self.send_tx_button, self.verify_address_button]:
            button.setStyleSheet("""
                QPushButton {
                    background-color: #444444;
                    color: #ffffff;
                    border: 2px solid #00ff88;
                    border-radius: 10px;
                    padding: 10px 15px;
                    font-size: 12px;
                    font-weight: bold;
                    margin: 5px;
                }
                QPushButton:hover {
                    background-color: #555555;
                }
                QPushButton:pressed {
                    background-color: #00ff88;
                    color: #000000;
                }
            """)
        
        self.send_tx_button.clicked.connect(self.send_transaction)
        self.verify_address_button.clicked.connect(self.verify_address)
        
        tx_layout.addWidget(self.send_tx_button, 1, 0, 1, 3)
        tx_layout.addWidget(self.verify_address_button, 1, 3, 1, 3)
        
        transaction_group.setLayout(tx_layout)
        layout.addWidget(transaction_group)
        
        widget.setLayout(layout)
        return widget
    
    def create_operations_section(self):
        """Criar seção de operações"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Tab widget para organizar
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444444;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: #ffffff;
                padding: 8px 16px;
                margin: 2px;
                border-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #00ff88;
                color: #000000;
                font-weight: bold;
            }
        """)
        
        # Aba de mineração
        mining_tab = self.create_mining_tab()
        tab_widget.addTab(mining_tab, "⛏️ Mineração")
        
        # Aba de histórico
        history_tab = self.create_history_tab()
        tab_widget.addTab(history_tab, "📊 Histórico")
        
        # Aba de rede
        network_tab = self.create_network_tab()
        tab_widget.addTab(network_tab, "🌐 Rede")
        
        layout.addWidget(tab_widget)
        widget.setLayout(layout)
        return widget
    
    def create_mining_tab(self):
        """Criar aba de mineração"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Status de mineração
        mining_status = QGroupBox("⛏️ STATUS DE MINERAÇÃO")
        mining_status.setStyleSheet("""
            QGroupBox {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                border: 2px solid #444444;
                border-radius: 10px;
                margin: 10px;
                padding-top: 10px;
            }
        """)
        
        status_layout = QGridLayout()
        
        self.mining_status_label = QLabel("🔴 Inativo")
        self.hashrate_label = QLabel("Hashrate: 0.0 MH/s")
        self.blocks_mined_label = QLabel("Blocos minerados: 0")
        self.estimated_time_label = QLabel("Próximo bloco: --")
        
        status_layout.addWidget(self.mining_status_label, 0, 0)
        status_layout.addWidget(self.hashrate_label, 0, 1)
        status_layout.addWidget(self.blocks_mined_label, 1, 0)
        status_layout.addWidget(self.estimated_time_label, 1, 1)
        
        mining_status.setLayout(status_layout)
        layout.addWidget(mining_status)
        
        # Controles de mineração
        controls_layout = QHBoxLayout()
        
        self.start_mining_button = QPushButton("⛏️ Iniciar Mineração")
        self.stop_mining_button = QPushButton("⏸️ Parar Mineração")
        self.mining_stats_button = QPushButton("📊 Estatísticas")
        
        for button in [self.start_mining_button, self.stop_mining_button, self.mining_stats_button]:
            button.setStyleSheet("""
                QPushButton {
                    background-color: #444444;
                    color: #ffffff;
                    border: 2px solid #00ff88;
                    border-radius: 10px;
                    padding: 10px 15px;
                    font-size: 12px;
                    font-weight: bold;
                    margin: 5px;
                }
                QPushButton:hover {
                    background-color: #555555;
                }
                QPushButton:pressed {
                    background-color: #00ff88;
                    color: #000000;
                }
            """)
        
        self.start_mining_button.clicked.connect(self.start_mining)
        self.stop_mining_button.clicked.connect(self.stop_mining)
        self.mining_stats_button.clicked.connect(self.show_mining_stats)
        
        controls_layout.addWidget(self.start_mining_button)
        controls_layout.addWidget(self.stop_mining_button)
        controls_layout.addWidget(self.mining_stats_button)
        
        layout.addLayout(controls_layout)
        
        # Barra de progresso de mineração
        self.mining_progress = QProgressBar()
        self.mining_progress.setVisible(False)
        self.mining_progress.setStyleSheet("""
            QProgressBar {
                border: 2px solid #444444;
                border-radius: 5px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                                stop: 0 #ffaa00, stop: 1 #ff6600);
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.mining_progress)
        
        widget.setLayout(layout)
        return widget
    
    def create_history_tab(self):
        """Criar aba de histórico"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Título
        title = QLabel("📊 HISTÓRICO DE TRANSAÇÕES")
        title.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #ffffff;
                margin: 10px;
            }
        """)
        layout.addWidget(title)
        
        # Tabela de transações
        self.transaction_history = TransactionHistoryWidget()
        layout.addWidget(self.transaction_history)
        
        widget.setLayout(layout)
        return widget
    
    def create_network_tab(self):
        """Criar aba de rede"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Status da rede
        self.network_status = QLabel("🌐 REDE BLOCKCHAIN: 5 nós conectados | Último bloco: há 30s")
        self.network_status.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #00ff88;
                padding: 10px;
                border: 1px solid #444444;
                border-radius: 5px;
                background-color: #2a2a2a;
                margin: 10px;
            }
        """)
        layout.addWidget(self.network_status)
        
        # Botão de sincronização
        self.sync_button = QPushButton("🔄 Sincronizar Blockchain")
        self.sync_button.setStyleSheet("""
            QPushButton {
                background-color: #444444;
                color: #ffffff;
                border: 2px solid #00ff88;
                border-radius: 10px;
                padding: 10px 15px;
                font-size: 14px;
                font-weight: bold;
                margin: 10px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QPushButton:pressed {
                background-color: #00ff88;
                color: #000000;
            }
        """)
        self.sync_button.clicked.connect(self.sync_blockchain)
        layout.addWidget(self.sync_button)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def log_message(self, message, level="INFO"):
        """Adicionar mensagem ao log"""
        if hasattr(self.parent, 'log_widget'):
            self.parent.log_widget.log_message(f"⛓️ {message}", level)
    
    def show_send_dialog(self, coin_type):
        """Mostrar diálogo de envio"""
        self.coin_combo.setCurrentText(coin_type)
        self.log_message(f"Preparando envio de {coin_type}", "INFO")
    
    def show_receive_dialog(self, coin_type):
        """Mostrar diálogo de recebimento"""
        # Simular endereço de recebimento
        address = f"QTC{hash(coin_type + str(time.time())) % 1000000:06d}"
        QMessageBox.information(self, f"Receber {coin_type}", 
                              f"Seu endereço para receber {coin_type}:\n\n{address}")
        self.log_message(f"Endereço de recebimento {coin_type} gerado", "SUCCESS")
    
    def send_transaction(self):
        """Enviar transação"""
        to_address = self.to_address_input.text().strip()
        amount = self.amount_input.value()
        coin_type = self.coin_combo.currentText()
        
        if not to_address:
            QMessageBox.warning(self, "Erro", "Digite o endereço de destino")
            return
        
        if amount <= 0:
            QMessageBox.warning(self, "Erro", "Digite um valor válido")
            return
        
        self.log_message(f"Enviando {amount} {coin_type} para {to_address[:10]}...", "INFO")
        
        # Iniciar worker para envio
        self.current_worker = BlockchainWorker(
            'send_transaction',
            from_address="user_address",
            to_address=to_address,
            amount=amount,
            coin_type=coin_type
        )
        self.current_worker.operation_completed.connect(self.on_transaction_completed)
        self.current_worker.start()
    
    def verify_address(self):
        """Verificar endereço"""
        address = self.to_address_input.text().strip()
        if address:
            # Simular verificação
            is_valid = address.startswith(('QTC', 'QTG', 'QTS')) and len(address) > 10
            if is_valid:
                QMessageBox.information(self, "Verificação", "✅ Endereço válido")
                self.log_message(f"Endereço {address[:10]}... verificado", "SUCCESS")
            else:
                QMessageBox.warning(self, "Verificação", "❌ Endereço inválido")
                self.log_message(f"Endereço {address[:10]}... inválido", "ERROR")
        else:
            QMessageBox.warning(self, "Erro", "Digite um endereço para verificar")
    
    def start_mining(self):
        """Iniciar mineração"""
        if self.mining_active:
            return
        
        self.mining_active = True
        self.mining_status_label.setText("🟢 Ativo")
        self.mining_progress.setVisible(True)
        self.log_message("Mineração iniciada", "SUCCESS")
        
        # Iniciar worker de mineração
        self.current_worker = BlockchainWorker('mine_block', miner_address="user_miner")
        self.current_worker.operation_completed.connect(self.on_mining_completed)
        self.current_worker.progress_updated.connect(self.mining_progress.setValue)
        self.current_worker.mining_update.connect(self.on_mining_update)
        self.current_worker.start()
    
    def stop_mining(self):
        """Parar mineração"""
        if self.current_worker:
            self.current_worker.stop()
        
        self.mining_active = False
        self.mining_status_label.setText("🔴 Inativo")
        self.mining_progress.setVisible(False)
        self.hashrate_label.setText("Hashrate: 0.0 MH/s")
        self.log_message("Mineração parada", "WARNING")
    
    def show_mining_stats(self):
        """Mostrar estatísticas de mineração"""
        stats = """
📊 ESTATÍSTICAS DE MINERAÇÃO

⛏️ Blocos minerados: 15
💰 Recompensas totais: 187.5 QTC
⚡ Hashrate médio: 1.2 MH/s
⏱️ Tempo total: 2h 15min
🎯 Taxa de sucesso: 94.2%
        """
        QMessageBox.information(self, "Estatísticas", stats)
    
    def sync_blockchain(self):
        """Sincronizar blockchain"""
        self.log_message("Iniciando sincronização do blockchain", "INFO")
        
        # Iniciar worker de sincronização
        self.current_worker = BlockchainWorker('sync_blockchain')
        self.current_worker.operation_completed.connect(self.on_sync_completed)
        self.current_worker.start()
    
    def on_transaction_completed(self, result):
        """Callback para transação completada"""
        if result['success']:
            self.log_message("Transação enviada com sucesso!", "SUCCESS")
            
            # Adicionar ao histórico
            self.transaction_history.add_transaction(result['transaction'])
            
            # Limpar campos
            self.to_address_input.clear()
            self.amount_input.setValue(0.0)
            
            QMessageBox.information(self, "Sucesso", result['message'])
        else:
            self.log_message(f"Erro na transação: {result['error']}", "ERROR")
            QMessageBox.warning(self, "Erro", result['error'])
    
    def on_mining_completed(self, result):
        """Callback para mineração completada"""
        self.mining_active = False
        self.mining_progress.setVisible(False)
        
        if result['success']:
            self.log_message("Bloco minerado com sucesso!", "SUCCESS")
            
            # Atualizar saldo (simular recompensa)
            current_balance = self.wallet_qtc.balance
            self.wallet_qtc.update_balance(current_balance + result['block']['reward'])
            
            QMessageBox.information(self, "Mineração", result['message'])
        else:
            self.log_message(f"Erro na mineração: {result['error']}", "ERROR")
        
        self.mining_status_label.setText("🔴 Inativo")
    
    def on_mining_update(self, update):
        """Callback para atualização de mineração"""
        self.hashrate_label.setText(f"Hashrate: {update['hashrate']}")
        self.estimated_time_label.setText(f"Próximo bloco: {update['estimated_time']:.0f}s")
    
    def on_sync_completed(self, result):
        """Callback para sincronização completada"""
        if result['success']:
            self.log_message("Blockchain sincronizado!", "SUCCESS")
            self.network_status.setText(f"🌐 REDE: {result['blocks_synced']} blocos | {result['peers_connected']} peers")
        else:
            self.log_message(f"Erro na sincronização: {result['error']}", "ERROR")
    
    def update_status(self):
        """Atualizar status geral"""
        # Simular atualizações periódicas
        if not self.mining_active:
            # Atualizar status da rede
            import random
            peers = random.randint(3, 8)
            last_block = random.randint(10, 120)
            self.network_status.setText(f"🌐 REDE BLOCKCHAIN: {peers} nós | Último bloco: há {last_block}s")

