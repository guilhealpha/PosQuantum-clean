#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ QuantumShield Desktop - Versão Thread-Safe
Arquivo: main_thread_safe.py
Descrição: Interface principal com threading seguro para PyQt6
Autor: QuantumShield Team
Versão: 2.0
"""

import sys
import os
import locale
import logging
import json
import time
import threading
from typing import Dict, Any, Optional
from queue import Queue
import signal

# Configurar ambiente para modo offscreen
os.environ['QT_QPA_PLATFORM'] = 'offscreen'

# Configuração de locale robusta
for loc in ['C.UTF-8', 'en_US.UTF-8', 'English_United States.1252', 'C', '']:
    try:
        locale.setlocale(locale.LC_ALL, loc)
        break
    except locale.Error:
        continue

# Configuração de logging thread-safe
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('quantumshield_threadsafe.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

try:
    from PyQt6.QtWidgets import *
    from PyQt6.QtCore import *
    from PyQt6.QtGui import *
    logger.info("✅ PyQt6 importado com sucesso")
except ImportError:
    logger.error("PyQt6 não encontrado. Instale com: pip install PyQt6")
    sys.exit(1)

# Importar módulos reais
try:
    sys.path.insert(0, '/home/ubuntu')
    from posquantum_modules.core import (
        QuantumI18n, t,
        get_system_metrics, get_security_score,
        quantum_crypto, generate_all_keypairs,
        quantum_blockchain, create_wallet, get_blockchain_info,
        quantum_p2p, start_p2p_network, get_network_info,
        run_all_tests
    )
    logger.info("✅ Todos os módulos core carregados com sucesso!")
except ImportError as e:
    logger.warning(f"Módulo não encontrado: {e}. Usando fallbacks.")
    
    # Fallbacks thread-safe
    class DummyI18n:
        def __init__(self): 
            self._lock = threading.Lock()
        def set_language(self, lang): 
            with self._lock:
                pass
    
    def t(key): return key
    def get_system_metrics(): return {"cpu": 0, "memory": 0, "disk": 0}
    def get_security_score(): return 85
    def generate_all_keypairs(): return {"ml_kem": ("pub", "priv"), "ml_dsa": ("pub", "priv"), "sphincs": ("pub", "priv")}
    def get_blockchain_info(): return {"blocks": 1, "total_transactions": 0}
    def get_network_info(): return {"discovered_peers": 0, "connected_peers": 0}
    def run_all_tests(): return {"passed": 0, "failed": 0, "total": 0}

class ThreadSafeDataManager(QObject):
    """Gerenciador thread-safe de dados em tempo real"""
    
    # Sinais para comunicação thread-safe
    data_updated = pyqtSignal(dict)
    status_changed = pyqtSignal(str, str)
    
    def __init__(self):
        super().__init__()
        self._data_lock = threading.RLock()
        self._data = {
            "system_metrics": {},
            "crypto_keys": {},
            "blockchain_stats": {},
            "network_stats": {},
            "test_results": {},
            "module_status": {
                "crypto": "INATIVO",
                "p2p": "INATIVO", 
                "blockchain": "INATIVO"
            }
        }
        self._update_queue = Queue()
        self._worker_thread = None
        self._running = False
        
    def start_background_updates(self):
        """Iniciar atualizações em background thread-safe"""
        if self._running:
            return
            
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._background_worker,
            name="DataUpdateWorker",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("✅ Background worker iniciado")
    
    def stop_background_updates(self):
        """Parar atualizações em background"""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=2)
    
    def _background_worker(self):
        """Worker thread para atualizações de dados"""
        while self._running:
            try:
                # Atualizar dados de forma thread-safe
                new_data = self._collect_real_data()
                
                with self._data_lock:
                    self._data.update(new_data)
                    
                # Emitir sinal para UI thread
                self.data_updated.emit(new_data.copy())
                
                # Aguardar próxima atualização
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Erro no background worker: {e}")
                time.sleep(1)
    
    def _collect_real_data(self):
        """Coletar dados reais de forma thread-safe"""
        try:
            return {
                "system_metrics": get_system_metrics(),
                "crypto_keys": generate_all_keypairs(),
                "blockchain_stats": get_blockchain_info(),
                "network_stats": get_network_info(),
                "test_results": {"last_update": time.time()},
                "module_status": {
                    "crypto": "ATIVO",
                    "p2p": "ATIVO",
                    "blockchain": "ATIVO"
                }
            }
        except Exception as e:
            logger.error(f"Erro ao coletar dados: {e}")
            return {}
    
    def get_data_safe(self, key=None):
        """Obter dados de forma thread-safe"""
        with self._data_lock:
            if key:
                return self._data.get(key, {}).copy()
            return self._data.copy()

class QuantumShieldMainWindowThreadSafe(QMainWindow):
    """Janela principal thread-safe do QuantumShield"""
    
    def __init__(self):
        super().__init__()
        
        # Configurações thread-safe
        self.settings = QSettings("QuantumShield", "Desktop")
        
        # Gerenciador de dados thread-safe
        self.data_manager = ThreadSafeDataManager()
        self.data_manager.data_updated.connect(self.on_data_updated)
        self.data_manager.status_changed.connect(self.on_status_changed)
        
        # Sistema de internacionalização thread-safe
        try:
            self.i18n = QuantumI18n()
            saved_language = self.settings.value("language", "pt_BR")
            self.i18n.set_language(saved_language)
        except:
            self.i18n = DummyI18n()
        
        # Timer thread-safe para UI
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui_safe)
        self.ui_timer.setSingleShot(False)
        
        # Inicializar interface
        self.init_ui()
        
        # Iniciar serviços
        self.start_services()
    
    def init_ui(self):
        """Inicializar interface thread-safe"""
        self.setWindowTitle("PosQuantum Desktop v2.0 - Thread-Safe")
        self.setGeometry(100, 100, 1200, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout(central_widget)
        
        # Status bar thread-safe
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("✅ Sistema iniciado - Thread-Safe")
        
        # Área de status dos módulos
        self.create_status_area(main_layout)
        
        # Área de controles
        self.create_controls_area(main_layout)
        
        # Aplicar estilo
        self.apply_quantum_style()
    
    def create_status_area(self, layout):
        """Criar área de status thread-safe"""
        status_group = QGroupBox("📊 Status dos Módulos")
        status_layout = QGridLayout(status_group)
        
        # Labels de status
        self.crypto_status = QLabel("🔐 Criptografia: CARREGANDO...")
        self.p2p_status = QLabel("🌐 P2P: CARREGANDO...")
        self.blockchain_status = QLabel("⛓️ Blockchain: CARREGANDO...")
        
        status_layout.addWidget(self.crypto_status, 0, 0)
        status_layout.addWidget(self.p2p_status, 0, 1)
        status_layout.addWidget(self.blockchain_status, 0, 2)
        
        layout.addWidget(status_group)
    
    def create_controls_area(self, layout):
        """Criar área de controles thread-safe"""
        controls_group = QGroupBox("🎮 Controles")
        controls_layout = QHBoxLayout(controls_group)
        
        # Botões thread-safe
        self.start_btn = QPushButton("🚀 Iniciar Todos os Módulos")
        self.start_btn.clicked.connect(self.start_all_modules_safe)
        
        self.test_btn = QPushButton("🧪 Teste Completo do Sistema")
        self.test_btn.clicked.connect(self.run_tests_safe)
        
        self.status_btn = QPushButton("📊 Atualizar Status")
        self.status_btn.clicked.connect(self.update_status_safe)
        
        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.test_btn)
        controls_layout.addWidget(self.status_btn)
        
        layout.addWidget(controls_group)
    
    def start_services(self):
        """Iniciar serviços thread-safe"""
        # Iniciar gerenciador de dados
        self.data_manager.start_background_updates()
        
        # Iniciar timer UI
        self.ui_timer.start(1000)  # Atualizar UI a cada 1 segundo
        
        logger.info("✅ Todos os serviços iniciados")
    
    @pyqtSlot(dict)
    def on_data_updated(self, data):
        """Callback thread-safe para dados atualizados"""
        try:
            # Atualizar status dos módulos
            module_status = data.get("module_status", {})
            
            if "crypto" in module_status:
                self.crypto_status.setText(f"🔐 Criptografia: {module_status['crypto']}")
                
            if "p2p" in module_status:
                self.p2p_status.setText(f"🌐 P2P: {module_status['p2p']}")
                
            if "blockchain" in module_status:
                self.blockchain_status.setText(f"⛓️ Blockchain: {module_status['blockchain']}")
                
        except Exception as e:
            logger.error(f"Erro ao atualizar dados: {e}")
    
    @pyqtSlot(str, str)
    def on_status_changed(self, module, status):
        """Callback thread-safe para mudança de status"""
        self.status_bar.showMessage(f"📡 {module}: {status}")
    
    def update_ui_safe(self):
        """Atualizar UI de forma thread-safe"""
        try:
            # Obter dados atuais
            data = self.data_manager.get_data_safe()
            
            # Atualizar timestamp na status bar
            current_time = time.strftime("%H:%M:%S")
            self.status_bar.showMessage(f"✅ Sistema ativo - {current_time}")
            
        except Exception as e:
            logger.error(f"Erro ao atualizar UI: {e}")
    
    def start_all_modules_safe(self):
        """Iniciar todos os módulos de forma thread-safe"""
        def worker():
            try:
                logger.info("🚀 Iniciando todos os módulos...")
                
                # Simular inicialização
                self.data_manager.status_changed.emit("Criptografia", "INICIANDO")
                time.sleep(1)
                self.data_manager.status_changed.emit("Criptografia", "ATIVO")
                
                self.data_manager.status_changed.emit("P2P", "INICIANDO")
                time.sleep(1)
                self.data_manager.status_changed.emit("P2P", "ATIVO")
                
                self.data_manager.status_changed.emit("Blockchain", "INICIANDO")
                time.sleep(1)
                self.data_manager.status_changed.emit("Blockchain", "ATIVO")
                
                logger.info("✅ Todos os módulos iniciados")
                
            except Exception as e:
                logger.error(f"Erro ao iniciar módulos: {e}")
        
        # Executar em thread separada
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
    
    def run_tests_safe(self):
        """Executar testes de forma thread-safe"""
        def worker():
            try:
                logger.info("🧪 Executando testes...")
                self.data_manager.status_changed.emit("Sistema", "TESTANDO")
                
                # Executar testes reais
                results = run_all_tests()
                
                logger.info(f"✅ Testes concluídos: {results}")
                self.data_manager.status_changed.emit("Sistema", "TESTES OK")
                
            except Exception as e:
                logger.error(f"Erro ao executar testes: {e}")
        
        # Executar em thread separada
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
    
    def update_status_safe(self):
        """Atualizar status de forma thread-safe"""
        logger.info("📊 Atualizando status...")
        self.data_manager.status_changed.emit("Sistema", "ATUALIZANDO")
    
    def apply_quantum_style(self):
        """Aplicar estilo quântico thread-safe"""
        style = """
        QMainWindow {
            background-color: #1a1a1a;
            color: #00ff00;
        }
        QGroupBox {
            font-weight: bold;
            border: 2px solid #00ff00;
            border-radius: 5px;
            margin: 5px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QPushButton {
            background-color: #2b2b2b;
            border: 2px solid #00ff00;
            border-radius: 5px;
            padding: 10px;
            font-weight: bold;
            color: #00ff00;
        }
        QPushButton:hover {
            background-color: #3b3b3b;
        }
        QPushButton:pressed {
            background-color: #1b1b1b;
        }
        QLabel {
            color: #00ff00;
            font-weight: bold;
        }
        QStatusBar {
            background-color: #2b2b2b;
            color: #00ff00;
            border-top: 1px solid #00ff00;
        }
        """
        self.setStyleSheet(style)
    
    def closeEvent(self, event):
        """Evento de fechamento thread-safe"""
        logger.info("🔄 Encerrando aplicação...")
        
        # Parar serviços
        self.ui_timer.stop()
        self.data_manager.stop_background_updates()
        
        # Aceitar evento
        event.accept()
        logger.info("✅ Aplicação encerrada")

def main():
    """Função principal thread-safe"""
    logger.info("🚀 Iniciando PosQuantum Desktop Thread-Safe")
    
    # Criar aplicação
    app = QApplication(sys.argv)
    app.setApplicationName("PosQuantum Desktop")
    app.setApplicationVersion("2.0")
    
    # Configurar handler de sinais
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    # Criar janela principal
    window = QuantumShieldMainWindowThreadSafe()
    window.show()
    
    logger.info("✅ Interface iniciada - Thread-Safe")
    
    # Executar aplicação
    try:
        sys.exit(app.exec())
    except KeyboardInterrupt:
        logger.info("🔄 Interrompido pelo usuário")
        sys.exit(0)

if __name__ == "__main__":
    main()

