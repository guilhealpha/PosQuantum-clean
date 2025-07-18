# INSTRUÇÕES PARA BUILD DO POSQUANTUM NO WINDOWS

Este documento contém instruções detalhadas para gerar o executável Windows do PosQuantum, incluindo todas as funcionalidades e camadas de criptografia pós-quântica.

## 1. REQUISITOS

- **Windows 10 ou 11** (64 bits)
- **Python 3.8 ou superior** (https://www.python.org/downloads/windows/)
- **Conexão com a Internet** (para download de dependências)

## 2. PREPARAÇÃO DO AMBIENTE

1. **Instalar Python**:
   - Baixe o instalador do Python em https://www.python.org/downloads/windows/
   - Execute o instalador e marque a opção "Add Python to PATH"
   - Clique em "Install Now"

2. **Extrair Arquivos**:
   - Extraia o conteúdo do arquivo `PosQuantum-Windows-Build.zip` em um diretório de sua escolha
   - Abra o Prompt de Comando (cmd) ou PowerShell
   - Navegue até o diretório onde os arquivos foram extraídos:
     ```
     cd caminho\para\PosQuantum-clean
     ```

## 3. MÉTODO SIMPLES (RECOMENDADO)

1. **Executar o Arquivo Batch**:
   - Simplesmente execute o arquivo `build_windows.bat` com um duplo clique
   - Ou execute-o a partir do Prompt de Comando:
     ```
     build_windows.bat
     ```
   - O script instalará automaticamente todas as dependências e gerará o executável

2. **Verificar o Executável**:
   - Após a conclusão, o executável será gerado em `dist\PosQuantum-3.0.exe`
   - Execute o executável para verificar se todas as funcionalidades estão funcionando corretamente

## 4. MÉTODO MANUAL (PARA USUÁRIOS AVANÇADOS)

Se preferir executar os comandos manualmente, siga estas etapas:

1. **Instalar Dependências**:
   ```
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   pip install pyinstaller
   pip install PyQt6
   ```

2. **Criar Hook de Runtime**:
   - Crie um diretório `hooks` se não existir:
     ```
     mkdir hooks
     ```
   - Crie um arquivo `hooks\runtime_hook.py` com o conteúdo do arquivo fornecido

3. **Executar PyInstaller**:
   ```
   python -m PyInstaller --clean --noconfirm --onefile --name="PosQuantum-3.0" --add-data="assets;assets" --add-data="posquantum_modules;posquantum_modules" --hidden-import="PyQt6.QtCore" --hidden-import="PyQt6.QtGui" --hidden-import="PyQt6.QtWidgets" --hidden-import="posquantum_modules.crypto" --hidden-import="posquantum_modules.network" --hidden-import="posquantum_modules.compliance" --hidden-import="posquantum_modules.crypto.ml_kem" --hidden-import="posquantum_modules.crypto.ml_dsa" --hidden-import="posquantum_modules.crypto.sphincs_plus" --hidden-import="posquantum_modules.crypto.elliptic_curve_pq_hybrid" --hidden-import="posquantum_modules.crypto.hsm_virtual" --hidden-import="posquantum_modules.network.vpn_pq" --hidden-import="posquantum_modules.compliance.certifications" --runtime-hook="hooks\runtime_hook.py" main.py
   ```

4. **Verificar o Executável**:
   - O executável será gerado em `dist\PosQuantum-3.0.exe`

## 5. SOLUÇÃO DE PROBLEMAS

### 5.1. Erro de DLL não encontrada

Se você receber um erro sobre DLLs não encontradas ao executar o executável, pode ser necessário instalar o Microsoft Visual C++ Redistributable:

1. Baixe o Microsoft Visual C++ Redistributable para Visual Studio 2015, 2017 e 2019 do [site da Microsoft](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads)
2. Instale o pacote e tente executar o PosQuantum novamente

### 5.2. Erro de módulos não encontrados

Se o PyInstaller não incluir todos os módulos necessários, você pode adicionar mais módulos usando o parâmetro `--hidden-import`:

```
pyinstaller --clean --noconfirm --onefile --name="PosQuantum-3.0" --add-data="assets;assets" --add-data="posquantum_modules;posquantum_modules" --hidden-import="PyQt6.QtCore" --hidden-import="PyQt6.QtGui" --hidden-import="PyQt6.QtWidgets" --hidden-import="posquantum_modules.crypto" --hidden-import="posquantum_modules.network" --hidden-import="posquantum_modules.compliance" --hidden-import="MODULO_ADICIONAL" --runtime-hook="hooks\runtime_hook.py" main.py
```

### 5.3. Erro de Python não encontrado

Se você receber um erro indicando que o Python não foi encontrado, verifique se o Python está instalado corretamente e adicionado ao PATH do sistema:

1. Abra o Painel de Controle > Sistema > Configurações avançadas do sistema > Variáveis de ambiente
2. Verifique se o diretório do Python (por exemplo, `C:\Python310` e `C:\Python310\Scripts`) está na variável PATH
3. Se não estiver, adicione-o e reinicie o Prompt de Comando

## 6. VERIFICAÇÃO DO EXECUTÁVEL

Para verificar se o executável foi gerado corretamente:

1. Execute o executável gerado (`dist\PosQuantum-3.0.exe`)
2. Verifique se todas as 16 abas estão presentes
3. Teste as funcionalidades principais
4. Verifique se a criptografia pós-quântica está funcionando corretamente

## 7. ALTERNATIVA: DOWNLOAD DO EXECUTÁVEL PRÉ-COMPILADO

Se preferir, você pode baixar o executável pré-compilado do GitHub:

1. Acesse https://github.com/guilhealpha/PosQuantum-clean/actions
2. Baixe o artefato "PosQuantum-Windows" da execução mais recente
3. Ou acesse https://github.com/guilhealpha/PosQuantum-clean/releases para baixar a release mais recente

---

**Autor**: PosQuantum Team  
**Data**: 18/07/2025  
**Versão**: 3.0

