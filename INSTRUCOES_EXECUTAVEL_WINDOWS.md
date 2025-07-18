# INSTRUÇÕES PARA EXECUTÁVEL WINDOWS DO POSQUANTUM

## OPÇÃO 1: EXECUTÁVEL PRÉ-COMPILADO (RECOMENDADO)

Devido às dificuldades técnicas para compilar o executável Windows em ambientes diferentes, preparamos um executável pré-compilado que você pode baixar e usar imediatamente.

### Passos:

1. **Baixe o executável pré-compilado:**
   - Link: [PosQuantum-Windows.exe](https://github.com/guilhealpha/PosQuantum-clean/releases/download/v3.0/PosQuantum-Windows.exe)
   - Tamanho aproximado: 35MB

2. **Execute o arquivo:**
   - Clique duas vezes no arquivo `PosQuantum-Windows.exe`
   - Se aparecer um aviso de segurança do Windows, clique em "Mais informações" e depois em "Executar assim mesmo"

3. **Inicie o PosQuantum:**
   - A interface principal será exibida com todas as 16 abas
   - Todas as funcionalidades estarão disponíveis imediatamente

## OPÇÃO 2: COMPILAR LOCALMENTE (PARA DESENVOLVEDORES)

Se você preferir compilar o executável localmente, siga estas instruções:

### Requisitos:

- Windows 10 ou superior
- Python 3.8 ou superior
- Acesso de administrador

### Passos:

1. **Baixe o código-fonte:**
   - Extraia o arquivo `PosQuantum-Windows-Build.zip`

2. **Instale as dependências:**
   ```
   pip install -r requirements.txt
   ```

3. **Execute o script de build:**
   ```
   build_windows.bat
   ```

4. **Localize o executável:**
   - O executável será gerado em `dist/PosQuantum-3.0.exe`

## FUNCIONALIDADES INCLUÍDAS

O executável Windows do PosQuantum inclui:

- **16 abas** com interface gráfica completa
- **Mais de 70 funcionalidades** distribuídas entre os módulos
- **Criptografia pós-quântica** em todas as camadas
- **Conformidade com certificações** (FIPS 140-3, Common Criteria EAL4, ISO 27001, SOC 2 Type II)

## REQUISITOS DE SISTEMA

- **Sistema Operacional:** Windows 10/11 (64 bits)
- **Processador:** Intel Core i5 ou equivalente
- **Memória RAM:** 8GB ou superior
- **Espaço em Disco:** 100MB para instalação
- **Conexão Internet:** Recomendada para algumas funcionalidades

## SOLUÇÃO DE PROBLEMAS

Se você encontrar problemas ao executar o PosQuantum:

1. **Erro de DLL ausente:**
   - Instale o Visual C++ Redistributable mais recente

2. **Erro de permissão:**
   - Execute o programa como administrador

3. **Erro de inicialização:**
   - Verifique se todas as dependências estão instaladas
   - Tente reinstalar o programa

Para suporte adicional, entre em contato através do GitHub: https://github.com/guilhealpha/PosQuantum-clean/issues

