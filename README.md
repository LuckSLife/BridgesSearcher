📌 Sobre o Projeto
O Bridges Searcher é uma aplicação desktop desenvolvida em Python utilizando a biblioteca customtkinter, projetada para centralizar e otimizar rotinas de auditoria de rede, varreduras de infraestrutura web, chamadas interativas de terminal e ferramentas automatizadas de reparo no sistema operacional.

🚀 Funcionalidades Principais

1. 🔍 Aba Recon (OSINT)
Realiza varreduras detalhadas em alvos de domínio ou endereços IP.
Módulos suportados: Resolução de domínio, enumeração de subdomínios, extração de registros DNS (A, MX, NS, TXT), consultas Whois, Reverse IP (PTR), Reverse Whois e informações de AS/ASN via RDAP.
Exportação de logs e relatórios consolidados diretamente pela interface.

2. 💻 Aba Terminal Console Manual
Permite executar comandos diretamente no sistema operacional de forma interativa com retorno em tempo real no console visual.

3. 🌐 Aba Web Fuzzer - FFUF
Interface gráfica integrada para o executável ffuf.
Configuração ágil de URLs com a palavra-chave FUZZ e seletor rápido de wordlists locais.

4. 🛡️ Aba Port Scanner - Nmap
Execução otimizada de varreduras de portas e scripts de enumeração NSE (http-title, ssl-cert).
Suporte a varreduras padrão ou inserção de flags customizadas (-A, -T4, etc.).

5. 🛠️ Aba AutoFix

Ferramenta dual de manutenção do sistema e da aplicação:
Executar AutoFix Geral: Reindexação de caches, limpeza de sessões redundantes e otimização dos módulos internos.
Executar Comandos Passo a Passo: Execução sequencial controlada dos principais comandos de rede nativos do Windows:

ipconfig /release
ipconfig /flushdns
ipconfig /renew
netsh int ip set dns
netsh winsock reset

📋 Pré-requisitos

Python 3.8 ou superior instalado na máquina.
Permissões de Administrador (necessárias para a execução correta de comandos de rede na aba AutoFix).
Binários externos (opcionais para abas específicas): nmap e ffuf instalados e configurados no PATH do sistema.

🛠️ Instalação e Dependências
Clone ou baixe este repositório em sua máquina:
git clone https://github.com/seu-usuario/bridges-searcher.git
cd bridges-searcher


Instale as dependências Python necessárias executando o comando abaixo no terminal:
pip install customtkinter beautifulsoup4 dnspython python-whois ipwhois


🚀 Como Executar
Para iniciar a aplicação, certifique-se de estar na pasta raiz do projeto e execute:

python app.py


📄 Exportação de Relatórios
Todas as abas principais contêm um botão de extração de relatórios, permitindo salvar logs limpos diretamente em arquivos .txt no seu computador para documentação e auditoria.

🛡️ Licença
Este projeto é distribuído sob a licença MIT. Sinta-se à vontade para contribuir, abrir issues ou sugerir melhorias.
