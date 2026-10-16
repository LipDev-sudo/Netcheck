# NetCheck — Diagnóstico de Redes

Ferramenta de linha de comando desenvolvida em Python para diagnóstico básico de DNS e conectividade TCP.

## Funcionalidades

- Resolução DNS de domínios para IPv4.
- Teste de conectividade TCP em portas configuráveis.
- Timeout para tentativas de conexão.
- Medição aproximada do tempo de estabelecimento da conexão TCP.
- Validação da entrada de domínio e número da porta.
- Geração de relatórios em arquivos TXT.
- Testes automatizados com `unittest` e `unittest.mock`.

## Tecnologias

- Python 3.13
- Biblioteca padrão `socket`
- Biblioteca padrão `time`
- `pathlib` e `datetime`
- `unittest`

## Como executar

Clone o repositório ou baixe os arquivos e entre na pasta do projeto.

Execute:

```bash
python3 netcheck.py
```

Informe um domínio e uma porta TCP. Pressione Enter no campo da porta para utilizar a porta padrão 443.

Os relatórios são salvos na pasta `reports/`.

## Executar os testes

```bash
python3 -m unittest discover -s tests -v
```

A suíte atual contém quatro testes automatizados para os comportamentos de sucesso e falha das funções DNS e TCP.

## Limitações

- A resolução DNS utiliza `socket.gethostbyname`, que retorna um endereço IPv4.
- O teste TCP confirma o estabelecimento de uma conexão, não o funcionamento completo do serviço.
- O tempo medido representa aproximadamente o estabelecimento da conexão TCP, não o tempo total de carregamento de uma página.
- Os resultados dependem da rede, do DNS, do destino e das regras de firewall.

## Objetivo

Projeto de estudo para praticar Python, diagnóstico de redes, tratamento de erros, automação e testes de software.

## Status

Projeto em desenvolvimento. Os testes automatizados atuais foram executados com sucesso no ambiente de desenvolvimento.