# NetCheck

Ferramenta de diagnóstico de rede desenvolvida em Python para verificar a resolução DNS e a conectividade TCP de hosts e portas.

## Funcionalidades

- **Verificação DNS:** verifica se um domínio pode ser resolvido para um endereço IP.
- **Teste TCP:** verifica se é possível estabelecer uma conexão com um host e uma porta.
- **Medição de latência:** registra o tempo necessário para estabelecer a conexão TCP.
- **Relatórios:** salva os resultados dos diagnósticos em arquivos na pasta `reports/`.
- **Testes automatizados:** utiliza `unittest` para verificar o funcionamento das principais funções.

## Requisitos

- Python 3.13 ou superior.
- Conexão com a rede para testar hosts externos.

## Como executar

Entre na pasta do projeto e execute:

```bash
python netcheck.py
```

O programa executará os diagnósticos definidos no código e registrará os resultados.

## Executar os testes

Para executar os testes automatizados:

```bash
python -m unittest discover -s tests -v
```

Os testes verificam os cenários de sucesso e falha das funções de DNS e conexão TCP.

## Estrutura do projeto

```text
netcheck/
├── netcheck.py
├── tests/
│   └── test_netcheck.py
└── reports/
```

A pasta `reports/` é criada para armazenar os relatórios gerados durante os diagnósticos.

## Tecnologias

- Python
- Socket
- Unittest
- Git e GitHub Actions

## Objetivo

Projeto de estudo voltado para diagnóstico de redes, automação de tarefas e testes automatizados, aplicando conceitos úteis para suporte técnico e infraestrutura de TI.
