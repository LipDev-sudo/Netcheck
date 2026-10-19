# NetCheck

Ferramenta de diagnóstico de rede em linha de comando, escrita em Python. Verifica se um domínio resolve no DNS, testa a conexão TCP em uma porta e salva um relatório em texto.

## Funcionalidades

- resolução DNS do domínio informado;
- teste de conexão TCP (porta padrão 443, timeout de 3 s) com medição do tempo de conexão em milissegundos;
- validação da entrada: domínio não vazio e porta inteira entre 1 e 65535;
- relatório em `reports/netcheck_AAAAMMDD_HHMMSS.txt` com data, domínio, IP, porta e resultado (ou em JSON com `--json`);
- códigos de saída distintos para uso em scripts.

## Tecnologias

- Python 3.13
- Biblioteca padrão (`socket`, `time`, `datetime`, `pathlib`), sem dependências externas
- `unittest` e GitHub Actions para testes automatizados

## Como executar

```bash
git clone https://github.com/LipDev-sudo/Netcheck.git
cd Netcheck
python3 netcheck.py
```

Sem argumentos, o programa pergunta o domínio e a porta (Enter usa 443). Também aceita argumentos:

```bash
python3 netcheck.py example.com                  # porta 443
python3 netcheck.py example.com -p 80 -t 5       # porta 80, timeout de 5 s
python3 netcheck.py example.com --json           # resultado em JSON
python3 netcheck.py example.com --sem-relatorio  # não grava arquivo
python3 netcheck.py --help
```

| Opção | Descrição |
| --- | --- |
| `-p`, `--porta` | porta TCP (padrão 443) |
| `-t`, `--timeout` | tempo limite em segundos (padrão 3) |
| `--json` | imprime e salva o resultado em JSON |
| `--sem-relatorio` | não salva o relatório |
| `-o`, `--pasta` | pasta dos relatórios (padrão `reports`) |

### Códigos de saída

| Código | Significado |
| --- | --- |
| 0 | DNS e conexão TCP funcionaram |
| 1 | falha de DNS ou de conexão |
| 2 | entrada inválida (domínio vazio, porta fora de 1–65535, timeout ≤ 0) |

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Os testes usam simulações (mocks) e não dependem de acesso à rede. O workflow em `.github/workflows/tests.yml` os executa a cada push e pull request na `main`.

## Estrutura do projeto

```text
netcheck/
├── netcheck.py
├── tests/
│   └── test_netcheck.py
└── reports/
```

A pasta `reports/` é criada para armazenar os relatórios gerados durante os diagnósticos.

## Objetivo

Projeto de estudo voltado para diagnóstico de redes, automação de tarefas e testes automatizados, aplicando conceitos úteis para suporte técnico e infraestrutura de TI.

## Limitações

Testa uma porta TCP por execução e não executa ping ICMP, traceroute nem varredura de portas.
