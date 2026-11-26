# SDU-final

Central de Consultas - servidor do Grupo 1 (Autenticação, usuários e permissões).

## Integrantes do grupo

| Nome | RA |
|------|----|
| _preencher_ | _preencher_ |
| _preencher_ | _preencher_ |
| _preencher_ | _preencher_ |

## Como subir

```bash
pip install -r requirements.txt
python servidor.py
```

Servidor sobe em `http://localhost:8000` (outra porta: `PORTA=9000 python servidor.py`).

Abrir `index.html` (duplo clique ou `start index.html`) com servidor rodando — front de teste manual já aponta pra `http://localhost:8000`.

## Usuários de teste

Guardados só como hash SHA-256 em `USUARIOS` (`servidor.py`). Nenhuma senha em claro no repositório.

| usuario | senha   | perfil         | permissões        |
|---------|---------|----------------|--------------------|
| admin   | admin123 | administrador | basico, avancado |
| aluno   | aluno123 | usuario        | basico             |

## Rotas

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| GET | `/saude` | não | healthcheck |
| POST | `/login` | não | autentica e devolve token |
| GET | `/perfil` | token | dados do usuário logado |
| POST | `/processamento/basico` | token (`basico`) | conta primos até `n` |
| POST | `/processamento/avancado` | token (`avancado`) | conta primos até `n` |
| GET | `/consultas/cep/<cep>` | não | consulta CEP (viaCEP, fallback BrasilAPI) |
| GET | `/consultas/clima` | não | consulta clima atual (Open-Meteo) |
| GET | `/logs` | token (`avancado`) | últimas 100 linhas de log |

## Solução (autenticação e permissões)

No `POST /login` o servidor calcula o SHA-256 da senha recebida e compara com o hash guardado usando `hmac.compare_digest` (evita timing attack). Em caso de sucesso emite um token aleatório (`secrets.token_urlsafe`), guardado em memória com expiração de 1h.

O decorator `exige(permissao)` valida o token (ausente/inválido/expirado → 401) e a permissão da rota (→ 403: `aluno` não acessa `/processamento/avancado` nem `/logs`). Senha, hash e token nunca aparecem em respostas nem em logs.

`/processamento/*` limita `n` a 5.000.000 para evitar esgotamento de memória/CPU por entrada maliciosa.

## Testar

Ver `ENTREGA.md` para exemplos de `curl` de cada rota, ou usar `index.html` (front-end de teste manual, já neste repo).
