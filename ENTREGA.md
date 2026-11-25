# Entrega – Grupo 1 (Autenticação, usuários e permissões)

**Subir:** `pip install -r requirements.txt && python servidor.py` (porta 8000; outra porta: `PORTA=9000 python servidor.py`)

**Usuários de teste:** `admin` e `aluno`, guardados só como hash SHA-256 em `USUARIOS` (servidor.py). Nenhuma senha em claro no repositório.

**Solução:** no POST /login o servidor calcula o SHA-256 da senha recebida e compara com o hash guardado usando `hmac.compare_digest`. Em caso de sucesso emite um token aleatório (`secrets.token_urlsafe`) guardado em memória. O decorator `exige(permissao)` valida o token (ausente/inválido → 401) e a permissão da rota (→ 403: aluno não acessa `/processamento/avancado` nem `/logs`). Senha, hash e token não aparecem em respostas nem em logs.
