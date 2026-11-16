# Amigo Secreto SaaS

Flask + SQLAlchemy num único `app.py` + `templates/index.html` (CSS e JS dentro do próprio HTML, como no projeto de LPs). SQLite por padrão, Postgres via `DATABASE_URL`.
Cadastro aberto: qualquer usuário cria grupos e vira organizador. Super-admin em `/_admin`.

## Banco
`usuarios` · `grupos` (código de convite, status aberto/sorteado) · `participantes` (usuário↔grupo, apelido, papel) ·
`exclusoes` (casais etc.) · `sorteios` (quem presenteia quem — só o próprio participante lê a sua linha) ·
`desejos` · `mensagens` (chat anônimo por par: `g2r`/`r2g`) · `rate_hits` · `schema_info`.
Migrações: `MIGRACOES` + `adicionar_coluna()` em `app.py`; o entrypoint roda `init-db` em todo start.

## Rodar local
    python -m venv venv && . venv/bin/activate && pip install -r requirements.txt
    DEBUG=1 python app.py            # http://127.0.0.1:8000   (DATA_DIR=./data)
    # super-admin local: ADMIN_USER=admin ADMIN_PASS=senhaforte123 DEBUG=1 python app.py  -> /_admin

## Produção (VPS + Docker)
1. `cp .env.example .env`; preencha `SECRET_KEY` (64 hex) e `ADMIN_USER`.
2. `docker compose run --rm app python app.py gerar-hash` e cole `ADMIN_PASS_HASH='...'` no `.env`.
3. `docker compose up -d --build` e ponha um proxy com HTTPS na frente (Caddy/Nginx/Traefik) → porta 8000.
   Mantenha `COOKIE_SECURE=1` e `PROXY_HOPS=1`. Para Postgres, descomente o serviço `db` e defina `DATABASE_URL`.
4. Backup SQLite: `docker compose exec app python -c "import sqlite3;s=sqlite3.connect('/data/db.sqlite');d=sqlite3.connect('/data/backup.sqlite');s.backup(d)"`.
   Atualizar: `git pull && docker compose up -d --build` (o volume `/data` é preservado; nunca use `down -v`).

## Regras de negócio
- Sorteio: mínimo 3 participantes, ninguém tira a si mesmo, respeita exclusões (valida se há solução).
- Organizador só refaz o sorteio se ninguém tiver visto o resultado. Depois do sorteio ninguém entra/sai.
- Chat: dois canais por pessoa (com quem tirei / com meu amigo secreto). A API nunca devolve o autor, só `minha: true/false`.

## Segurança
CSRF em todo POST/PUT/DELETE · sessão presa à versão da senha · rate limit no banco (login, cadastro, chat, convite) ·
textos sem tags + front só com `textContent` · links só http(s) · CSP · cookies HttpOnly/SameSite/Secure · toda rota de grupo checa participação.

## Ainda não incluso (próximos passos)
Recuperação de senha e confirmação de e-mail (precisa de SMTP), notificações, cobrança/planos, PWA.
