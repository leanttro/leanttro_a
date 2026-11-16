"""Amigo Secreto SaaS — TODO o Python neste arquivo (mesmo padrão do projeto de LPs).

  Dev:   DEBUG=1 python app.py
  Prod:  gunicorn app:app
  CLI:   python app.py init-db | gerar-hash | listar-usuarios

Regra de ouro: toda consulta de dados de grupo passa por `membro_do_grupo()` (checa participação).
O resultado do sorteio só é lido pelo próprio participante; nada expõe quem escreveu no chat.
"""
import argparse
import getpass
import hmac
import os
import random
import re
import secrets
import sqlite3
import sys
import time
from datetime import date, datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, abort, g, jsonify, redirect, render_template, render_template_string, request, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event, func, inspect, select, text
from sqlalchemy.engine import Engine
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════
def _bool(nome, padrao=False):
    v = os.environ.get(nome, "").strip().lower()
    return padrao if not v else v in ("1", "true", "yes", "sim", "on")


def _int(nome, padrao):
    try:
        return int(os.environ.get(nome, "").strip() or padrao)
    except ValueError:
        return padrao


_DEBUG = _bool("DEBUG")
_DATA_DIR = os.path.abspath(os.environ.get("DATA_DIR", "/data" if not _DEBUG else "./data"))


def _db_url():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        return "sqlite:///" + os.path.join(_DATA_DIR, "db.sqlite")
    for pre in ("postgres://", "postgresql://"):
        if url.startswith(pre):
            return "postgresql+psycopg2://" + url[len(pre):]
    return url


def _secret(debug):
    k = os.environ.get("SECRET_KEY", "").strip()
    if not k:
        if debug:
            return "dev-inseguro"
        raise RuntimeError('SECRET_KEY ausente. Gere: python -c "import secrets; print(secrets.token_hex(32))"')
    if not debug and len(k) < 32:
        raise RuntimeError("SECRET_KEY fraca (mínimo 32 caracteres).")
    return k


class Config:
    DEBUG = _DEBUG
    DATA_DIR = _DATA_DIR
    SQLALCHEMY_DATABASE_URI = _db_url()
    SQLALCHEMY_ENGINE_OPTIONS = ({"connect_args": {"timeout": 15}} if _db_url().startswith("sqlite") else {"pool_pre_ping": True})
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 256 * 1024
    PROXY_HOPS = _int("PROXY_HOPS", 1)
    ADMIN_HOST = os.environ.get("ADMIN_HOST", "").strip().lower().split(":")[0]
    ADMIN_USER = os.environ.get("ADMIN_USER", "").strip()
    ADMIN_PASS_HASH = os.environ.get("ADMIN_PASS_HASH", "").strip()
    ADMIN_PASS = os.environ.get("ADMIN_PASS", "").strip()
    CADASTRO_ABERTO = _bool("CADASTRO_ABERTO", True)
    SESSION_COOKIE_NAME = "amigo_sessao"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("COOKIE_SECURE", not _DEBUG)
    PERMANENT_SESSION_LIFETIME = _int("SESSAO_HORAS", 24 * 7) * 3600
    LOGIN_RATE_MAX = _int("LOGIN_RATE_MAX", 8)
    LOGIN_RATE_JANELA = _int("LOGIN_RATE_JANELA", 600)
    CADASTRO_RATE_MAX = _int("CADASTRO_RATE_MAX", 5)
    MAX_GRUPOS_POR_USUARIO = _int("MAX_GRUPOS_POR_USUARIO", 20)
    MAX_PARTICIPANTES = _int("MAX_PARTICIPANTES", 200)


db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _pragmas(conn, _):
    if isinstance(conn, sqlite3.Connection):
        c = conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=10000")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.close()


# ═══════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════
def agora():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Usuario(db.Model):
    __tablename__ = "usuarios"
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    senha_hash = db.Column(db.String(255), nullable=False)
    sessao_versao = db.Column(db.Integer, nullable=False, default=1)   # trocar senha invalida sessões
    ativo = db.Column(db.Boolean, nullable=False, default=True)
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)
    ultimo_login = db.Column(db.DateTime)


class Grupo(db.Model):
    __tablename__ = "grupos"
    id = db.Column(db.Integer, primary_key=True)
    dono_id = db.Column(db.Integer, db.ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False, index=True)
    nome = db.Column(db.String(80), nullable=False)
    descricao = db.Column(db.String(500))
    codigo = db.Column(db.String(12), unique=True, nullable=False, index=True)   # convite
    data_evento = db.Column(db.Date)
    valor_min = db.Column(db.Integer)
    valor_max = db.Column(db.Integer)
    tema = db.Column(db.String(20), nullable=False, default="festa")
    status = db.Column(db.String(12), nullable=False, default="aberto")          # aberto | sorteado
    sorteado_em = db.Column(db.DateTime)
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)
    participantes = db.relationship("Participante", backref="grupo", cascade="all, delete-orphan", lazy="selectin")


class Participante(db.Model):
    __tablename__ = "participantes"
    __table_args__ = (db.UniqueConstraint("grupo_id", "usuario_id", name="uq_part_grupo_usuario"),)
    id = db.Column(db.Integer, primary_key=True)
    grupo_id = db.Column(db.Integer, db.ForeignKey("grupos.id", ondelete="CASCADE"), nullable=False, index=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False, index=True)
    apelido = db.Column(db.String(40), nullable=False)
    papel = db.Column(db.String(12), nullable=False, default="membro")          # organizador | membro
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)
    usuario = db.relationship("Usuario", lazy="joined")


class Exclusao(db.Model):
    """Par que NÃO pode se tirar (ex.: casal). Guardado uma vez; tratado como simétrico."""
    __tablename__ = "exclusoes"
    __table_args__ = (db.UniqueConstraint("grupo_id", "a_id", "b_id", name="uq_excl"),)
    id = db.Column(db.Integer, primary_key=True)
    grupo_id = db.Column(db.Integer, db.ForeignKey("grupos.id", ondelete="CASCADE"), nullable=False, index=True)
    a_id = db.Column(db.Integer, db.ForeignKey("participantes.id", ondelete="CASCADE"), nullable=False)
    b_id = db.Column(db.Integer, db.ForeignKey("participantes.id", ondelete="CASCADE"), nullable=False)


class Sorteio(db.Model):
    """Quem presenteia quem. Tabela sensível: só o próprio participante lê a sua linha."""
    __tablename__ = "sorteios"
    __table_args__ = (db.UniqueConstraint("grupo_id", "presenteador_id", name="uq_sorteio_presenteador"),
                      db.UniqueConstraint("grupo_id", "presenteado_id", name="uq_sorteio_presenteado"))
    id = db.Column(db.Integer, primary_key=True)
    grupo_id = db.Column(db.Integer, db.ForeignKey("grupos.id", ondelete="CASCADE"), nullable=False, index=True)
    presenteador_id = db.Column(db.Integer, db.ForeignKey("participantes.id", ondelete="CASCADE"), nullable=False)
    presenteado_id = db.Column(db.Integer, db.ForeignKey("participantes.id", ondelete="CASCADE"), nullable=False)
    revelado_em = db.Column(db.DateTime)


class Desejo(db.Model):
    __tablename__ = "desejos"
    id = db.Column(db.Integer, primary_key=True)
    grupo_id = db.Column(db.Integer, db.ForeignKey("grupos.id", ondelete="CASCADE"), nullable=False, index=True)
    participante_id = db.Column(db.Integer, db.ForeignKey("participantes.id", ondelete="CASCADE"), nullable=False)
    link = db.Column(db.String(500))
    observacao = db.Column(db.String(500))
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)
    participante = db.relationship("Participante", lazy="joined")


class Mensagem(db.Model):
    """Chat anônimo por par. sentido: 'g2r' (presenteador→presenteado) ou 'r2g' (o inverso)."""
    __tablename__ = "mensagens"
    __table_args__ = (db.Index("ix_msg_sorteio", "sorteio_id", "id"),)
    id = db.Column(db.Integer, primary_key=True)
    sorteio_id = db.Column(db.Integer, db.ForeignKey("sorteios.id", ondelete="CASCADE"), nullable=False)
    sentido = db.Column(db.String(3), nullable=False)
    texto = db.Column(db.String(1000), nullable=False)
    criado_em = db.Column(db.DateTime, nullable=False, default=agora)


class RateHit(db.Model):
    __tablename__ = "rate_hits"
    __table_args__ = (db.Index("ix_rate_chave_ts", "chave", "ts"),)
    id = db.Column(db.Integer, primary_key=True)
    chave = db.Column(db.String(120), nullable=False)
    ts = db.Column(db.Float, nullable=False)


class SchemaInfo(db.Model):
    __tablename__ = "schema_info"
    id = db.Column(db.Integer, primary_key=True)
    versao = db.Column(db.Integer, nullable=False, default=1)


# Migrações futuras: def _v2(): adicionar_coluna("grupos", "x", "VARCHAR(20)")  →  MIGRACOES = [(2, _v2)]
def adicionar_coluna(tabela, coluna, ddl):
    if coluna not in {c["name"] for c in inspect(db.engine).get_columns(tabela)}:
        db.session.execute(text(f"ALTER TABLE {tabela} ADD COLUMN {coluna} {ddl}"))
        db.session.commit()


MIGRACOES = []


def iniciar_banco(app):
    with app.app_context():
        os.makedirs(app.config["DATA_DIR"], exist_ok=True)
        db.create_all()
        info = db.session.get(SchemaInfo, 1)
        if info is None:
            info = SchemaInfo(id=1, versao=1)
            db.session.add(info)
            db.session.commit()
        for versao, fn in MIGRACOES:
            if versao > info.versao:
                fn()
                info.versao = versao
                db.session.commit()
        return info.versao


# ═══════════════════════════════════════════════════════════════════════════
# UTILS
# ═══════════════════════════════════════════════════════════════════════════
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
TEMAS = ("festa", "natal", "aniversario", "confra")


def limpar(txt, limite=500):
    txt = re.sub(r"<[^>]*>", "", str(txt or ""))
    txt = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", txt).strip()
    return txt[:limite]


def url_https(v):
    v = (v or "").strip()
    if not v:
        return None
    p = urlparse(v)
    if p.scheme not in ("http", "https") or not p.netloc or len(v) > 500:
        raise Erro("Link inválido (use http:// ou https://).")
    return v


def parse_int(v, minimo=0, maximo=1_000_000):
    if v in (None, ""):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise Erro("Valor numérico inválido.")
    if not minimo <= n <= maximo:
        raise Erro("Valor fora do intervalo permitido.")
    return n


def parse_data(v):
    if not v:
        return None
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        raise Erro("Data inválida.")


def gerar_codigo():
    alfabeto = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        c = "".join(secrets.choice(alfabeto) for _ in range(7))
        if not db.session.scalar(select(Grupo.id).where(Grupo.codigo == c)):
            return c


def permitir(chave, maximo, janela):
    """Rate limit no banco (vale entre workers). True = pode seguir."""
    agora_ts = time.time()
    n = db.session.scalar(select(func.count(RateHit.id)).where(RateHit.chave == chave, RateHit.ts > agora_ts - janela))
    if n >= maximo:
        return False
    db.session.add(RateHit(chave=chave, ts=agora_ts))
    if random.random() < 0.02:
        db.session.execute(text("DELETE FROM rate_hits WHERE ts < :t"), {"t": agora_ts - 86400})
    db.session.commit()
    return True


class Erro(ValueError):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def exigir_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    enviado = request.headers.get("X-CSRF") or request.form.get("csrf") or ""
    if not enviado or not hmac.compare_digest(enviado, session.get("csrf", "")):
        abort(400)


def sortear(ids, proibidos):
    """Sorteio sem auto-tirada, respeitando exclusões. Retorna {presenteador: presenteado} ou None."""
    if len(ids) < 3:
        return None
    for _ in range(5000):
        alvo = ids[:]
        random.SystemRandom().shuffle(alvo)
        if all(a != b and (a, b) not in proibidos for a, b in zip(ids, alvo)):
            return dict(zip(ids, alvo))
    return None


# ═══════════════════════════════════════════════════════════════════════════
# API (usuário)
# ═══════════════════════════════════════════════════════════════════════════
from flask import Blueprint  # noqa: E402

api = Blueprint("api", __name__, url_prefix="/api")
ABERTAS = {"api.me", "api.login", "api.cadastro"}


@api.errorhandler(Erro)
def _erro(e):
    return jsonify(ok=False, erro=str(e)), e.status


@api.before_request
def _antes():
    exigir_csrf()
    g.u = None
    uid = session.get("uid")
    if uid:
        u = db.session.get(Usuario, uid)
        if u and u.ativo and session.get("v") == u.sessao_versao:
            g.u = u
        else:
            session.pop("uid", None)
    if request.endpoint not in ABERTAS and g.u is None:
        return jsonify(ok=False, erro="Faça login."), 401


def membro_do_grupo(gid):
    p = db.session.scalar(select(Participante).where(Participante.grupo_id == gid, Participante.usuario_id == g.u.id))
    if not p:
        raise Erro("Grupo não encontrado.", 404)
    return p, p.grupo


def so_organizador(p):
    if p.papel != "organizador":
        raise Erro("Só o organizador pode fazer isso.", 403)


def j_grupo(gr, p):
    return {"id": gr.id, "nome": gr.nome, "descricao": gr.descricao, "tema": gr.tema, "status": gr.status,
            "data_evento": gr.data_evento.isoformat() if gr.data_evento else None,
            "valor_min": gr.valor_min, "valor_max": gr.valor_max,
            "codigo": gr.codigo if p.papel == "organizador" else None,
            "papel": p.papel, "meu_participante": p.id, "total": len(gr.participantes)}


@api.get("/me")
def me():
    u = g.u
    return jsonify(ok=True, csrf=csrf_token(), usuario={"id": u.id, "nome": u.nome, "email": u.email} if u else None,
                   cadastro_aberto=Config.CADASTRO_ABERTO)


@api.post("/cadastro")
def cadastro():
    if not Config.CADASTRO_ABERTO:
        raise Erro("Cadastros fechados.", 403)
    d = request.get_json(silent=True) or {}
    nome, email, senha = limpar(d.get("nome"), 80), limpar(d.get("email"), 254).lower(), str(d.get("senha") or "")
    if not nome or not EMAIL_RE.match(email):
        raise Erro("Informe nome e um e-mail válido.")
    if len(senha) < 8 or len(senha) > 128:
        raise Erro("A senha precisa ter de 8 a 128 caracteres.")
    if not permitir(f"cad:{request.remote_addr}", Config.CADASTRO_RATE_MAX, 3600):
        raise Erro("Muitas tentativas. Aguarde.", 429)
    if db.session.scalar(select(Usuario.id).where(Usuario.email == email)):
        raise Erro("Esse e-mail já está cadastrado.", 409)
    u = Usuario(nome=nome, email=email, senha_hash=generate_password_hash(senha), ultimo_login=agora())
    db.session.add(u)
    db.session.commit()
    session.clear()
    session.permanent = True
    session.update(uid=u.id, v=u.sessao_versao, csrf=secrets.token_urlsafe(32))
    return jsonify(ok=True, csrf=session["csrf"], usuario={"id": u.id, "nome": u.nome, "email": u.email})


@api.post("/login")
def login():
    d = request.get_json(silent=True) or {}
    email, senha = limpar(d.get("email"), 254).lower(), str(d.get("senha") or "")
    if not permitir(f"login:{request.remote_addr}", Config.LOGIN_RATE_MAX, Config.LOGIN_RATE_JANELA):
        raise Erro("Muitas tentativas. Aguarde alguns minutos.", 429)
    u = db.session.scalar(select(Usuario).where(Usuario.email == email))
    if not u or not u.ativo or not check_password_hash(u.senha_hash, senha):
        raise Erro("E-mail ou senha incorretos.", 401)
    u.ultimo_login = agora()
    db.session.commit()
    session.clear()
    session.permanent = True
    session.update(uid=u.id, v=u.sessao_versao, csrf=secrets.token_urlsafe(32))
    return jsonify(ok=True, csrf=session["csrf"], usuario={"id": u.id, "nome": u.nome, "email": u.email})


@api.post("/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@api.post("/senha")
def trocar_senha():
    d = request.get_json(silent=True) or {}
    if not check_password_hash(g.u.senha_hash, str(d.get("atual") or "")):
        raise Erro("Senha atual incorreta.", 401)
    nova = str(d.get("nova") or "")
    if len(nova) < 8 or len(nova) > 128:
        raise Erro("A nova senha precisa ter de 8 a 128 caracteres.")
    g.u.senha_hash = generate_password_hash(nova)
    g.u.sessao_versao += 1
    db.session.commit()
    session["v"] = g.u.sessao_versao
    return jsonify(ok=True)


@api.post("/conta/excluir")                        # LGPD: apaga conta e tudo que depende dela
def excluir_conta():
    d = request.get_json(silent=True) or {}
    if not check_password_hash(g.u.senha_hash, str(d.get("senha") or "")):
        raise Erro("Senha incorreta.", 401)
    if db.session.scalar(select(func.count(Grupo.id)).where(Grupo.dono_id == g.u.id, Grupo.status == "sorteado")):
        raise Erro("Você é dono de grupo já sorteado. Peça ao suporte para excluir.", 409)
    db.session.delete(g.u)
    db.session.commit()
    session.clear()
    return jsonify(ok=True)


# ── Grupos ────────────────────────────────────────────────────────────────
@api.get("/grupos")
def grupos_lista():
    ps = db.session.scalars(select(Participante).where(Participante.usuario_id == g.u.id).order_by(Participante.id.desc())).all()
    return jsonify(ok=True, grupos=[j_grupo(p.grupo, p) for p in ps])


def _campos_grupo(d, gr):
    nome = limpar(d.get("nome"), 80)
    if not nome:
        raise Erro("Dê um nome ao grupo.")
    gr.nome = nome
    gr.descricao = limpar(d.get("descricao"), 500) or None
    gr.data_evento = parse_data(d.get("data_evento"))
    gr.valor_min = parse_int(d.get("valor_min"))
    gr.valor_max = parse_int(d.get("valor_max"))
    if gr.valor_min is not None and gr.valor_max is not None and gr.valor_min > gr.valor_max:
        raise Erro("O valor mínimo não pode ser maior que o máximo.")
    tema = d.get("tema") or "festa"
    gr.tema = tema if tema in TEMAS else "festa"


@api.post("/grupos")
def grupo_criar():
    d = request.get_json(silent=True) or {}
    n = db.session.scalar(select(func.count(Grupo.id)).where(Grupo.dono_id == g.u.id))
    if n >= Config.MAX_GRUPOS_POR_USUARIO:
        raise Erro("Limite de grupos atingido.", 429)
    gr = Grupo(dono_id=g.u.id, codigo=gerar_codigo())
    _campos_grupo(d, gr)
    apelido = limpar(d.get("apelido"), 40) or g.u.nome.split(" ")[0]
    gr.participantes.append(Participante(usuario_id=g.u.id, apelido=apelido, papel="organizador"))
    db.session.add(gr)
    db.session.commit()
    p = gr.participantes[0]
    return jsonify(ok=True, grupo=j_grupo(gr, p))


@api.post("/entrar")
def grupo_entrar():
    d = request.get_json(silent=True) or {}
    if not permitir(f"join:{g.u.id}", 15, 600):
        raise Erro("Muitas tentativas. Aguarde.", 429)
    gr = db.session.scalar(select(Grupo).where(Grupo.codigo == limpar(d.get("codigo"), 12).upper()))
    if not gr:
        raise Erro("Código de convite inválido.", 404)
    existente = db.session.scalar(select(Participante).where(Participante.grupo_id == gr.id, Participante.usuario_id == g.u.id))
    if existente:
        return jsonify(ok=True, grupo=j_grupo(gr, existente))
    if gr.status != "aberto":
        raise Erro("Esse grupo já foi sorteado e não aceita novos participantes.", 409)
    if len(gr.participantes) >= Config.MAX_PARTICIPANTES:
        raise Erro("Grupo lotado.", 409)
    apelido = limpar(d.get("apelido"), 40) or g.u.nome.split(" ")[0]
    if any(x.apelido.lower() == apelido.lower() for x in gr.participantes):
        raise Erro("Já existe alguém com esse apelido no grupo. Escolha outro.", 409)
    p = Participante(grupo_id=gr.id, usuario_id=g.u.id, apelido=apelido)
    db.session.add(p)
    db.session.commit()
    return jsonify(ok=True, grupo=j_grupo(gr, p))


@api.get("/grupos/<int:gid>")
def grupo_ver(gid):
    p, gr = membro_do_grupo(gid)
    ex = db.session.scalars(select(Exclusao).where(Exclusao.grupo_id == gid)).all() if p.papel == "organizador" else []
    return jsonify(ok=True, grupo=j_grupo(gr, p),
                   participantes=[{"id": x.id, "apelido": x.apelido, "papel": x.papel} for x in gr.participantes],
                   exclusoes=[{"id": e.id, "a": e.a_id, "b": e.b_id} for e in ex])


@api.put("/grupos/<int:gid>")
def grupo_editar(gid):
    p, gr = membro_do_grupo(gid)
    so_organizador(p)
    _campos_grupo(request.get_json(silent=True) or {}, gr)
    db.session.commit()
    return jsonify(ok=True, grupo=j_grupo(gr, p))


@api.delete("/grupos/<int:gid>")
def grupo_excluir(gid):
    p, gr = membro_do_grupo(gid)
    so_organizador(p)
    db.session.delete(gr)
    db.session.commit()
    return jsonify(ok=True)


@api.delete("/grupos/<int:gid>/participantes/<int:pid>")
def participante_remover(gid, pid):
    p, gr = membro_do_grupo(gid)
    alvo = next((x for x in gr.participantes if x.id == pid), None)
    if not alvo:
        raise Erro("Participante não encontrado.", 404)
    if alvo.id != p.id:
        so_organizador(p)
    if gr.status != "aberto":
        raise Erro("Depois do sorteio ninguém pode sair. Peça ao organizador para refazer.", 409)
    if alvo.papel == "organizador":
        raise Erro("O organizador não pode sair; exclua o grupo.", 409)
    db.session.delete(alvo)
    db.session.commit()
    return jsonify(ok=True)


@api.post("/grupos/<int:gid>/exclusoes")
def exclusao_criar(gid):
    p, gr = membro_do_grupo(gid)
    so_organizador(p)
    if gr.status != "aberto":
        raise Erro("Já sorteado.", 409)
    d = request.get_json(silent=True) or {}
    ids = {x.id for x in gr.participantes}
    try:
        a, b = int(d.get("a")), int(d.get("b"))
    except (TypeError, ValueError):
        raise Erro("Par inválido.")
    if a == b or a not in ids or b not in ids:
        raise Erro("Par inválido.")
    a, b = min(a, b), max(a, b)
    if not db.session.scalar(select(Exclusao.id).where(Exclusao.grupo_id == gid, Exclusao.a_id == a, Exclusao.b_id == b)):
        db.session.add(Exclusao(grupo_id=gid, a_id=a, b_id=b))
        db.session.commit()
    return jsonify(ok=True)


@api.delete("/grupos/<int:gid>/exclusoes/<int:eid>")
def exclusao_remover(gid, eid):
    p, gr = membro_do_grupo(gid)
    so_organizador(p)
    e = db.session.scalar(select(Exclusao).where(Exclusao.id == eid, Exclusao.grupo_id == gid))
    if e:
        db.session.delete(e)
        db.session.commit()
    return jsonify(ok=True)


@api.post("/grupos/<int:gid>/sortear")
def grupo_sortear(gid):
    p, gr = membro_do_grupo(gid)
    so_organizador(p)
    if gr.status != "aberto":
        raise Erro("Esse grupo já foi sorteado.", 409)
    ids = [x.id for x in gr.participantes]
    proibidos = set()
    for e in db.session.scalars(select(Exclusao).where(Exclusao.grupo_id == gid)):
        proibidos |= {(e.a_id, e.b_id), (e.b_id, e.a_id)}
    res = sortear(ids, proibidos)
    if res is None:
        raise Erro("Não foi possível sortear: precisa de 3+ participantes e exclusões que deixem alguma combinação possível.")
    for a, b in res.items():
        db.session.add(Sorteio(grupo_id=gid, presenteador_id=a, presenteado_id=b))
    gr.status, gr.sorteado_em = "sorteado", agora()
    db.session.commit()
    return jsonify(ok=True, grupo=j_grupo(gr, p))


@api.post("/grupos/<int:gid>/refazer")
def grupo_refazer(gid):
    """Só se ninguém tiver revelado ainda."""
    p, gr = membro_do_grupo(gid)
    so_organizador(p)
    if gr.status != "sorteado":
        raise Erro("O grupo ainda não foi sorteado.", 409)
    if db.session.scalar(select(func.count(Sorteio.id)).where(Sorteio.grupo_id == gid, Sorteio.revelado_em.isnot(None))):
        raise Erro("Alguém já viu o resultado; não dá mais para refazer.", 409)
    db.session.execute(text("DELETE FROM sorteios WHERE grupo_id = :g"), {"g": gid})
    gr.status, gr.sorteado_em = "aberto", None
    db.session.commit()
    return jsonify(ok=True, grupo=j_grupo(gr, p))


@api.get("/grupos/<int:gid>/meu-amigo")
def meu_amigo(gid):
    p, gr = membro_do_grupo(gid)
    if gr.status != "sorteado":
        return jsonify(ok=True, sorteado=False)
    s = db.session.scalar(select(Sorteio).where(Sorteio.grupo_id == gid, Sorteio.presenteador_id == p.id))
    if not s:
        return jsonify(ok=True, sorteado=False)
    if not s.revelado_em:
        s.revelado_em = agora()
        db.session.commit()
    alvo = db.session.get(Participante, s.presenteado_id)
    desejos = db.session.scalars(select(Desejo).where(Desejo.participante_id == alvo.id).order_by(Desejo.id.desc())).all()
    return jsonify(ok=True, sorteado=True, nome=alvo.apelido,
                   desejos=[{"link": d.link, "observacao": d.observacao} for d in desejos])


@api.get("/grupos/<int:gid>/status-revelacao")      # organizador vê quem já olhou (sem ver o par)
def status_revelacao(gid):
    p, gr = membro_do_grupo(gid)
    so_organizador(p)
    vistos = {s.presenteador_id for s in db.session.scalars(select(Sorteio).where(Sorteio.grupo_id == gid, Sorteio.revelado_em.isnot(None)))}
    return jsonify(ok=True, participantes=[{"apelido": x.apelido, "viu": x.id in vistos} for x in gr.participantes])


# ── Desejos ───────────────────────────────────────────────────────────────
@api.get("/grupos/<int:gid>/desejos")
def desejos_lista(gid):
    p, _ = membro_do_grupo(gid)
    ds = db.session.scalars(select(Desejo).where(Desejo.grupo_id == gid).order_by(Desejo.id.desc()).limit(300)).all()
    return jsonify(ok=True, desejos=[{"id": d.id, "dono": d.participante.apelido, "meu": d.participante_id == p.id,
                                      "link": d.link, "observacao": d.observacao} for d in ds])


@api.post("/grupos/<int:gid>/desejos")
def desejo_criar(gid):
    p, _ = membro_do_grupo(gid)
    d = request.get_json(silent=True) or {}
    link, obs = url_https(d.get("link")), limpar(d.get("observacao"), 500)
    if not link and not obs:
        raise Erro("Informe um link ou uma descrição.")
    if db.session.scalar(select(func.count(Desejo.id)).where(Desejo.participante_id == p.id)) >= 30:
        raise Erro("Limite de 30 desejos.", 429)
    db.session.add(Desejo(grupo_id=gid, participante_id=p.id, link=link, observacao=obs or None))
    db.session.commit()
    return jsonify(ok=True)


@api.delete("/grupos/<int:gid>/desejos/<int:did>")
def desejo_excluir(gid, did):
    p, _ = membro_do_grupo(gid)
    d = db.session.scalar(select(Desejo).where(Desejo.id == did, Desejo.grupo_id == gid, Desejo.participante_id == p.id))
    if d:
        db.session.delete(d)
        db.session.commit()
    return jsonify(ok=True)


# ── Chat anônimo por par ──────────────────────────────────────────────────
def _canal(gid, canal):
    """canal 'para_meu_amigo': eu sou o presenteador. 'do_meu_amigo': eu sou o presenteado."""
    p, gr = membro_do_grupo(gid)
    if gr.status != "sorteado":
        raise Erro("O sorteio ainda não aconteceu.", 409)
    if canal == "para_meu_amigo":
        s = db.session.scalar(select(Sorteio).where(Sorteio.grupo_id == gid, Sorteio.presenteador_id == p.id))
        meu = "g2r"
    elif canal == "do_meu_amigo":
        s = db.session.scalar(select(Sorteio).where(Sorteio.grupo_id == gid, Sorteio.presenteado_id == p.id))
        meu = "r2g"
    else:
        raise Erro("Canal inválido.", 404)
    if not s:
        raise Erro("Sorteio não encontrado.", 404)
    return s, meu


@api.get("/grupos/<int:gid>/chat/<canal>")
def chat_ler(gid, canal):
    s, meu = _canal(gid, canal)
    ms = db.session.scalars(select(Mensagem).where(Mensagem.sorteio_id == s.id).order_by(Mensagem.id.desc()).limit(100)).all()[::-1]
    return jsonify(ok=True, mensagens=[{"texto": m.texto, "minha": m.sentido == meu, "em": m.criado_em.isoformat() + "Z"} for m in ms])


@api.post("/grupos/<int:gid>/chat/<canal>")
def chat_enviar(gid, canal):
    s, meu = _canal(gid, canal)
    texto = limpar((request.get_json(silent=True) or {}).get("texto"), 1000)
    if not texto:
        raise Erro("Mensagem vazia.")
    if not permitir(f"chat:{g.u.id}", 30, 300):
        raise Erro("Devagar! Aguarde um pouco.", 429)
    db.session.add(Mensagem(sorteio_id=s.id, sentido=meu, texto=texto))
    db.session.commit()
    return jsonify(ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# SUPER-ADMIN  (/_admin)
# ═══════════════════════════════════════════════════════════════════════════
adm = Blueprint("adm", __name__, url_prefix="/_admin")

_BASE = """<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin</title><style>
body{font-family:system-ui,sans-serif;background:#0f0c29;color:#eee;margin:0;padding:24px}
a{color:#f89b29}table{width:100%;border-collapse:collapse;margin:12px 0 32px}th,td{padding:8px 10px;border-bottom:1px solid #ffffff22;text-align:left;font-size:14px}
.cards{display:flex;gap:12px;flex-wrap:wrap}.c{background:#ffffff14;padding:16px 22px;border-radius:14px}.c b{font-size:28px;display:block}
button,input{padding:8px 12px;border-radius:8px;border:0;font-size:14px}button{background:#ff0f7b;color:#fff;cursor:pointer}
.off{opacity:.5}form{display:inline}</style><body>{% block b %}{% endblock %}</body></html>"""

_LOGIN = _BASE.replace("{% block b %}{% endblock %}", """
<h2>Super-admin</h2>{% if erro %}<p style="color:#ff6b6b">{{erro}}</p>{% endif %}
<form method="post"><input type="hidden" name="csrf" value="{{csrf}}">
<p><input name="usuario" placeholder="usuário" autocomplete="username"></p>
<p><input name="senha" type="password" placeholder="senha" autocomplete="current-password"></p><button>Entrar</button></form>""")

_PAINEL = _BASE.replace("{% block b %}{% endblock %}", """
<h2>Amigo Secreto — Super-admin</h2>
<form method="post" action="/_admin/sair"><input type="hidden" name="csrf" value="{{csrf}}"><button>Sair</button></form>
<div class="cards">{% for k,v in stats %}<div class="c"><b>{{v}}</b>{{k}}</div>{% endfor %}</div>
<h3>Usuários (últimos 200)</h3><table><tr><th>ID</th><th>Nome</th><th>E-mail</th><th>Criado</th><th>Último login</th><th>Grupos</th><th></th></tr>
{% for u,n in usuarios %}<tr class="{{'off' if not u.ativo}}"><td>{{u.id}}</td><td>{{u.nome}}</td><td>{{u.email}}</td><td>{{u.criado_em.strftime('%d/%m/%Y')}}</td>
<td>{{u.ultimo_login.strftime('%d/%m/%Y %H:%M') if u.ultimo_login else '-'}}</td><td>{{n}}</td>
<td><form method="post" action="/_admin/usuarios/{{u.id}}/alternar"><input type="hidden" name="csrf" value="{{csrf}}"><button>{{'Suspender' if u.ativo else 'Reativar'}}</button></form>
<form method="post" action="/_admin/usuarios/{{u.id}}/senha"><input type="hidden" name="csrf" value="{{csrf}}"><button>Resetar senha</button></form></td></tr>{% endfor %}</table>
<h3>Grupos (últimos 200)</h3><table><tr><th>ID</th><th>Nome</th><th>Dono</th><th>Status</th><th>Particip.</th><th>Evento</th><th></th></tr>
{% for gr in grupos %}<tr><td>{{gr.id}}</td><td>{{gr.nome}}</td><td>{{gr.dono_id}}</td><td>{{gr.status}}</td><td>{{gr.participantes|length}}</td>
<td>{{gr.data_evento or '-'}}</td><td><form method="post" action="/_admin/grupos/{{gr.id}}/excluir"><input type="hidden" name="csrf" value="{{csrf}}"><button>Excluir</button></form></td></tr>{% endfor %}</table>
{% if nova %}<p style="background:#fff;color:#000;padding:12px;border-radius:8px">Nova senha: <b>{{nova}}</b> (anote; não será mostrada de novo)</p>{% endif %}""")


def _admin_ok(usuario, senha):
    c = Config
    if not c.ADMIN_USER or not (c.ADMIN_PASS_HASH or c.ADMIN_PASS):
        return False
    ok_u = hmac.compare_digest(usuario, c.ADMIN_USER)
    ok_s = check_password_hash(c.ADMIN_PASS_HASH, senha) if c.ADMIN_PASS_HASH else hmac.compare_digest(senha, c.ADMIN_PASS)
    return ok_u and ok_s


@adm.before_request
def _antes_adm():
    if Config.ADMIN_HOST and request.host.split(":")[0].lower() != Config.ADMIN_HOST:
        abort(404)
    exigir_csrf()
    if request.endpoint not in ("adm.login",) and not session.get("sa"):
        return redirect("/_admin/login")


@adm.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    if request.method == "POST":
        if not permitir(f"adm:{request.remote_addr}", 6, 600):
            abort(429)
        if _admin_ok(request.form.get("usuario", ""), request.form.get("senha", "")):
            session.clear()
            session.update(sa=True, csrf=secrets.token_urlsafe(32))
            return redirect("/_admin/")
        erro = "Credenciais inválidas."
    return render_template_string(_LOGIN, erro=erro, csrf=csrf_token())


@adm.post("/sair")
def sair():
    session.clear()
    return redirect("/_admin/login")


def _painel(nova=None):
    stats = [("usuários", db.session.scalar(select(func.count(Usuario.id)))),
             ("grupos", db.session.scalar(select(func.count(Grupo.id)))),
             ("grupos sorteados", db.session.scalar(select(func.count(Grupo.id)).where(Grupo.status == "sorteado"))),
             ("participações", db.session.scalar(select(func.count(Participante.id)))),
             ("mensagens", db.session.scalar(select(func.count(Mensagem.id)))),
             ("desejos", db.session.scalar(select(func.count(Desejo.id))))]
    us = db.session.scalars(select(Usuario).order_by(Usuario.id.desc()).limit(200)).all()
    cont = dict(db.session.execute(select(Participante.usuario_id, func.count(Participante.id)).group_by(Participante.usuario_id)).all())
    grs = db.session.scalars(select(Grupo).order_by(Grupo.id.desc()).limit(200)).all()
    return render_template_string(_PAINEL, stats=stats, usuarios=[(u, cont.get(u.id, 0)) for u in us],
                                  grupos=grs, csrf=csrf_token(), nova=nova)


@adm.get("/")
def painel():
    return _painel()


@adm.post("/usuarios/<int:uid>/alternar")
def alternar(uid):
    u = db.get_or_404(Usuario, uid)
    u.ativo = not u.ativo
    u.sessao_versao += 1
    db.session.commit()
    return redirect("/_admin/")


@adm.post("/usuarios/<int:uid>/senha")
def resetar(uid):
    u = db.get_or_404(Usuario, uid)
    nova = secrets.token_urlsafe(9)
    u.senha_hash = generate_password_hash(nova)
    u.sessao_versao += 1
    db.session.commit()
    return _painel(nova=nova)


@adm.post("/grupos/<int:gid>/excluir")
def excluir_grupo(gid):
    db.session.delete(db.get_or_404(Grupo, gid))
    db.session.commit()
    return redirect("/_admin/")


# ═══════════════════════════════════════════════════════════════════════════
# APP FACTORY
# ═══════════════════════════════════════════════════════════════════════════
def create_app(config=None):
    app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=None)
    app.config.from_object(Config)
    app.config["SECRET_KEY"] = _secret(_DEBUG)
    if config:
        app.config.update(config)
    if Config.PROXY_HOPS > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=Config.PROXY_HOPS, x_proto=Config.PROXY_HOPS, x_host=Config.PROXY_HOPS)
    db.init_app(app)
    app.register_blueprint(api)
    app.register_blueprint(adm)

    @app.before_request
    def _nonce():
        g.nonce = secrets.token_urlsafe(16)

    @app.get("/")
    def home():
        return render_template("index.html", nonce=g.nonce)

    @app.get("/og-image.png")                      # imagem de prévia do link (WhatsApp, Instagram, etc.)
    def og_image():
        r = send_from_directory(BASE_DIR / "static", "og-image.png", mimetype="image/png")
        r.headers["Cache-Control"] = "public, max-age=86400"
        return r

    @app.get("/healthz")
    def healthz():
        db.session.execute(text("SELECT 1"))
        return "ok"

    @app.after_request
    def _seg(r):
        r.headers.setdefault("X-Content-Type-Options", "nosniff")
        r.headers.setdefault("X-Frame-Options", "DENY")
        r.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        r.headers.setdefault("Content-Security-Policy",
                             f"default-src 'self'; script-src 'nonce-{g.get('nonce', '')}' https://cdn.jsdelivr.net; "
                             "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        if request.path.startswith(("/api", "/_admin")):
            r.headers["Cache-Control"] = "no-store"
        return r

    @app.errorhandler(404)
    def _404(e):
        return (jsonify(ok=False, erro="Não encontrado."), 404) if request.path.startswith("/api") else ("Página não encontrada.", 404)

    @app.errorhandler(400)
    def _400(e):
        return (jsonify(ok=False, erro="Sessão expirada. Recarregue a página."), 400) if request.path.startswith("/api") else ("Requisição inválida.", 400)

    @app.errorhandler(429)
    def _429(e):
        return jsonify(ok=False, erro="Muitas tentativas. Aguarde."), 429

    return app


app = create_app()


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description="Amigo Secreto SaaS")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run")
    sub.add_parser("init-db")
    sub.add_parser("gerar-hash")
    sub.add_parser("listar-usuarios")
    a = ap.parse_args()
    if a.cmd == "gerar-hash":
        s = getpass.getpass("Senha do super-admin: ")
        if len(s) < 10:
            sys.exit("Use pelo menos 10 caracteres.")
        if s != getpass.getpass("Repita: "):
            sys.exit("Não conferem.")
        print(f"\nADMIN_PASS_HASH='{generate_password_hash(s)}'")
        return
    v = iniciar_banco(app)
    if a.cmd == "init-db":
        print(f"Banco pronto (schema v{v}).")
    elif a.cmd == "listar-usuarios":
        with app.app_context():
            for u in db.session.scalars(select(Usuario)):
                print(u.id, u.email, "ativo" if u.ativo else "SUSPENSO")
    else:
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=_int("PORT", 8000), debug=_DEBUG)


if __name__ == "__main__":
    main()
