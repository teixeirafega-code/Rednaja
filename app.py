from flask import Flask, request, render_template, send_file, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd
import pdfplumber

try:
    import camelot
except Exception:
    camelot = None

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import os
import datetime
import warnings
import urllib.parse
import sqlite3
import xml.etree.ElementTree as ET
import json
import logging
import re
import threading

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-me")
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "16")) * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {".pdf", ".csv", ".xlsx", ".ofx", ".json"}
ALLOWED_VENDAS_EXTENSIONS = {".pdf", ".csv", ".xlsx", ".json"}
ALLOWED_EXTRATO_EXTENSIONS = {".pdf", ".csv", ".xlsx", ".ofx", ".json"}


def format_br(valor):
    try:
        return f"{valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return "0,00"


def formato_br(valor):
    return f"R$ {format_br(valor)}"


app.jinja_env.filters["format_br"] = format_br

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# SQLite
DB_PATH = os.getenv("DATABASE_PATH", "meis.db")
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row
DB_LOCK = threading.Lock()


def db_execute(query, params=(), commit=False):
    with DB_LOCK:
        cur = conn.execute(query, params)
        if commit:
            conn.commit()
        return cur


def db_fetchone(query, params=()):
    with DB_LOCK:
        cur = conn.execute(query, params)
        return cur.fetchone()


def db_fetchall(query, params=()):
    with DB_LOCK:
        cur = conn.execute(query, params)
        return cur.fetchall()


def initialize_db():
    with DB_LOCK:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, is_pro INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS conciliacoes
                (id INTEGER PRIMARY KEY, user_id INTEGER, data TEXT, total_extrato REAL, total_vendas REAL, divergencia REAL);
            CREATE TABLE IF NOT EXISTS sales
                (id INTEGER PRIMARY KEY, user_id INTEGER, data TEXT, descricao TEXT, metodo_pagamento TEXT, parcelado INTEGER, parcelas INTEGER,
                valor_bruto REAL, taxa_percentual REAL, taxa_fixa REAL, valor_liquido REAL, status TEXT, created_at TEXT);
            """
        )
        conn.commit()


initialize_db()


class User(UserMixin):
    def __init__(self, id, email, is_pro):
        self.id = id
        self.email = email
        self.is_pro = is_pro


@login_manager.user_loader
def load_user(user_id):
    row = db_fetchone("SELECT id, email, is_pro FROM users WHERE id = ?", (user_id,))
    if row:
        return User(row[0], row[1], row[2])
    return None


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Entrar")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Senha", validators=[DataRequired()])
    confirm_password = PasswordField("Confirmar Senha", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Cadastrar")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = generate_password_hash(form.password.data)
        try:
            db_execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password), commit=True)

            row = db_fetchone("SELECT id, password, is_pro FROM users WHERE email = ?", (email,))
            if row:
                user = User(row[0], email, row[2])
                login_user(user)
                flash("Cadastro realizado e voce ja esta logado!", "success")
                return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("Email ja cadastrado.", "danger")
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        row = db_fetchone("SELECT id, password, is_pro FROM users WHERE email = ?", (email,))
        if row and check_password_hash(row[1], form.password.data):
            user = User(row[0], email, row[2])
            login_user(user)
            flash("Login feito!", "success")
            return redirect(url_for("dashboard"))
        flash("Email ou senha invalidos.", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Saiu da conta.", "info")
    return redirect(url_for("login"))


@app.errorhandler(413)
def file_too_large(_err):
    flash(f"Arquivo muito grande. Limite: {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB.", "danger")
    return redirect(url_for("dashboard"))


def _file_extension(filename):
    return os.path.splitext(filename or "")[1].lower()


def is_allowed_file(filename, allowed_extensions=None):
    ext = _file_extension(filename)
    allowed = allowed_extensions if allowed_extensions is not None else ALLOWED_EXTENSIONS
    return ext in allowed


def save_uploaded_file(file_storage, user_id, prefix, allowed_extensions):
    if not file_storage or not file_storage.filename:
        raise ValueError("Arquivo nao enviado.")
    if not is_allowed_file(file_storage.filename, allowed_extensions):
        raise ValueError(f"Formato nao permitido para {prefix}.")

    safe_name = secure_filename(file_storage.filename)
    if not safe_name:
        raise ValueError("Nome de arquivo invalido.")

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    final_name = f"{prefix}_{user_id}_{stamp}_{safe_name}"
    dest_path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
    real_upload = os.path.realpath(app.config["UPLOAD_FOLDER"])
    real_dest = os.path.realpath(dest_path)
    if not real_dest.startswith(real_upload):
        raise ValueError("Destino de upload invalido.")

    file_storage.save(real_dest)
    return real_dest


def limpar_valor(v):
    if v is None:
        return None

    v = str(v).strip().replace("R$", "").replace(" ", "")
    negativo = False
    if v.startswith("(") and v.endswith(")"):
        negativo = True
        v = v[1:-1]
    if v.startswith("-"):
        negativo = True
        v = v[1:]

    qtd_ponto = v.count(".")
    qtd_virgula = v.count(",")

    if qtd_virgula == 1 and qtd_ponto <= 1:
        v = v.replace(".", "").replace(",", ".")
    elif qtd_ponto == 1 and qtd_virgula == 0:
        pass
    elif qtd_ponto > 1 and qtd_virgula == 0:
        v = v.replace(".", "")
    elif qtd_virgula > 1 and qtd_ponto == 0:
        v = v.replace(",", "")
    else:
        v = "".join(ch for ch in v if ch.isdigit() or ch in ".-")

    try:
        valor = float(v)
        return -valor if negativo else valor
    except (ValueError, TypeError):
        return None


PALAVRAS_VENDA = [
    "pix",
    "pix recebido",
    "credito pix",
    "ac cr pix",
    "venda",
    "credito",
    "crédito",
    "cartao",
    "cartão",
    "recebido",
    "pagamento recebido",
    "mercado pago",
    "pagseguro",
    "sumup",
    "link de pagamento",
    "venda online",
    "recebimento",
    "pagto",
    "cr vd cart",
    "cr trans rec",
    "cr fornec",
    "cr tev",
    "tev",
    "doc recebido",
    "ted recebido",
    "cielo",
    "rede",
    "stone",
    "getnet",
    "bin",
    "pagbank",
    "picpay",
    "pagamento",
    "receb",
]

PALAVRAS_IGNORAR = [
    "transferencia",
    "transferência",
    "deposito",
    "depósito",
    "entre contas",
    "estorno",
    "est credit",
    "devolucao",
    "devolução",
    "taxa",
    "tarifa",
    "iof",
    "mdr",
    "saque",
]


def eh_venda(descricao):
    if not descricao:
        return False

    d = str(descricao).lower()
    if any(p in d for p in PALAVRAS_IGNORAR):
        return False
    return any(p in d for p in PALAVRAS_VENDA)


def _selecionar_coluna(df, palavras):
    for col in df.columns:
        nome = str(col).lower().strip()
        if any(p in nome for p in palavras):
            return col
    return None


def _extrair_total_pdf_tabela(path):
    total = 0.0
    linhas_validas = 0
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            tables = page.extract_tables() or []
            for table in tables:
                if not table or len(table) < 2:
                    continue

                header = [str(h).lower().strip() for h in table[0] if h]
                header_str = " ".join(header)
                is_extrato = "saldo" in header_str and "valor" in header_str

                col_idx = None
                for i, nome in enumerate(header):
                    if any(p in nome for p in ["valor", "total", "crédito", "credito", "débito", "debito"]):
                        col_idx = i
                        break
                if col_idx is None:
                    continue

                for row in table[1:]:
                    if len(row) <= col_idx:
                        continue
                    valor = limpar_valor(row[col_idx])
                    if valor is None:
                        continue
                    if not is_extrato or valor > 0:
                        total += valor
                        linhas_validas += 1
    return total if linhas_validas > 0 else 0.0


def _extrair_total_pdf_texto(path):
    total = 0.0
    valor_re = re.compile(r"\(?-?\d{1,3}(?:\.\d{3})*(?:,\d{2})\)?|\(?-?\d+(?:[.,]\d{2})\)?")
    with pdfplumber.open(path) as pdf:
        texto = "\n".join((page.extract_text() or "") for page in pdf.pages)

    for line in texto.split("\n"):
        line_low = line.lower()
        if not any(p in line_low for p in PALAVRAS_VENDA):
            continue
        valores = [limpar_valor(m.group(0)) for m in valor_re.finditer(line)]
        valores = [v for v in valores if v is not None and v > 0]
        if valores:
            total += max(valores)
    return total


def _extrair_total_pdf_camelot(path):
    if camelot is None:
        return 0.0

    total = 0.0
    try:
        tables = camelot.read_pdf(path, flavor="stream")
    except Exception:
        return 0.0

    for table in tables:
        df = table.df
        best_col = None
        for col in df.columns:
            serie = df[col].apply(limpar_valor)
            validos = serie[serie.notnull()]
            if len(validos) >= 3:
                best_col = col
                break
        if best_col is not None:
            serie = df[best_col].apply(limpar_valor)
            total += float(serie[serie.notnull() & (serie > 0)].sum())
    return total


def ler_arquivo(path):
    if not os.path.exists(path):
        raise ValueError("Arquivo nao encontrado para leitura.")
    ext = os.path.splitext(path)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError("Formato nao suportado")
    total = 0.0

    if ext in [".csv", ".xlsx"]:
        if ext == ".csv":
            try:
                df = pd.read_csv(path, sep=None, engine="python")
            except Exception:
                df = pd.read_csv(path)
        else:
            df = pd.read_excel(path)

        valor_col = _selecionar_coluna(df, ["valor", "total", "amount", "credito", "crédito", "debito", "débito"])
        desc_col = _selecionar_coluna(df, ["descri", "memo", "historico", "histórico"])

        if not valor_col:
            raise ValueError("Arquivo sem coluna de valor identificavel.")

        df["valor_limpo"] = df[valor_col].apply(limpar_valor)
        df = df[df["valor_limpo"].notnull()]

        header_str = " ".join(str(col).lower() for col in df.columns)
        if any(p in header_str for p in ["saldo", "descricao", "descrição", "banco"]):
            df = df[df["valor_limpo"] > 0]

        if desc_col:
            filtrado = df[df[desc_col].apply(eh_venda)]
            if not filtrado.empty:
                df = filtrado

        total = float(df["valor_limpo"].sum())

    elif ext == ".pdf":
        tentativas = []
        try:
            tentativas.append(("tabela_pdfplumber", _extrair_total_pdf_tabela(path)))
        except Exception:
            tentativas.append(("tabela_pdfplumber", 0.0))
        try:
            tentativas.append(("texto_pdfplumber", _extrair_total_pdf_texto(path)))
        except Exception:
            tentativas.append(("texto_pdfplumber", 0.0))
        try:
            tentativas.append(("camelot", _extrair_total_pdf_camelot(path)))
        except Exception:
            tentativas.append(("camelot", 0.0))

        metodo, valor = next(((m, v) for m, v in tentativas if v > 0), ("nenhum", 0.0))
        logger.info("Leitura PDF %s metodo=%s total=%.2f", os.path.basename(path), metodo, valor)
        if valor <= 0:
            raise ValueError("Nao foi possivel extrair valores validos do PDF.")
        total = valor

    elif ext == ".ofx":
        tree = ET.parse(path)
        root = tree.getroot()
        for trn in root.findall(".//STMTTRN"):
            amt = trn.find("TRNAMT")
            memo = trn.find("MEMO")
            val = limpar_valor(amt.text if amt is not None else None)
            desc = memo.text if memo is not None else ""
            if val and val > 0 and eh_venda(desc):
                total += val

    elif ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            for trans in data:
                val = limpar_valor(trans.get("valor") or trans.get("amount"))
                desc = trans.get("descricao") or trans.get("memo")
                if val and val > 0 and eh_venda(desc):
                    total += val

    return float(total)


class MapColumnsForm(FlaskForm):
    data_col = StringField("Coluna de Data")
    desc_col = StringField("Coluna de Descricao")
    valor_col = StringField("Coluna de Valor")
    submit = SubmitField("Mapear")


@app.route("/map_columns", methods=["GET", "POST"])
@login_required
def map_columns():
    form = MapColumnsForm()
    path = session.get("file_path")
    if not path:
        return redirect(url_for("dashboard"))
    real_upload = os.path.realpath(app.config["UPLOAD_FOLDER"])
    real_path = os.path.realpath(path)
    if not real_path.startswith(real_upload) or not os.path.exists(real_path):
        flash("Arquivo temporario invalido ou expirado.", "danger")
        session.pop("file_path", None)
        return redirect(url_for("dashboard"))

    if form.validate_on_submit():
        try:
            df = pd.read_csv(real_path) if real_path.lower().endswith(".csv") else pd.read_excel(real_path)
            data_col = form.data_col.data
            desc_col = form.desc_col.data
            valor_col = form.valor_col.data

            if all([data_col in df.columns, desc_col in df.columns, valor_col in df.columns]):
                df["valor_limpo"] = df[valor_col].apply(limpar_valor)
                df = df[df["valor_limpo"].notnull() & (df["valor_limpo"] > 0)]
                df = df[df[desc_col].apply(eh_venda)]
                total = float(df["valor_limpo"].sum())
                session["manual_total"] = total
                flash("Arquivo mapeado com sucesso.", "success")
                return redirect(url_for("dashboard"))

            flash("Colunas invalidas.", "danger")
        except Exception as e:
            flash(f"Erro ao mapear colunas: {e}", "danger")

    return render_template("map_columns.html", form=form)


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/termos", methods=["GET"])
def termos():
    return render_template("termos.html")


@app.route("/privacidade", methods=["GET"])
def privacidade():
    return render_template("politica.html")


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    mensagem = None
    divergencia = 0.0
    total_extrato = 0.0
    total_vendas = 0.0
    pdf_path = None
    wa_link = None

    if request.method == "POST":
        if "extrato" not in request.files or "vendas" not in request.files:
            mensagem = "Suba os dois arquivos (PDF, CSV, XLSX, OFX ou JSON)!"
            return render_template("dashboard.html", mensagem=mensagem)

        extrato_file = request.files["extrato"]
        vendas_file = request.files["vendas"]

        if extrato_file.filename == "" or vendas_file.filename == "":
            mensagem = "Selecione os dois arquivos!"
            return render_template("dashboard.html", mensagem=mensagem)

        extrato_path = None
        vendas_path = None

        try:
            extrato_path = save_uploaded_file(
                extrato_file,
                user_id=current_user.id,
                prefix="extrato",
                allowed_extensions=ALLOWED_EXTRATO_EXTENSIONS,
            )
            vendas_path = save_uploaded_file(
                vendas_file,
                user_id=current_user.id,
                prefix="vendas",
                allowed_extensions=ALLOWED_VENDAS_EXTENSIONS,
            )
            total_extrato = ler_arquivo(extrato_path)
            total_vendas = ler_arquivo(vendas_path)
            if total_extrato < 0 or total_vendas < 0:
                raise ValueError("Foram detectados valores negativos no total. Revise os arquivos.")
            divergencia = total_vendas - total_extrato

            mensagem = (
                f"Conciliacao feita!\n"
                f"Total Extrato (movimentacoes liquidas): {formato_br(total_extrato)}\n"
                f"Total Vendas registradas: {formato_br(total_vendas)}\n"
                f"Divergencia: {formato_br(divergencia)}\n\n"
                f"{'Dica: ' if abs(divergencia) > 50 else ''}"
                f"{'Se vendas > extrato: confira depositos pendentes, taxas ou prazos de cartao/Pix.' if divergencia > 0 else ''}"
                f"{'Se extrato > vendas: verifique lancamentos duplicados ou entradas nao registradas.' if divergencia < 0 else ''}"
            )

            db_execute(
                "INSERT INTO conciliacoes (user_id, data, total_extrato, total_vendas, divergencia) VALUES (?, DATETIME('now'), ?, ?, ?)",
                (current_user.id, total_extrato, total_vendas, divergencia),
                commit=True,
            )
            session["ultima_conciliacao"] = {
                "total_extrato": total_extrato,
                "total_vendas": total_vendas,
                "divergencia": divergencia,
                "data_referencia": datetime.date.today().isoformat(),
            }

            pdf_path_temp = os.path.join(
                app.config["UPLOAD_FOLDER"],
                f"relatorio_{current_user.id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            )
            wa_link_temp = None
            if abs(divergencia) > 50.0:
                texto = (
                    f"Ei, detectei divergencia de {formato_br(divergencia)} esse mes no meu sistema MEI Organizado.\n"
                    f"Total vendas: {formato_br(total_vendas)}\n"
                    f"Total extrato: {formato_br(total_extrato)}\n"
                    f"Da uma olhada?"
                )
                texto_encoded = urllib.parse.quote(texto)
                wa_link_temp = f"https://wa.me/?text={texto_encoded}"

            if current_user.is_pro:
                pdf_path = gerar_pdf(total_extrato, total_vendas, divergencia, pdf_path_temp)
                wa_link = wa_link_temp
                session["last_pdf_path"] = pdf_path
            else:
                session["conciliacao_pendente"] = {
                    "mensagem": mensagem,
                    "divergencia": divergencia,
                    "total_extrato": total_extrato,
                    "total_vendas": total_vendas,
                    "pdf_path_temp": pdf_path_temp,
                    "wa_link_temp": wa_link_temp,
                }
                return redirect(url_for("escolher_plano"))

        except Exception as e:
            logger.exception("Erro ao processar conciliacao user_id=%s", current_user.id)
            mensagem = f"Erro ao processar: {e}"

        finally:
            for p in [extrato_path, vendas_path]:
                try:
                    os.remove(p)
                except Exception:
                    pass

    month = datetime.date.today().strftime("%Y-%m")
    row = db_fetchone(
        "SELECT SUM(valor_bruto) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto > 0",
        (current_user.id, month),
    )
    receita_total = (row[0] if row else 0.0) or 0.0

    row = db_fetchone(
        "SELECT SUM(ABS(valor_bruto)) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto < 0",
        (current_user.id, month),
    )
    despesas = (row[0] if row else 0.0) or 0.0
    lucro_liquido = receita_total - despesas

    grafico_linha_rows = db_fetchall(
        """
        SELECT strftime('%Y-%m', data) as mes, SUM(valor_liquido) as liquido
        FROM sales WHERE user_id = ? GROUP BY mes ORDER BY mes DESC LIMIT 12
    """,
        (current_user.id,),
    )
    grafico_mapa = {str(row[0]): float(row[1] or 0.0) for row in grafico_linha_rows}
    hoje_mes = datetime.date.today().replace(day=1)
    grafico_linha = []
    for offset in range(11, -1, -1):
        ano = hoje_mes.year
        mes = hoje_mes.month - offset
        while mes <= 0:
            mes += 12
            ano -= 1
        chave = f"{ano:04d}-{mes:02d}"
        grafico_linha.append((chave, grafico_mapa.get(chave, 0.0)))

    year = datetime.date.today().strftime("%Y")
    row = db_fetchone(
        "SELECT SUM(valor_bruto) FROM sales WHERE user_id = ? AND strftime('%Y', data) = ? AND valor_bruto > 0",
        (current_user.id, year),
    )
    faturamento_anual = (row[0] if row else 0.0) or 0.0

    limite_mei = 81000.0
    perto_limite = faturamento_anual > (limite_mei * 0.8)
    categoria_taxa = 0.04
    das_estimado = faturamento_anual * categoria_taxa

    # ==================== RETIRADA SEGURA ====================
    # Regra solicitada:
    # Lucro real = Receita - Despesas - DAS (do mes)
    # Reserva obrigatoria = 20% do lucro real
    # Retirada segura = Lucro real - Reserva
    das_mensal_estimado = receita_total * categoria_taxa
    lucro_real_mes = receita_total - despesas - das_mensal_estimado
    reserva_minima = max(lucro_real_mes * 0.20, 0.0)
    retirada_segura = max(lucro_real_mes - reserva_minima, 0.0)
    retirada_recomendada = retirada_segura > 0
    caixa_real = lucro_real_mes
    saldo_acumulado = 0.0
    despesas_media_mensal = despesas
    if retirada_recomendada:
        retirada_titulo = "Retirada segura hoje"
        retirada_subtexto = "Ja considerando reserva de 20% do lucro real."
    else:
        retirada_titulo = "Retirada nao recomendada"
        retirada_subtexto = "Seu lucro real nao cobre uma retirada segura no momento."
    # ==========================================================

    # ======================= SCORE FINANCEIRO =======================
    margem_lucro = (lucro_liquido / receita_total) if receita_total > 0 else 0.0
    if margem_lucro > 0.30:
        margem_status, margem_pontos = "forte", 25
    elif margem_lucro >= 0.15:
        margem_status, margem_pontos = "atencao", 15
    else:
        margem_status, margem_pontos = "risco", 0

    primeiro_dia_mes = datetime.date.today().replace(day=1)
    mes_anterior_data = primeiro_dia_mes - datetime.timedelta(days=1)
    mes_anterior = mes_anterior_data.strftime("%Y-%m")
    mes_anterior_label = mes_anterior_data.strftime("%m/%Y")

    row = db_fetchone(
        "SELECT SUM(valor_bruto) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto > 0",
        (current_user.id, mes_anterior),
    )
    receita_anterior = (row[0] if row else 0.0) or 0.0
    row = db_fetchone(
        "SELECT SUM(ABS(valor_bruto)) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto < 0",
        (current_user.id, mes_anterior),
    )
    despesas_anterior = (row[0] if row else 0.0) or 0.0
    lucro_anterior = receita_anterior - despesas_anterior

    if lucro_anterior > 0:
        variacao_lucro_pct = ((lucro_liquido - lucro_anterior) / lucro_anterior) * 100
    elif lucro_anterior == 0 and lucro_liquido > 0:
        variacao_lucro_pct = 100.0
    elif lucro_anterior == 0 and lucro_liquido <= 0:
        variacao_lucro_pct = 0.0
    else:
        variacao_lucro_pct = ((lucro_liquido - lucro_anterior) / abs(lucro_anterior)) * 100

    if variacao_lucro_pct > 0:
        tendencia_status, tendencia_pontos = "positiva", 25
    elif variacao_lucro_pct <= -20:
        tendencia_status, tendencia_pontos = "risco", 0
    else:
        tendencia_status, tendencia_pontos = "atencao", 15

    proporcao_despesa = (despesas / receita_total) if receita_total > 0 else 0.0
    if proporcao_despesa <= 0.70:
        despesa_status, despesa_pontos = "controlada", 25
    else:
        despesa_status, despesa_pontos = "alta", 0

    limite_ratio = faturamento_anual / limite_mei if limite_mei > 0 else 0.0
    if limite_ratio <= 0.80:
        limite_status, limite_pontos = "dentro", 25
    elif limite_ratio <= 1.00:
        limite_status, limite_pontos = "alerta", 10
    else:
        limite_status, limite_pontos = "estourado", 0

    finance_score = margem_pontos + tendencia_pontos + despesa_pontos + limite_pontos
    if finance_score >= 80:
        finance_score_label, finance_score_tone = "Saudavel", "green"
    elif finance_score >= 60:
        finance_score_label, finance_score_tone = "Atencao", "yellow"
    else:
        finance_score_label, finance_score_tone = "Risco", "red"

    motivos = []
    if margem_status == "risco":
        motivos.append(f"Margem baixa em {margem_lucro * 100:.1f}%.")
    elif margem_status == "atencao":
        motivos.append(f"Margem em atencao ({margem_lucro * 100:.1f}%).")
    if tendencia_status == "risco":
        motivos.append(f"Lucro caiu {abs(variacao_lucro_pct):.1f}% vs mes anterior.")
    elif tendencia_status == "atencao":
        motivos.append(f"Tendencia estavel/queda leve ({variacao_lucro_pct:.1f}%).")
    if despesa_status == "alta":
        motivos.append(f"Despesas em {proporcao_despesa * 100:.1f}% da receita.")
    if limite_status == "alerta":
        motivos.append(f"Faturamento em {limite_ratio * 100:.1f}% do limite MEI.")
    elif limite_status == "estourado":
        motivos.append("Limite anual do MEI ultrapassado.")
    if not motivos:
        motivos.append("Margem, tendencia, despesas e limite estao em zona saudavel.")

    score_criterios = [
        {"titulo": "Margem", "status": margem_status, "pontos": margem_pontos, "detalhe": f"{margem_lucro * 100:.1f}%"},
        {"titulo": "Tendencia", "status": tendencia_status, "pontos": tendencia_pontos, "detalhe": f"{variacao_lucro_pct:.1f}%"},
        {"titulo": "Despesas", "status": despesa_status, "pontos": despesa_pontos, "detalhe": f"{proporcao_despesa * 100:.1f}%"},
        {"titulo": "Limite MEI", "status": limite_status, "pontos": limite_pontos, "detalhe": f"{limite_ratio * 100:.1f}%"},
    ]
    # ===============================================================

    hoje = datetime.date.today()
    if hoje.day > 20:
        prox_ano = hoje.year + (1 if hoje.month == 12 else 0)
        prox_mes = 1 if hoje.month == 12 else hoje.month + 1
        proximo_vencimento = datetime.date(prox_ano, prox_mes, 20)
    else:
        proximo_vencimento = datetime.date(hoje.year, hoje.month, 20)

    dias_para_vencimento = (proximo_vencimento - hoje).days
    alerta_vencimento = dias_para_vencimento <= 5

    # Evita poluir a UI com flashes repetidos a cada refresh do dashboard.
    # Os indicadores de DAS e limite ja aparecem visualmente nos cards do painel.

    ultima_conciliacao = session.get("ultima_conciliacao")

    return render_template(
        "dashboard.html",
        mensagem=mensagem,
        divergencia=divergencia,
        total_extrato=total_extrato,
        total_vendas=total_vendas,
        pdf_path=pdf_path,
        wa_link=wa_link,
        receita_total=receita_total,
        despesas=despesas,
        lucro_liquido=lucro_liquido,
        grafico_linha=grafico_linha,
        faturamento_anual=faturamento_anual,
        perto_limite=perto_limite,
        das_estimado=das_estimado,
        saldo_acumulado=saldo_acumulado,
        das_mensal_estimado=das_mensal_estimado,
        caixa_real=caixa_real,
        despesas_media_mensal=despesas_media_mensal,
        reserva_minima=reserva_minima,
        retirada_segura=retirada_segura,
        retirada_recomendada=retirada_recomendada,
        retirada_titulo=retirada_titulo,
        retirada_subtexto=retirada_subtexto,
        alerta_vencimento=alerta_vencimento,
        dias_para_vencimento=dias_para_vencimento,
        finance_score=finance_score,
        finance_score_label=finance_score_label,
        finance_score_tone=finance_score_tone,
        score_criterios=score_criterios,
        score_motivo=" ".join(motivos),
        variacao_lucro_pct=variacao_lucro_pct,
        tendencia_status=tendencia_status,
        mes_anterior_label=mes_anterior_label,
        ultima_conciliacao=ultima_conciliacao,
        formato_br=formato_br,
    )


@app.route("/dashboard/aplicar-visao-geral", methods=["POST"])
@login_required
def aplicar_visao_geral():
    acao = request.form.get("acao")
    ultima_conciliacao = session.get("ultima_conciliacao")

    if not ultima_conciliacao:
        flash("Nenhuma conciliacao recente para aplicar na visao geral.", "warning")
        return redirect(url_for("dashboard"))

    total_vendas = float(ultima_conciliacao.get("total_vendas") or 0.0)
    data_referencia = ultima_conciliacao.get("data_referencia") or datetime.date.today().isoformat()
    descricao = f"Resumo conciliacao {data_referencia[:7]}"

    if total_vendas <= 0:
        flash("O total de vendas da conciliacao e zero. Nada foi aplicado.", "warning")
        return redirect(url_for("dashboard"))

    if acao == "substituir":
        db_execute(
            """
            DELETE FROM sales
            WHERE user_id = ?
              AND status IN ('resumo_conciliacao', 'resumo_conciliacao_extra')
              AND strftime('%Y-%m', data) = strftime('%Y-%m', ?)
            """,
            (current_user.id, data_referencia),
        )
        db_execute(
            """
            INSERT INTO sales (
                user_id, data, descricao, metodo_pagamento, parcelado, parcelas,
                valor_bruto, taxa_percentual, taxa_fixa, valor_liquido, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
            """,
            (
                current_user.id,
                data_referencia,
                descricao,
                "resumo_conciliacao",
                0,
                0,
                total_vendas,
                0.0,
                0.0,
                total_vendas,
                "resumo_conciliacao",
            ),
        )
        flash("Visao geral atualizada com o total da conciliacao deste mes.", "success")
    elif acao == "somar":
        db_execute(
            """
            INSERT INTO sales (
                user_id, data, descricao, metodo_pagamento, parcelado, parcelas,
                valor_bruto, taxa_percentual, taxa_fixa, valor_liquido, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))
            """,
            (
                current_user.id,
                data_referencia,
                f"{descricao} (soma)",
                "resumo_conciliacao",
                0,
                0,
                total_vendas,
                0.0,
                0.0,
                total_vendas,
                "resumo_conciliacao_extra",
            ),
        )
        flash("Total da conciliacao foi somado ao que ja existe na visao geral.", "success")
    else:
        flash("Acao invalida.", "danger")
        return redirect(url_for("dashboard"))

    with DB_LOCK:
        conn.commit()
    session.pop("ultima_conciliacao", None)
    return redirect(url_for("dashboard"))


def gerar_pdf(total_extrato, total_vendas, divergencia, pdf_path, logo=None, user_data=None, periodo=None, tabela=None):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    _, height = A4

    if logo:
        p.drawImage(logo, 50, height - 70, width=100, preserveAspectRatio=True, mask="auto")

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 80, "Relatorio de Conciliacao Mensal - MEI Organizado")

    p.setFont("Helvetica", 12)
    p.drawString(50, height - 105, f"Usuario: {user_data or current_user.email}")
    p.drawString(50, height - 125, f"Periodo: {periodo or datetime.date.today().strftime('%m/%Y')}")
    p.drawString(50, height - 145, f"Data do relatorio: {datetime.date.today().strftime('%d/%m/%Y')}")
    p.drawString(50, height - 165, f"Total no extrato bancario: {formato_br(total_extrato)}")
    p.drawString(50, height - 185, f"Total de vendas registradas: {formato_br(total_vendas)}")

    p.setFont("Helvetica-Bold", 14)
    p.setFillColorRGB(0, 0.7, 0) if divergencia >= 0 else p.setFillColorRGB(0.8, 0, 0)
    p.drawString(50, height - 210, f"Divergencia: {formato_br(divergencia)}")

    y = height - 235
    p.setFillColorRGB(0, 0, 0)

    if tabela:
        p.setFont("Helvetica-Bold", 10)
        p.drawString(50, y, "Detalhes:")
        y -= 20
        p.setFont("Helvetica", 9)

        for row in tabela:
            linha = " | ".join(str(item) for item in row)
            p.drawString(50, y, linha[:120])
            y -= 16
            if y < 80:
                p.showPage()
                y = height - 50
                p.setFont("Helvetica", 9)

    p.setFont("Helvetica", 10)
    p.drawString(50, y - 20, "Dica: divergencia acima de R$ 50 pode indicar entradas nao identificadas.")
    p.drawString(50, y - 40, "Gerado por MEI Organizado")

    p.save()
    buffer.seek(0)

    with open(pdf_path, "wb") as f:
        f.write(buffer.read())

    return pdf_path


def conciliar(vendas, extrato):
    extrato_disponivel = extrato.copy()
    conciliadas = []
    vendas_nao_encontradas = []

    for venda in vendas:
        encontrado = False
        valor_venda = round(venda["valor"], 2)

        for entrada in list(extrato_disponivel):
            valor_entrada = round(entrada["valor"], 2)
            if valor_venda == valor_entrada:
                conciliadas.append({"venda": venda, "entrada": entrada})
                extrato_disponivel.remove(entrada)
                encontrado = True
                break

        if not encontrado:
            vendas_nao_encontradas.append(venda)

    return {
        "conciliadas": conciliadas,
        "vendas_nao_encontradas": vendas_nao_encontradas,
        "entradas_sem_venda": extrato_disponivel,
    }


@app.route("/download")
@login_required
def download():
    if not current_user.is_pro:
        flash("Baixar PDF completo e exclusivo do Plano Pro. Assine agora!", "warning")
        return redirect(url_for("dashboard"))

    pdf_path = session.get("last_pdf_path")
    if pdf_path and os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, download_name=f"relatorio_{datetime.date.today()}.pdf")
    return "Relatorio nao encontrado", 404


@app.route("/escolher-plano")
@login_required
def escolher_plano():
    conciliacao = session.get("conciliacao_pendente")
    if not conciliacao:
        flash("Nenhuma conciliacao pendente. Faca upload novamente.", "info")
        return redirect(url_for("dashboard"))

    return render_template("escolher_plano.html", conciliacao=conciliacao)


@app.route("/historico")
@login_required
def historico():
    conciliacoes = db_fetchall(
        "SELECT data, total_extrato, total_vendas, divergencia FROM conciliacoes WHERE user_id = ? ORDER BY id DESC",
        (current_user.id,),
    )
    return render_template("historico.html", conciliacoes=conciliacoes)


@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json
    if not data:
        return "", 400

    if data.get("type") == "payment":
        email = data.get("data", {}).get("metadata", {}).get("email")
        if email:
            db_execute("UPDATE users SET is_pro = 1 WHERE email = ?", (email,), commit=True)
            print(f"Usuario {email} ativado como Pro via webhook!")
            return "", 200

    return "", 200


@app.route("/add_sale", methods=["GET", "POST"])
@login_required
def add_sale():
    if request.method == "POST":
        data = request.form.get("data")
        descricao = request.form.get("descricao")
        metodo = request.form.get("metodo_pagamento")
        parcelado = 1 if request.form.get("parcelado") else 0
        parcelas = int(request.form.get("parcelas") or 0)
        valor_bruto = float(limpar_valor(request.form.get("valor_bruto")) or 0)
        taxa_percentual = float(request.form.get("taxa_percentual") or 0)
        taxa_fixa = float(request.form.get("taxa_fixa") or 0)
        status = request.form.get("status")

        valor_liquido = valor_bruto - (valor_bruto * taxa_percentual / 100) - taxa_fixa
        if parcelado:
            taxa_antecipacao = 1.5
            valor_liquido -= valor_bruto * taxa_antecipacao / 100

        db_execute(
            """INSERT INTO sales (user_id, data, descricao, metodo_pagamento, parcelado, parcelas, valor_bruto, taxa_percentual, taxa_fixa,
                     valor_liquido, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))""",
            (current_user.id, data, descricao, metodo, parcelado, parcelas, valor_bruto, taxa_percentual, taxa_fixa, valor_liquido, status),
            commit=True,
        )
        flash("Venda adicionada com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_sale.html")


@app.route("/export/<tipo>", methods=["GET"])
@login_required
def export(tipo):
    if not current_user.is_pro:
        flash("Exportacao disponivel apenas para usuarios Pro.", "warning")
        return redirect(url_for("dashboard"))

    month = request.args.get("month", datetime.date.today().strftime("%Y-%m"))
    if not re.fullmatch(r"\d{4}-\d{2}", month):
        month = datetime.date.today().strftime("%Y-%m")

    if tipo == "extrato_mensal":
        data = db_fetchall("SELECT * FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ?", (current_user.id, month))
    elif tipo == "relatorio_vendas":
        data = db_fetchall(
            "SELECT metodo_pagamento, SUM(valor_bruto), SUM(valor_liquido) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? GROUP BY metodo_pagamento",
            (current_user.id, month),
        )
    elif tipo == "resumo_financeiro":
        row = db_fetchone(
            "SELECT SUM(valor_bruto) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto > 0",
            (current_user.id, month),
        )
        receita_total = (row[0] if row else 0.0) or 0.0
        row = db_fetchone(
            "SELECT SUM(ABS(valor_bruto)) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto < 0",
            (current_user.id, month),
        )
        despesas = (row[0] if row else 0.0) or 0.0
        lucro_liquido = receita_total - despesas
        data = [("Receita", receita_total), ("Despesas", despesas), ("Lucro", lucro_liquido)]
    else:
        return "Tipo de exportacao invalido", 400

    fmt = request.args.get("format", "pdf")

    if fmt == "pdf":
        pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{tipo}_{month}.pdf")
        gerar_pdf(0, 0, 0, pdf_path, tabela=data, periodo=month)
        return send_file(pdf_path, as_attachment=True)

    if fmt == "csv":
        df = pd.DataFrame(data)
        csv_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{tipo}_{month}.csv")
        df.to_csv(csv_path, index=False)
        return send_file(csv_path, as_attachment=True)

    if fmt == "xlsx":
        df = pd.DataFrame(data)
        xlsx_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{tipo}_{month}.xlsx")
        df.to_excel(xlsx_path, index=False)
        return send_file(xlsx_path, as_attachment=True)

    return "Formato invalido", 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
