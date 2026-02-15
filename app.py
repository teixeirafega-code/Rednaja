from flask import Flask, request, render_template, send_file, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import tabula
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import os
import datetime
import warnings
import urllib.parse

warnings.filterwarnings("ignore")

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Muda pra algo seguro (ex: string aleatória longa)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configura Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Banco simples (SQLite)
import sqlite3
conn = sqlite3.connect('meis.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, is_pro INTEGER DEFAULT 0)''')
c.execute('''CREATE TABLE IF NOT EXISTS conciliacoes
             (id INTEGER PRIMARY KEY, user_id INTEGER, data TEXT, total_extrato REAL, total_vendas REAL, divergencia REAL)''')
conn.commit()

class User(UserMixin):
    def __init__(self, id, email, is_pro):
        self.id = id
        self.email = email
        self.is_pro = is_pro

@login_manager.user_loader
def load_user(user_id):
    c.execute("SELECT id, email, is_pro FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row:
        return User(row[0], row[1], row[2])
    return None

# Formulários
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Cadastrar')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = generate_password_hash(form.password.data)
        try:
            c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
            conn.commit()
            flash('Cadastro feito! Faça login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email já cadastrado.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        c.execute("SELECT id, password, is_pro FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        if row and check_password_hash(row[1], form.password.data):  # row[1] = password
            user = User(row[0], email, row[2])  # row[2] = is_pro
            login_user(user)
            flash('Login feito!', 'success')
            return redirect(url_for('home'))
        flash('Email ou senha inválidos.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Saiu da conta.', 'info')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def home():
    mensagem = ""
    divergencia = None
    total_extrato = None
    total_vendas = None
    pdf_path = None
    wa_link = None

    if request.method == 'POST':
        if 'extrato' not in request.files or 'vendas' not in request.files:
            mensagem = "Suba os dois arquivos (PDF ou CSV)!"
            return render_template('index.html', mensagem=mensagem)

        extrato_file = request.files['extrato']
        vendas_file = request.files['vendas']

        if extrato_file.filename == '' or vendas_file.filename == '':
            mensagem = "Selecione os dois arquivos!"
            return render_template('index.html', mensagem=mensagem)

        extrato_path = os.path.join(app.config['UPLOAD_FOLDER'], extrato_file.filename)
        vendas_path = os.path.join(app.config['UPLOAD_FOLDER'], vendas_file.filename)
        extrato_file.save(extrato_path)
        vendas_file.save(vendas_path)

        try:
            def ler_arquivo(caminho):
                if caminho.lower().endswith('.pdf'):
                    dfs = tabula.read_pdf(caminho, pages='all', multiple_tables=True)
                    if not dfs:
                        raise ValueError("Nenhuma tabela encontrada no PDF. O PDF pode ser imagem escaneada (não texto selecionável). Converta para CSV ou use um PDF com texto.")
                    df = pd.concat(dfs, ignore_index=True)
                    df.columns = df.columns.str.lower().str.strip()
                    valor_col = next((col for col in df.columns if 'valor' in col or 'total' in col or 'saldo' in col), None)
                    if valor_col is None:
                        raise ValueError("Não encontrou coluna de valor/total/saldo no PDF.")
                    df[valor_col] = pd.to_numeric(df[valor_col].astype(str).str.replace(',', '.').str.strip(), errors='coerce')
                    return df[valor_col].sum()
                elif caminho.lower().endswith('.csv'):
                    df = pd.read_csv(caminho)
                    df.columns = df.columns.str.lower().str.strip()
                    valor_col = next((col for col in df.columns if 'valor' in col or 'total' in col), None)
                    if valor_col is None:
                        raise ValueError("Não encontrou coluna de valor/total no CSV.")
                    df[valor_col] = pd.to_numeric(df[valor_col].astype(str).str.replace(',', '.').str.strip(), errors='coerce')
                    return df[valor_col].sum()
                else:
                    raise ValueError(f"Formato não suportado: {caminho}")

            total_extrato = ler_arquivo(extrato_path)
            total_vendas = ler_arquivo(vendas_path)
            divergencia = total_vendas - total_extrato

            mensagem = f"Conciliação feita! Divergência: R$ {divergencia:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')

            # Salva histórico sempre (pra todos os usuários)
            c.execute("INSERT INTO conciliacoes (user_id, data, total_extrato, total_vendas, divergencia) VALUES (?, DATETIME('now'), ?, ?, ?)",
                      (current_user.id, total_extrato, total_vendas, divergencia))
            conn.commit()

            # Libera conteúdo completo só pro Pro
            if current_user.is_pro:
                pdf_path = gerar_pdf(total_extrato, total_vendas, divergencia)
                if abs(divergencia) > 50.00:
                    texto = f"Ei, detectei divergência de R$ {divergencia:,.2f} esse mês no meu sistema MEI Organizado.\nTotal vendas: R$ {total_vendas:,.2f}\nTotal extrato: R$ {total_extrato:,.2f}\nDá uma olhada? 🚨"
                    texto_encoded = urllib.parse.quote(texto)
                    wa_link = f"https://wa.me/?text={texto_encoded}"
            else:
                mensagem += "<br><strong>Resultado completo (PDF + alerta WhatsApp) liberado apenas no Plano Pro (R$ 59/mês). Assine agora!</strong>"

        except Exception as e:
            mensagem = f"Erro ao processar: {str(e)}"

        try:
            os.remove(extrato_path)
            os.remove(vendas_path)
        except:
            pass

    return render_template('index.html', mensagem=mensagem, divergencia=divergencia,
                           total_extrato=total_extrato, total_vendas=total_vendas, pdf_path=pdf_path, wa_link=wa_link)

def gerar_pdf(total_extrato, total_vendas, divergencia):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 80, "Relatório de Conciliação Mensal - MEI Organizado")

    p.setFont("Helvetica", 12)
    p.drawString(50, height - 120, f"Data do relatório: {datetime.date.today().strftime('%d/%m/%Y')}")
    p.drawString(50, height - 150, f"Total no extrato bancário: R$ {total_extrato:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.'))
    p.drawString(50, height - 170, f"Total de vendas registradas: R$ {total_vendas:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.'))

    p.setFont("Helvetica-Bold", 14)
    p.setFillColorRGB(0, 0.7, 0) if divergencia >= 0 else p.setFillColorRGB(0.8, 0, 0)
    p.drawString(50, height - 210, f"Divergência: R$ {divergencia:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.'))

    p.setFont("Helvetica", 10)
    p.drawString(50, height - 250, "Dica: Se a divergência for maior que R$ 50, confira entradas manuais ou depósitos não identificados.")
    p.drawString(50, height - 270, "Gerado por MEI Organizado - Seu dinheiro sem dor de cabeça")

    p.save()
    buffer.seek(0)

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'relatorio.pdf')
    with open(pdf_path, 'wb') as f:
        f.write(buffer.read())

    return pdf_path

@app.route('/download')
@login_required
def download():
    if not current_user.is_pro:
        flash('Baixar PDF completo é exclusivo do Plano Pro. Assine agora!', 'warning')
        return redirect(url_for('home'))
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'relatorio.pdf')
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, download_name=f"relatorio_{datetime.date.today()}.pdf")
    return "Relatório não encontrado", 404

@app.route('/historico')
@login_required
def historico():
    c.execute("SELECT data, total_extrato, total_vendas, divergencia FROM conciliacoes WHERE user_id = ? ORDER BY id DESC", (current_user.id,))
    conciliacoes = c.fetchall()
    return render_template('historico.html', conciliacoes=conciliacoes)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

