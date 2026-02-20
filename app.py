from flask import Flask, request, render_template, send_file, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import pdfplumber  # principal pra PDF sem Java
#import camelot     # fallback pra tabelas difíceis (instale se necessário)
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO
import os
import datetime
import warnings
import urllib.parse
import sqlite3
import xml.etree.ElementTree as ET  # Para OFX
import json  # Para JSON

warnings.filterwarnings("ignore")

app = Flask(__name__)
app.secret_key = 'Fernando12@24'  # Mude pra algo seguro em produção!
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def format_br(valor):
    try:
        return f"{valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except:
        return "0,00"

app.jinja_env.filters['format_br'] = format_br


# Configura Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Banco simples (SQLite)
conn = sqlite3.connect('meis.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, is_pro INTEGER DEFAULT 0)''')
c.execute('''CREATE TABLE IF NOT EXISTS conciliacoes
             (id INTEGER PRIMARY KEY, user_id INTEGER, data TEXT, total_extrato REAL, total_vendas REAL, divergencia REAL)''')
c.execute('''CREATE TABLE IF NOT EXISTS sales
             (id INTEGER PRIMARY KEY, user_id INTEGER, data TEXT, descricao TEXT, metodo_pagamento TEXT, parcelado INTEGER, parcelas INTEGER, 
             valor_bruto REAL, taxa_percentual REAL, taxa_fixa REAL, valor_liquido REAL, status TEXT, created_at TEXT)''')
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
            
            # Logar automaticamente após cadastro
            c.execute("SELECT id, password, is_pro FROM users WHERE email = ?", (email,))
            row = c.fetchone()
            if row:
                user = User(row[0], email, row[2])
                login_user(user)
                flash('Cadastro realizado e você já está logado!', 'success')
                return redirect(url_for('dashboard'))  # Leva direto para dashboard com upload
            
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
        if row and check_password_hash(row[1], form.password.data):
            user = User(row[0], email, row[2])
            login_user(user)
            flash('Login feito!', 'success')
            return redirect(url_for('dashboard'))  # Leva direto para dashboard com upload
        flash('Email ou senha inválidos.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Saiu da conta.', 'info')
    return redirect(url_for('login'))

def limpar_valor(v):
    if v is None:
        return None
    
    v = str(v).strip()
    
    # Remove símbolos comuns de moeda e espaços extras
    v = v.replace('R$', '').replace('R$ ', '').replace('R$', '').strip()
    v = v.replace(' ', '')
    
    # Conta quantos pontos e vírgulas existem
    qtd_ponto = v.count('.')
    qtd_virgula = v.count(',')
    
    if qtd_virgula == 1 and qtd_ponto <= 1:
        # Formato brasileiro clássico: 1.234,56
        v = v.replace('.', '').replace(',', '.')
    
    elif qtd_ponto == 1 and qtd_virgula == 0:
        # Formato americano/alguns sistemas: 1234.56
        pass
    
    elif qtd_ponto > 1 and qtd_virgula == 0:
        # 1.234.567,89 → provavelmente brasileiro com ponto como milhar
        v = v.replace('.', '')
    
    elif qtd_virgula > 1 and qtd_ponto == 0:
        # 1,234,567.89 → americano com vírgula como milhar
        v = v.replace(',', '')
    
    else:
        # Caso ambíguo → tenta remover tudo que não seja número, -, .
        v = ''.join(c for c in v if c.isdigit() or c in '.-')
    
    try:
        return float(v)
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
    "receb"
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
    "saque"
]

def eh_venda(descricao):
    if not descricao:
        return False

    d = descricao.lower()

    num_neg = sum(1 for p in PALAVRAS_IGNORAR if p in d)
    if num_neg > 0:
        return False

    num_pos = sum(1 for p in PALAVRAS_VENDA if p in d)
    return num_pos > 0

def formato_br(valor):
    return f"R$ {valor:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')

def ler_arquivo(path):
    ext = os.path.splitext(path)[1].lower()
    total = 0.0

    if ext in ['.csv', '.xlsx']:
        if ext == '.csv':
            df = pd.read_csv(path)
        else:
            df = pd.read_excel(path)
        
        # Detectar colunas automaticamente
        cols = df.columns.str.lower()
        data_col = next((col for col in cols if 'data' in col or 'date' in col), None)
        desc_col = next((col for col in cols if 'descri' in col or 'memo' in col), None)
        valor_col = next((col for col in cols if 'valor' in col or 'amount' in col), None)
        tipo_col = next((col for col in cols if 'tipo' in col or 'type' in col or 'crédito' in col or 'débito' in col), None)
        
        if not all([data_col, desc_col, valor_col]):
            # TODO: Implementar rota para mapeamento manual
            flash('Colunas não identificadas. Por favor, mapeie manualmente.', 'warning')
            session['file_path'] = path
            return redirect(url_for('map_columns'))
        
        df['valor_limpo'] = df[valor_col].apply(limpar_valor)
        df = df[df['valor_limpo'].notnull() & (df['valor_limpo'] > 0)]  # Apenas créditos positivos
        
        if desc_col:
            df = df[df[desc_col].apply(eh_venda)]
        
        total = df['valor_limpo'].sum()

    elif ext == '.pdf':
        with pdfplumber.open(path) as pdf:
            text = ''
            for page in pdf.pages:
                text += page.extract_text() or ''
        
        lines = text.split('\n')
        for line in lines:
            # Identificar padrões: data dd/mm/yyyy, valor R$ XXX,XX, palavras-chave
            if any(p in line.lower() for p in PALAVRAS_VENDA) and 'R$' in line:
                parts = line.split()
                for p in parts:
                    val = limpar_valor(p)
                    if val and val > 0:
                        total += val
        
        # Fallback camelot se instalado
        try:
            tables = camelot.read_pdf(path, flavor='stream')
            for table in tables:
                df = table.df
                df = df.applymap(limpar_valor)
                total += df.sum().sum()  # Simplificado, ajuste
        except:
            pass  # Ignorar se camelot não instalado

    elif ext == '.ofx':
        tree = ET.parse(path)
        root = tree.getroot()
        for trn in root.findall('.//STMTTRN'):
            amt = trn.find('TRNAMT').text if trn.find('TRNAMT') is not None else None
            val = limpar_valor(amt)
            memo = trn.find('MEMO').text if trn.find('MEMO') is not None else ''
            if val and val > 0 and eh_venda(memo):
                total += val

    elif ext == '.json':
        with open(path, 'r') as f:
            data = json.load(f)
        # Assumir estrutura como lista de transações
        if isinstance(data, list):
            for trans in data:
                val = limpar_valor(trans.get('valor') or trans.get('amount'))
                desc = trans.get('descricao') or trans.get('memo')
                if val and val > 0 and eh_venda(desc):
                    total += val

    return total

# Rota para mapeamento manual de colunas (simples form)
class MapColumnsForm(FlaskForm):
    data_col = StringField('Coluna de Data')
    desc_col = StringField('Coluna de Descrição')
    valor_col = StringField('Coluna de Valor')
    submit = SubmitField('Mapear')

@app.route('/map_columns', methods=['GET', 'POST'])
@login_required
def map_columns():
    form = MapColumnsForm()
    path = session.get('file_path')
    if not path:
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        # Reprocessar com mapeamento
        df = pd.read_csv(path) if path.endswith('.csv') else pd.read_excel(path)
        data_col = form.data_col.data
        desc_col = form.desc_col.data
        valor_col = form.valor_col.data

        if all([data_col in df.columns, desc_col in df.columns, valor_col in df.columns]):
            df['valor_limpo'] = df[valor_col].apply(limpar_valor)
            df = df[df['valor_limpo'].notnull() & (df['valor_limpo'] > 0)]
            df = df[df[desc_col].apply(eh_venda)]
            total = df['valor_limpo'].sum()
            # Armazenar total ou prosseguir
            session['manual_total'] = total
            return redirect(url_for('dashboard'))  # Ajuste
        else:
            flash('Colunas inválidas.', 'danger')

    return render_template('map_columns.html', form=form)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    mensagem = None
    divergencia = None
    total_extrato = None
    total_vendas = None
    pdf_path = None
    wa_link = None

    if request.method == 'POST':
        if 'extrato' not in request.files or 'vendas' not in request.files:
            mensagem = "Suba os dois arquivos (PDF ou CSV)!"
            return render_template('dashboard.html', mensagem=mensagem)

        extrato_file = request.files['extrato']
        vendas_file = request.files['vendas']

        if extrato_file.filename == '' or vendas_file.filename == '':
            mensagem = "Selecione os dois arquivos!"
            return render_template('dashboard.html', mensagem=mensagem)

        extrato_path = os.path.join(app.config['UPLOAD_FOLDER'], extrato_file.filename)
        vendas_path = os.path.join(app.config['UPLOAD_FOLDER'], vendas_file.filename)
        extrato_file.save(extrato_path)
        vendas_file.save(vendas_path)

        try:
            total_extrato = ler_arquivo(extrato_path)
            total_vendas = ler_arquivo(vendas_path)
            divergencia = total_vendas - total_extrato

            mensagem = f"Conciliação feita! Divergência: {formato_br(divergencia)}"

            # Salva histórico sempre
            c.execute("INSERT INTO conciliacoes (user_id, data, total_extrato, total_vendas, divergencia) VALUES (?, DATETIME('now'), ?, ?, ?)",
                      (current_user.id, total_extrato, total_vendas, divergencia))
            conn.commit()

            # Preparar PDF e WhatsApp temporários
            pdf_path_temp = os.path.join(app.config['UPLOAD_FOLDER'], f'relatorio_{current_user.id}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
            wa_link_temp = None
            if abs(divergencia) > 50.00:
                texto = f"Ei, detectei divergência de {formato_br(divergencia)} esse mês no meu sistema MEI Organizado.\nTotal vendas: {formato_br(total_vendas)}\nTotal extrato: {formato_br(total_extrato)}\nDá uma olhada? 🚨"
                texto_encoded = urllib.parse.quote(texto)
                wa_link_temp = f"https://wa.me/?text={texto_encoded}"

            # Verifica plano
            if current_user.is_pro:
                pdf_path = gerar_pdf(total_extrato, total_vendas, divergencia, pdf_path_temp)
                wa_link = wa_link_temp
                session['last_pdf_path'] = pdf_path  # Salva para download
            else:
                session['conciliacao_pendente'] = {
                    'mensagem': mensagem,
                    'divergencia': divergencia,
                    'total_extrato': total_extrato,
                    'total_vendas': total_vendas,
                    'pdf_path_temp': pdf_path_temp,
                    'wa_link_temp': wa_link_temp
                }
                return redirect(url_for('escolher_plano'))

        except Exception as e:
            mensagem = f"Erro ao processar: {str(e)}"

        finally:
            try:
                os.remove(extrato_path)
                os.remove(vendas_path)
            except:
                pass

    # Cálculos para resumo financeiro (sempre mostrado)
    month = datetime.date.today().strftime('%Y-%m')
    c.execute("SELECT SUM(valor_bruto) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto > 0", (current_user.id, month))
    receita_total = c.fetchone()[0] or 0.0

    c.execute("SELECT SUM(ABS(valor_bruto)) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? AND valor_bruto < 0", (current_user.id, month))
    despesas = c.fetchone()[0] or 0.0

    lucro_liquido = receita_total - despesas

    # Dados para gráfico de linha mensal
    c.execute("""
        SELECT strftime('%Y-%m', data) as mes, SUM(valor_liquido) as liquido
        FROM sales WHERE user_id = ? GROUP BY mes ORDER BY mes DESC LIMIT 12
    """, (current_user.id,))
    grafico_linha = c.fetchall()

    # Dados para gráfico de barras por método
    c.execute("""
        SELECT metodo_pagamento, SUM(valor_liquido) as liquido
        FROM sales WHERE user_id = ? GROUP BY metodo_pagamento
    """, (current_user.id,))
    grafico_barras = c.fetchall()

    # Para Simples Nacional / DAS
    year = datetime.date.today().strftime('%Y')
    c.execute("SELECT SUM(valor_bruto) FROM sales WHERE user_id = ? AND strftime('%Y', data) = ? AND valor_bruto > 0", (current_user.id, year))
    faturamento_anual = c.fetchone()[0] or 0.0

    limite_mei = 81000.0
    perto_limite = faturamento_anual > (limite_mei * 0.8)

    # Estimativa de DAS (ex: 4% para comércio; ajuste por categoria do usuário)
    categoria_taxa = 0.04  # TODO: Armazenar no user ou config
    das_estimado = faturamento_anual * categoria_taxa

    # Alerta de vencimento (DAS vence dia 20)
    hoje = datetime.date.today()
    if hoje.day > 20:
        proximo_vencimento = datetime.date(hoje.year, hoje.month + 1, 20)
    else:
        proximo_vencimento = datetime.date(hoje.year, hoje.month, 20)
    dias_para_vencimento = (proximo_vencimento - hoje).days
    alerta_vencimento = dias_para_vencimento <= 5

    if current_user.is_pro:
        # Enviar notificação (ex: via email ou wa_link similar)
        if alerta_vencimento:
            # TODO: Implementar envio real
            flash(f'Alerta: DAS vence em {dias_para_vencimento} dias!', 'warning')
    else:
        if perto_limite or alerta_vencimento:
            flash('Alertas de DAS e limite disponíveis no Plano Pro.', 'info')

   # ==================== PROTEÇÃO CONTRA None ====================
    # Evita erro no template quando a página carrega pela primeira vez (GET)
    if divergencia is None:
        divergencia = 0.0
    if total_extrato is None:
        total_extrato = 0.0
    if total_vendas is None:
        total_vendas = 0.0
    # ===========================================================
    
    return render_template('dashboard.html', mensagem=mensagem, divergencia=divergencia,
                           total_extrato=total_extrato, total_vendas=total_vendas, pdf_path=pdf_path, wa_link=wa_link,
                           receita_total=receita_total, despesas=despesas, lucro_liquido=lucro_liquido,
                           grafico_linha=grafico_linha, grafico_barras=grafico_barras,
                           faturamento_anual=faturamento_anual, perto_limite=perto_limite, das_estimado=das_estimado,
                           alerta_vencimento=alerta_vencimento, dias_para_vencimento=dias_para_vencimento,
                           formato_br=formato_br)

def gerar_pdf(total_extrato, total_vendas, divergencia, pdf_path, logo=None, user_data=None, periodo=None, tabela=None):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Logo (se tiver)
    if logo:
        p.drawImage(logo, 50, height - 70, width=100, preserveAspectRatio=True, mask='auto')

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height - 80, "Relatório de Conciliação Mensal - MEI Organizado")

    p.setFont("Helvetica", 12)
    p.drawString(50, height - 100, f"Usuário: {user_data or current_user.email}")
    p.drawString(50, height - 120, f"Período: {periodo or datetime.date.today().strftime('%m/%Y')}")
    p.drawString(50, height - 140, f"Data do relatório: {datetime.date.today().strftime('%d/%m/%Y')}")
    p.drawString(50, height - 160, f"Total no extrato bancário: {formato_br(total_extrato)}")
    p.drawString(50, height - 180, f"Total de vendas registradas: {formato_br(total_vendas)}")

    p.setFont("Helvetica-Bold", 14)
    if divergencia >= 0:
        p.setFillColorRGB(0, 0.7, 0)
    else:
        p.setFillColorRGB(0.8, 0, 0)
    p.drawString(50, height - 210, f"Divergência: {formato_br(divergencia)}")

    # ==================== CORREÇÃO AQUI ====================
    # Posição inicial para o conteúdo após os totais
    y = height - 230

    # Tabela detalhada (se houver)
    if tabela:
        p.setFont("Helvetica-Bold", 10)
        p.drawString(50, y, "Detalhes das Vendas:")
        y -= 25
        p.setFont("Helvetica", 10)
        p.setFillColorRGB(0, 0, 0)

        for row in tabela:
            linha = f"ID: {row[0]} | Data: {row[2]} | Valor Líquido: {formato_br(row[10])}"
            p.drawString(50, y, linha)
            y -= 18
            if y < 80:  # margem de segurança para não sair da página
                p.showPage()
                y = height - 50

    # Rodapé / dicas (sempre aparece, mesmo sem tabela)
    p.setFont("Helvetica", 10)
    p.drawString(50, y - 25, "Dica: Se a divergência for maior que R$ 50, confira entradas manuais ou depósitos não identificados.")
    p.drawString(50, y - 45, "Gerado por MEI Organizado - Seu dinheiro sem dor de cabeça")

    p.save()
    buffer.seek(0)

    with open(pdf_path, 'wb') as f:
        f.write(buffer.read())

    return pdf_path
    
def conciliar(vendas, extrato):
    extrato_disponivel = extrato.copy()
    conciliadas = []
    vendas_nao_encontradas = []

    for venda in vendas:
        encontrado = False
        valor_venda = round(venda["valor"], 2)

        for entrada in extrato_disponivel:
            valor_entrada = round(entrada["valor"], 2)

            if valor_venda == valor_entrada:
                conciliadas.append({
                    "venda": venda,
                    "entrada": entrada
                })
                extrato_disponivel.remove(entrada)
                encontrado = True
                break

        if not encontrado:
            vendas_nao_encontradas.append(venda)

    entradas_sem_venda = extrato_disponivel

    return {
        "conciliadas": conciliadas,
        "vendas_nao_encontradas": vendas_nao_encontradas,
        "entradas_sem_venda": entradas_sem_venda
    }
@app.route('/download')
@login_required
def download():
    if not current_user.is_pro:
        flash('Baixar PDF completo é exclusivo do Plano Pro. Assine agora!', 'warning')
        return redirect(url_for('dashboard'))
    pdf_path = session.get('last_pdf_path')
    if pdf_path and os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, download_name=f"relatorio_{datetime.date.today()}.pdf")
    return "Relatório não encontrado", 404

@app.route('/escolher-plano')
@login_required
def escolher_plano():
    conciliacao = session.get('conciliacao_pendente')
    if not conciliacao:
        flash("Nenhuma conciliação pendente. Faça upload novamente.", "info")
        return redirect(url_for('dashboard'))
    return render_template('escolher_plano.html', conciliacao=conciliacao)

@app.route('/historico')
@login_required
def historico():
    c.execute("SELECT data, total_extrato, total_vendas, divergencia FROM conciliacoes WHERE user_id = ? ORDER BY id DESC", (current_user.id,))
    conciliacoes = c.fetchall()
    return render_template('historico.html', conciliacoes=conciliacoes)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    if not data:
        return '', 400

    if data.get('type') == 'payment':
        payment_id = data.get('data', {}).get('id')
        email = data.get('data', {}).get('metadata', {}).get('email')

        if email:
            c.execute("UPDATE users SET is_pro = 1 WHERE email = ?", (email,))
            conn.commit()
            print(f"Usuário {email} ativado como Pro via webhook!")
            return '', 200

    return '', 200

# Rota para adicionar venda
@app.route('/add_sale', methods=['GET', 'POST'])
@login_required
def add_sale():
    if request.method == 'POST':
        data = request.form.get('data')
        descricao = request.form.get('descricao')
        metodo = request.form.get('metodo_pagamento')
        parcelado = 1 if request.form.get('parcelado') else 0
        parcelas = int(request.form.get('parcelas') or 0)
        valor_bruto = float(limpar_valor(request.form.get('valor_bruto')) or 0)
        taxa_percentual = float(request.form.get('taxa_percentual') or 0)
        taxa_fixa = float(request.form.get('taxa_fixa') or 0)
        status = request.form.get('status')

        # Cálculo automático
        valor_liquido = valor_bruto - (valor_bruto * taxa_percentual / 100) - taxa_fixa
        if parcelado:
            # Exemplo de taxa adicional para antecipação
            taxa_antecipacao = 1.5  # Configurável
            valor_liquido -= (valor_bruto * taxa_antecipacao / 100)

        c.execute("""INSERT INTO sales (user_id, data, descricao, metodo_pagamento, parcelado, parcelas, valor_bruto, taxa_percentual, taxa_fixa, 
                     valor_liquido, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATETIME('now'))""",
                  (current_user.id, data, descricao, metodo, parcelado, parcelas, valor_bruto, taxa_percentual, taxa_fixa, valor_liquido, status))
        conn.commit()
        flash('Venda adicionada com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_sale.html')  # Crie um template com form para os campos

# Rota para exportar relatórios
@app.route('/export/<tipo>', methods=['GET'])
@login_required
def export(tipo):
    if not current_user.is_pro:
        flash('Exportação disponível apenas para usuários Pro.', 'warning')
        return redirect(url_for('dashboard'))

    month = request.args.get('month', datetime.date.today().strftime('%Y-%m'))

    if tipo == 'extrato_mensal':
        c.execute("SELECT * FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ?", (current_user.id, month))
        data = c.fetchall()

    elif tipo == 'relatorio_vendas':
        c.execute("SELECT metodo_pagamento, SUM(valor_bruto), SUM(valor_liquido) FROM sales WHERE user_id = ? AND strftime('%Y-%m', data) = ? GROUP BY metodo_pagamento", (current_user.id, month))
        data = c.fetchall()

    elif tipo == 'resumo_financeiro':
        data = [('Receita', receita_total), ('Despesas', despesas), ('Lucro', lucro_liquido)]  # De dashboard calc

    fmt = request.args.get('format', 'pdf')

    if fmt == 'pdf':
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{tipo}_{month}.pdf')
        gerar_pdf(0, 0, 0, pdf_path, tabela=data, periodo=month)  # Ajuste params
        return send_file(pdf_path, as_attachment=True)

    elif fmt == 'csv':
        df = pd.DataFrame(data)
        csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{tipo}_{month}.csv')
        df.to_csv(csv_path, index=False)
        return send_file(csv_path, as_attachment=True)

    elif fmt == 'xlsx':
        df = pd.DataFrame(data)
        xlsx_path = os.path.join(app.config['UPLOAD_FOLDER'], f'{tipo}_{month}.xlsx')
        df.to_excel(xlsx_path, index=False)
        return send_file(xlsx_path, as_attachment=True)

    return "Formato inválido", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)