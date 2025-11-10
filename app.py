from flask import Flask, render_template, request, redirect, url_for, flash
from models.database import db, init_db_schema
import threading
import paho.mqtt.client as mqtt
from flask_login import (LoginManager, UserMixin, login_user, login_required,logout_user, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import os, json, random
from flask import jsonify
from dotenv import load_dotenv
from models.users import User
import mysql.connector
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from flask import make_response
from werkzeug.utils import secure_filename


# --- Configuração base ---
app = Flask(__name__, template_folder="templates")
app.secret_key = "pedro_eas_gurias"  # troque em produção

# Caminho relativo (sem o "static")
app.config["UPLOAD_FOLDER"] = os.path.join("uploads", "pdfs")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # limite de 16MB por arquivo
ALLOWED_EXTENSIONS = {"pdf"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


ultimo_cartao_lido = None

login_manager = LoginManager(app)
login_manager.login_view = "login"


with app.app_context(): # Inicializa o banco de dados ao iniciar o app
    db.connect()
    init_db_schema()

@app.before_request
def before_request_func(): #antes do mqtt pedir algo, ele vê se esta conectado ao banco
    if not db.connection or not db.connection.is_connected():
        db.connect()

'''@app.after_request
def after_request_func(response): #depois de o mqtt pedir algo, ele fecha a conexão com o banco
    db.close()
    return response'''

def init_users():
    db.connect()
    User.create_admin_if_not_exists()

@login_manager.user_loader
def load_user(user_id):
    cursor = db.connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    data = cursor.fetchone()
    cursor.close()
    if not data:
        return None
    return User(**data)

@app.route("/usuarios/<int:id>/editar", methods=["GET", "POST"])
@login_required
def usuarios_editar(id):
    # Busca o usuário pelo ID no banco
    query_select = "SELECT * FROM users WHERE id = %s"
    user_data = db.execute_query(query_select, (id,))

    if not user_data:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("dashboard"))

    user = user_data[0]

    # Se for POST, atualiza os dados no banco
    if request.method == "POST":
        nome = request.form.get("nome")
        sobrenome = request.form.get("sobrenome")
        cpf = request.form.get("cpf")
        email = request.form.get("email")
        id_cartao = request.form.get("id_cartao") or None
        papel = request.form.get("papel") or user["role"]
        senha = request.form.get("senha", "")
        senha_hash = None 
        data_nascimento = request.form.get("data_nascimento") or None
        
        if senha:   
            senha_hash = generate_password_hash(senha)
            query_update = """
                UPDATE users 
                SET nome = %s, sobrenome = %s, cpf = %s, email = %s, id_cartao = %s, role = %s, data_nascimento = %s, password_hash = %s
                WHERE id = %s
            """
            params = (nome, sobrenome, cpf, email, id_cartao, papel, data_nascimento, senha_hash, id)

        else:
            query_update = """
                UPDATE users 
                SET nome = %s, sobrenome = %s, cpf = %s, email = %s, id_cartao = %s, role = %s, data_nascimento = %s
                WHERE id = %s
            """
            params = (nome, sobrenome, cpf, email, id_cartao, papel, data_nascimento, id)

        result = db.execute_query(query_update, params)

        if result is not None:
            flash("Usuário atualizado com sucesso!", "success")
        else:
            flash("Erro ao atualizar usuário.", "danger")

        return redirect(url_for("usuarios"))

    # 🔸 Se for GET, mostra o formulário preenchido
    return render_template("usuario_form.html", usuario=user)

@app.route("/voluntarios/<int:id>/editar", methods=["GET", "POST"])
@login_required
def voluntarios_editar(id):
    # Busca o usuário pelo ID no banco
    query_select = "SELECT * FROM users WHERE id = %s AND role = 'voluntario'"
    user_data = db.execute_query(query_select, (id,))

    if not user_data:
        flash("Voluntário não encontrado.", "error")
        return redirect(url_for("dashboard"))

    user = user_data[0]

    if request.method == "POST":
        nome = request.form.get("nome")
        sobrenome = request.form.get("sobrenome")
        cpf = request.form.get("cpf")
        email = request.form.get("email")
        id_cartao = request.form.get("id_cartao") or None
        papel = request.form.get("papel") or user["role"]
        senha = request.form.get("senha", "")
        data_nascimento = request.form.get("data_nascimento") or None

        # PDFs
        pdf1 = request.files.get("pdf1")
        pdf2 = request.files.get("pdf2")
        pdf3 = request.files.get("pdf3")

        # Pasta de uploads
        upload_folder = os.path.join(app.static_folder, "uploads", "voluntarios")
        os.makedirs(upload_folder, exist_ok=True)

        pdf1_path = user.get("pdf1_path")
        pdf2_path = user.get("pdf2_path")
        pdf3_path = user.get("pdf3_path")

        # Se um novo PDF for enviado, substitui o antigo
        if pdf1 and pdf1.filename != "":
            filename1 = secure_filename(pdf1.filename)
            save_path1 = os.path.join(upload_folder, filename1)
            pdf1.save(save_path1)
            pdf1_path = os.path.relpath(save_path1, app.static_folder).replace("\\", "/")

        if pdf2 and pdf2.filename != "":
            filename2 = secure_filename(pdf2.filename)
            save_path2 = os.path.join(upload_folder, filename2)
            pdf2.save(save_path2)
            pdf2_path = os.path.relpath(save_path2, app.static_folder).replace("\\", "/")

        if pdf3 and pdf3.filename != "":
            filename3 = secure_filename(pdf3.filename)
            save_path3 = os.path.join(upload_folder, filename3)
            pdf3.save(save_path3)
            pdf3_path = os.path.relpath(save_path3, app.static_folder).replace("\\", "/")

        # Atualiza a senha se o campo não estiver vazio
        if senha:
            senha_hash = generate_password_hash(senha)
            query_update = """
                UPDATE users 
                SET nome = %s, sobrenome = %s, cpf = %s, email = %s,
                    id_cartao = %s, role = %s, password_hash = %s, data_nascimento = %s,
                    pdf1_path = %s, pdf2_path = %s, pdf3_path = %s
                WHERE id = %s
            """
            params = (
                nome, sobrenome, cpf, email, id_cartao, papel, senha_hash, data_nascimento,
                pdf1_path, pdf2_path, pdf3_path, id
            )
        else:
            query_update = """
                UPDATE users 
                SET nome = %s, sobrenome = %s, cpf = %s, email = %s,
                    id_cartao = %s, role = %s, data_nascimento = %s,
                    pdf1_path = %s, pdf2_path = %s, pdf3_path = %s
                WHERE id = %s
            """
            params = (
                nome, sobrenome, cpf, email, id_cartao, papel, data_nascimento,
                pdf1_path, pdf2_path, pdf3_path, id
            )

        result = db.execute_query(query_update, params)

        if result is not None:
            flash("Voluntário atualizado com sucesso!", "success")
        else:
            flash("Erro ao atualizar voluntário.", "danger")

        return redirect(url_for("voluntarios"))

    # Se for GET, mostra o formulário preenchido
    return render_template("voluntario_form.html", voluntario=user)


@app.route("/usuarios/<int:id>/excluir", methods=["POST", "GET"])
@login_required
def usuarios_excluir(id):
    # Verifica se o usuário existe antes de tentar excluir
    query_check = "SELECT * FROM users WHERE id = %s"
    user = db.execute_query(query_check, (id,))

    if not user:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("dashboard"))

    # Executa a exclusão
    query_delete = "DELETE FROM users WHERE id = %s"
    result = db.execute_query(query_delete, (id,))

    if result and result > 0:
        flash("Usuário excluído com sucesso!", "success")
    else:
        flash("Erro ao excluir usuário.", "danger")

    return redirect(url_for("dashboard"))


# --- Middleware: protege tudo que não for login/register/static ---
@login_manager.unauthorized_handler
def unauthorized():
    flash("Faça login para continuar.", "error")
    return redirect(url_for("login"))

@app.before_request
def require_login_for_everything():
    public_endpoints = {"login", "register", "static"}
    if request.endpoint is None:
        return
    if request.endpoint.split(".")[0] not in public_endpoints and not current_user.is_authenticated:
        return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nome = request.form.get("name", "").strip()
        sobrenome = request.form.get("lastname", "").strip()
        cpf = request.form.get("cpf", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not nome or not email or not password:
            flash("Preencha todos os campos obrigatórios.", "error")
            return render_template("register.html")

        query_check = "SELECT * FROM users WHERE email = %s"
        existing_user = db.execute_query(query_check, (email,))
        if existing_user:
            flash("Já existe uma conta com este e-mail.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)
        query_insert = """
            INSERT INTO users (nome, sobrenome, cpf, email, password_hash, role, ativo)
            VALUES (%s, %s, %s, %s, %s, 'voluntario', 1)
        """
        db.execute_query(query_insert, (nome, sobrenome, cpf, email, password_hash))

        # Busca o usuário recém-criado
        novo_user = db.execute_query("SELECT * FROM users WHERE email = %s", (email,))
        if novo_user:
            user_data = novo_user[0]
            user = User(
                id=user_data["id"],
                nome=user_data.get("nome"),
                sobrenome=user_data.get("sobrenome"),
                email=user_data["email"],
                password_hash=user_data["password_hash"],
                role=user_data["role"],
                cpf=user_data.get("cpf"),
                id_cartao=user_data.get("id_cartao"),
                ativo=user_data.get("ativo", 1)
            )
            login_user(user)
            flash("Conta criada com sucesso!", "success")
            return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # busca o usuário no banco
        query = "SELECT * FROM users WHERE email = %s"
        result = db.execute_query(query, (email,))

        if not result:
            flash("E-mail ou senha incorretos.", "error")
            return render_template("login.html")

        user_data = result[0]

        # verifica a senha
        if not check_password_hash(user_data["password_hash"], password):
            flash("E-mail ou senha incorretos.", "error")
            return render_template("login.html")

        # cria o objeto User (necessário para o Flask-Login)
        user = User(
            id=user_data.get("id"),
            nome=user_data.get("nome", ""),
            sobrenome=user_data.get("sobrenome", ""),  # 👈 agora não quebra
            email=user_data.get("email", ""),
            password_hash=user_data.get("password_hash", ""),
            role=user_data.get("role", ""),
            cpf=user_data.get("cpf"),
            id_cartao=user_data.get("id_cartao"),
            ativo=user_data.get("ativo", 1)
        )

        login_user(user)
        flash("Login realizado com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Sessão encerrada.", "success")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    hoje = date.today()
    # 1. Número de voluntários ativos
    voluntarios_ativos_query = """
        SELECT COUNT(*) AS total 
        FROM users 
        WHERE role = 'voluntario' AND ativo = 1
    """

    result = db.execute_query(voluntarios_ativos_query)
    voluntarios_ativos = result[0]["total"] if result else 0

    # 2. Presenças registradas hoje
    presencas_query = """
        SELECT COUNT(*) AS total
        FROM historico
        WHERE DATE(horario) = CURDATE()
    """

    result = db.execute_query(presencas_query)
    presencas_hoje = result[0]["total"] if result else 0

    # 3. Dispositivos online
    dispositivos_query = "SELECT COUNT(*) AS total FROM devices WHERE online = 1"
    try:
        result = db.execute_query(dispositivos_query)
        dispositivos_online = result[0]["total"] if result else 0
    except Exception as e:
        print("⚠️ Erro ao consultar dispositivos online:", e)
        dispositivos_online = 0  # caso a tabela devices ainda não exista
    
    aniversariantes_query = """
        SELECT nome, sobrenome
        FROM users
        WHERE data_nascimento IS NOT NULL
          AND DAY(data_nascimento) = %s
          AND MONTH(data_nascimento) = %s
    """
    aniversariantes = db.execute_query(aniversariantes_query, (hoje.day, hoje.month)) or []


    # 4. Retorna tudo pro template direto
    return render_template(
        "dashboard.html",
        voluntarios_ativos=voluntarios_ativos,
        presencas_hoje=presencas_hoje,
        dispositivos_online=dispositivos_online,
        aniversariantes= aniversariantes,
        current_user=current_user
    )


@app.route("/usuarios")
@login_required
def usuarios():
    if current_user.role != "admin":
        flash("Apenas administradores podem ver usuários.", "error")
        return redirect(url_for("dashboard"))

    query = "SELECT id, nome, sobrenome, email, cpf, id_cartao, role FROM users"
    usuarios_db = db.execute_query(query)

    return render_template("usuarios_list.html", usuarios=usuarios_db)

@app.route("/usuarios/novo", methods=["GET", "POST"])
@login_required
def usuarios_novo():
    # ✅ Só administradores podem cadastrar novos usuários
    if not current_user.role == "admin":
        flash("Apenas administradores podem criar usuários.", "error")
        return redirect(url_for("usuarios"))

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        sobrenome = request.form.get("sobrenome", "").strip()
        email = request.form.get("email", "").strip().lower()
        papel = request.form.get("papel", "voluntario")
        senha = request.form.get("senha", "").strip()
        data_nascimento = request.form.get("data_nascimento") or None

        # 🔸 Validação básica
        if not nome or not email or not senha:
            flash("Preencha nome, e-mail e senha.", "error")
            return render_template("usuario_form.html")

        # 🔸 Verifica se já existe um usuário com esse e-mail
        existing_user = db.execute_query("SELECT * FROM users WHERE email = %s", (email,))
        if existing_user:
            flash("Já existe um usuário com este e-mail.", "error")
            return render_template("usuario_form.html")

        # 🔸 Cria o novo usuário no banco
        senha_hash = generate_password_hash(senha)
        query = """
                INSERT INTO users (nome, sobrenome, email, role, password_hash, ativo, data_nascimento)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
        db.execute_query(query, (nome, sobrenome, email, papel, senha_hash, 1, data_nascimento))

        flash("Usuário criado com sucesso!", "success")
        return redirect(url_for("usuarios"))

    # Se for GET, só mostra o formulário
    return render_template("usuario_form.html")

@app.route("/usuarios/<int:id>/ver")
@login_required
def usuarios_ver(id):
    query = "SELECT * FROM users WHERE id = %s"
    user_data = db.execute_query(query, (id,))

    if not user_data:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("usuarios"))

    usuario = user_data[0]

    return render_template("usuario_ver.html", usuario=usuario)


@app.route('/cadastrar_cartao/<int:user_id>', methods=['GET', 'POST'])
def cadastrar_cartao(user_id):
    # Pega o usuário do banco
    query = "SELECT * FROM users WHERE id = %s"
    usuario = db.execute_query(query, (user_id,))
    if not usuario:
        flash('Usuário não encontrado!', 'danger')
        return redirect(url_for('dashboard'))
    user = usuario

    if request.method == 'POST':
        id_cartao = request.form['id_cartao']
        # Atualiza o usuário com o cartão
        query_update = "UPDATE users SET id_cartao = %s WHERE id = %s"
        db.execute_query(query_update, (id_cartao, user_id))
        flash(f'Cartão {id_cartao} cadastrado para {user["nome"]}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('cadastrar_cartao.html', user=user)

@app.route('/cartao_atual')
def cartao_atual():
    global ultimo_cartao_lido
    return jsonify({"id_cartao": ultimo_cartao_lido})


@app.route('/registrar_acao/<acao>')
@login_required
def registrar_acao(acao):
    query = """
        INSERT INTO historico (user_id, nome, cpf, email, acao, horario)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    values = (
        current_user.id,
        current_user.nome,
        getattr(current_user, "cpf", ""),  # caso não tenha o atributo CPF
        current_user.email,
        acao.capitalize(),
        datetime.now()
    )
    db.execute_query(query, values)

    flash(f"Ação '{acao}' registrada com sucesso!", "success")
    return redirect(url_for('ponto'))

@app.route("/voluntarios")
@login_required
def voluntarios():
    query = "SELECT * FROM users WHERE role = 'voluntario'"
    voluntarios = db.execute_query(query)
    return render_template("voluntarios_list.html", voluntarios=voluntarios)

@app.route("/voluntarios/<int:id>/ver")
@login_required
def voluntarios_ver(id):
    query = "SELECT * FROM users WHERE id = %s AND role = 'voluntario'"
    voluntario_data = db.execute_query(query, (id,))

    if not voluntario_data:
        flash("Voluntário não encontrado.", "error")
        return redirect(url_for("voluntarios"))

    voluntario = voluntario_data[0]

    return render_template("voluntario_ver.html", voluntario=voluntario)



@app.route("/voluntarios/novo", methods=["GET", "POST"])
@login_required
def voluntarios_novo():
    if current_user.role != "admin":
        flash("Apenas administradores podem cadastrar voluntários.", "error")
        return redirect(url_for("voluntarios"))

    if request.method == "POST":
        nome = request.form.get("nome")
        email = request.form.get("email")
        senha = request.form.get("senha")
        id_cartao = request.form.get("id_cartao") or None
        data_nascimento = request.form.get("data_nascimento") or None
        pdf1 = request.files.get("pdf1")
        pdf2 = request.files.get("pdf2")
        pdf3 = request.files.get("pdf3")

        if not nome or not email or not senha:
            flash("Preencha todos os campos.", "error")
            return render_template("voluntario_form.html", voluntario=None)

        # Pasta de upload dentro da pasta static
        upload_folder = os.path.join(app.root_path, "static", "uploads", "voluntarios")
        os.makedirs(upload_folder, exist_ok=True)

        # PDF 1
        pdf1_path = None
        if pdf1 and pdf1.filename != "":
            filename1 = secure_filename(pdf1.filename)
            save_path1 = os.path.join(app.static_folder, "uploads", "voluntarios", filename1)
            os.makedirs(os.path.dirname(save_path1), exist_ok=True)
            pdf1.save(save_path1)
            # Garante que o caminho no banco NÃO começa com 'static/'
            pdf1_path = os.path.relpath(save_path1, app.static_folder).replace("\\", "/")

        # PDF 2
        pdf2_path = None
        if pdf2 and pdf2.filename != "":
            filename2 = secure_filename(pdf2.filename)
            save_path2 = os.path.join(app.static_folder, "uploads", "voluntarios", filename2)
            os.makedirs(os.path.dirname(save_path2), exist_ok=True)
            pdf2.save(save_path2)
            pdf2_path = os.path.relpath(save_path2, app.static_folder).replace("\\", "/")

        # PDF 3
        pdf3_path = None
        if pdf3 and pdf3.filename != "":
            filename3 = secure_filename(pdf3.filename)
            save_path3 = os.path.join(app.static_folder, "uploads", "voluntarios", filename3)
            os.makedirs(os.path.dirname(save_path3), exist_ok=True)
            pdf3.save(save_path3)
            pdf3_path = os.path.relpath(save_path3, app.static_folder).replace("\\", "/")



        # Inserir no banco
        query = """
            INSERT INTO users (nome, email, password_hash, role, id_cartao, data_nascimento, pdf1_path, pdf2_path, pdf3_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            nome,
            email,
            generate_password_hash(senha),
            "voluntario",
            id_cartao,
            data_nascimento,
            pdf1_path,
            pdf2_path,
            pdf3_path
        )
        db.execute_query(query, values)

        flash("Voluntário cadastrado com sucesso!", "success")
        return redirect(url_for("voluntarios"))

    return render_template("voluntario_form.html", voluntario=None)


@app.route("/iot")
def iot_dashboard():
    db.close()
    db.connect()
    query = "SELECT * FROM devices ORDER BY nome ASC"
    dispositivos = db.execute_query(query) or []
    return render_template("iot.html", dispositivos=dispositivos)

@app.route("/relatorios")
@login_required
def relatorios():
    query = """
        SELECT nome, acao, horario
        FROM historico
        ORDER BY horario DESC
    """
    registros = db.execute_query(query)

    # opcional: agrupar por usuário ou contar ações
    resumo = {}
    for r in registros:
        nome = r["nome"]
        resumo[nome] = resumo.get(nome, 0) + 1

    return render_template("relatorios.html", registros=registros, resumo=resumo)

@app.route("/suporte")
@login_required
def suporte():
    return render_template("suporte.html", ava_url="https://www.pucpr.br/ava/")

@app.route("/ponto")
def ponto():
    db.close()
    db.connect()

    # Busca os registros mais recentes
    registros = db.execute_query(
        "SELECT nome, cpf, email, acao, horario FROM historico ORDER BY horario DESC"
    ) or []

    return render_template("ponto.html", registros=registros)

@app.route("/ponto/pdf")
@login_required
def gerar_pdf_historico():
    # 🔸 Consulta os registros do banco
    registros = db.execute_query(
        "SELECT nome, cpf, email, acao, horario FROM historico ORDER BY horario DESC"
    ) or []

    # 🔸 Cria o buffer de bytes
    buffer = BytesIO()

    # 🔸 Define o documento
    pdf = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elementos = []

    # 🔹 Título
    elementos.append(Paragraph("<b>Relatório de Histórico de Ações</b>", styles["Title"]))
    elementos.append(Spacer(1, 12))

    # 🔹 Cabeçalhos da tabela
    dados = [["Nome", "CPF", "Email", "Ação", "Horário"]]

    # 🔹 Adiciona linhas da tabela
    for r in registros:
        dados.append([
            r["nome"],
            r.get("cpf", "-"),
            r["email"],
            r["acao"].capitalize(),
            str(r["horario"])
        ])

    # 🔹 Cria a tabela com estilo
    tabela = Table(dados, repeatRows=1)
    tabela.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))

    elementos.append(tabela)

    # 🔹 Constrói o PDF
    pdf.build(elementos)

    # 🔹 Retorna o PDF para download
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename=historico.pdf'

    return response


# ------------------ MQTT CLIENT ------------------
# 🔧 Configurações do broker local
BROKER = "localhost"
PORTA = 1884
TOPICO = "hospital/ponto/voluntarios"

# Dicionário para acompanhar o status de entrada/saída por ID
status_voluntarios = {}

def ao_conectar(client, userdata, flags, rc): #se o codigo de retorno for 0, conectou
    if rc == 0:
        print(f"✅ Conectado ao broker MQTT (porta {PORTA})")
        client.subscribe(TOPICO)
    else:
        print("❌ Falha na conexão. Código:", rc)

def get_mqtt_db_connection():
    """Cria uma nova conexão exclusiva para o MQTT."""
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="isamanu0608@",
        database="cajuru_com_interface"
    )

def ao_mensagem(client, userdata, msg):
    """Processa mensagens MQTT com tratamento correto de conexões"""
    global ultimo_cartao_lido
    
    # Parse da mensagem
    try:
        dados = json.loads(msg.payload.decode())
        tipo = dados.get("tipo", "rfid")
    except Exception as e:
        print("⚠️ Mensagem inválida recebida:", msg.payload.decode())
        return

    hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Cria conexão e cursor com tratamento adequado
    mqtt_db = None
    cursor = None
    
    try:
        mqtt_db = get_mqtt_db_connection()
        cursor = mqtt_db.cursor(dictionary=True, buffered=True)  # buffered=True previne erros
        
        # --- Caso 1: RFID detectado ---
        if tipo == "rfid":
            id_cartao = dados.get("id", "desconhecido")
            ultimo_cartao_lido = id_cartao

            cursor.execute("SELECT * FROM users WHERE id_cartao = %s", (id_cartao,))
            usuario = cursor.fetchone()
            
            if usuario:
                user_id = usuario["id"]
                nome = usuario["nome"]
                cpf = usuario.get("cpf", "")
                email = usuario["email"]

                # Determina ação (entrada/saída)
                acao = "entrada" if status_voluntarios.get(id_cartao) != "entrada" else "saida"
                status_voluntarios[id_cartao] = acao

                # Insere no histórico
                cursor.execute(
                    "INSERT INTO historico (user_id, nome, cpf, email, acao, horario) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (user_id, nome, cpf, email, acao, hora)
                )
                mqtt_db.commit()

                # Atualiza dispositivo
                cursor.execute(
                    "UPDATE devices SET ultima_comunicacao = %s WHERE nome = 'Módulo RFID'",
                    (hora,)
                )
                mqtt_db.commit()

                print(f"✅ {hora} - {nome} registrou {acao.upper()} com cartão {id_cartao}")
            else:
                print(f"⚠️ {hora} - RFID {id_cartao} não cadastrado!")

        # --- Caso 2: CPF completo enviado ---
        elif tipo == "cpf":
            cpf = dados.get("cpf", "desconhecido")
            
            cursor.execute("SELECT * FROM users WHERE cpf = %s", (cpf,))
            usuario = cursor.fetchone()
            
            if usuario:
                user_id = usuario["id"]
                nome = usuario["nome"]
                email = usuario["email"]

                # Determina ação (entrada/saída)
                acao = "entrada" if status_voluntarios.get(cpf) != "entrada" else "saida"
                status_voluntarios[cpf] = acao

                # Insere no histórico
                cursor.execute(
                    "INSERT INTO historico (user_id, nome, cpf, email, acao, horario) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (user_id, nome, cpf, email, acao, hora)
                )
                mqtt_db.commit()

                # Atualiza dispositivo
                cursor.execute(
                    "UPDATE devices SET ultima_comunicacao = %s WHERE nome = 'Teclado matricial'",
                    (hora,)
                )
                mqtt_db.commit()

                print(f"✅ {hora} - {nome} CPF {cpf} registrou {acao.upper()}")
            else:
                print(f"⚠️ {hora} - CPF {cpf} não cadastrado!")
    
    except mysql.connector.Error as db_error:
        print(f"❌ Erro no banco de dados: {db_error}")
        if mqtt_db:
            mqtt_db.rollback()
    
    except Exception as e:
        print(f"❌ Erro inesperado no MQTT: {e}")
    
    finally:
        # SEMPRE fecha recursos na ordem correta
        if cursor:
            cursor.close()
        if mqtt_db and mqtt_db.is_connected():
            mqtt_db.close()

# 🚀 Cria o cliente MQTT
def iniciar_mqtt():
    cliente = mqtt.Client()
    cliente.on_connect = ao_conectar
    cliente.on_message = ao_mensagem

# 🔌 Conecta e escuta
    try:
        cliente.connect(BROKER, PORTA, 60)
        print("🔄 Aguardando dados do ESP32 (RFID + Teclado)...\n")
        cliente.loop_forever()
    except Exception as e:
        print("❌ Erro ao conectar:", e)

if __name__ == '__main__':
    # Rodar MQTT em uma thread separada
    print("🔥 Thread MQTT sendo iniciada...")
    t = threading.Thread(target=iniciar_mqtt)
    t.daemon = True
    t.start()

    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
