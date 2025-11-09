from models.database import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, nome, sobrenome=None, email=None, password_hash=None, role=None, cpf=None, id_cartao=None, ativo=1, data_nascimento=None, pdf1_path=None, pdf2_path=None, pdf3_path=None):
        self.id = id
        self.nome = nome
        self.sobrenome = sobrenome
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.cpf = cpf
        self.id_cartao = id_cartao
        self.ativo = bool(ativo)
        self.data_nascimento = data_nascimento
        self.pdf1_path = pdf1_path
        self.pdf2_path = pdf2_path
        self.pdf3_path = pdf3_path
        


    @property
    def is_active(self):
        return self.ativo == 1
    
    @property
    def is_admin(self):
        return self.role == 'admin'

    @classmethod
    def find_by_email(cls, email):
        cursor = db.connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        data = cursor.fetchone()
        cursor.close()
        return cls(**data) if data else None

    @classmethod
    def create(cls, nome, sobrenome, email, password, role='voluntario', ativo=1):
        cursor = db.connection.cursor()
        hash_ = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (nome, sobrenome, email, password_hash, role, ativo) VALUES (%s, %s, %s, %s, %s, %s)",
            (nome, sobrenome, email, hash_, role, ativo)
        )
        db.connection.commit()
        cursor.close()

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_voluntarios_ativos():
        query = "SELECT COUNT(*) AS total FROM users WHERE role = 'voluntario' AND ativo = 1"
        result = db.execute_query(query)
        return result[0]['total'] if result else 0

    @staticmethod
    def get_presencas_hoje():
        query = """
        SELECT COUNT(*) AS total
        FROM historico
        WHERE DATE(horario) = CURDATE()
        """
        result = db.execute_query(query)
        return result[0]['total'] if result else 0
    
    def create_admin_if_not_exists():
        cursor = db.connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE role = 'admin'")
        admin = cursor.fetchone()

        # se não existir admin, cria um padrão
        if not admin:
            from werkzeug.security import generate_password_hash
            senha_hash = generate_password_hash("admin123")
            cursor.execute("""
                INSERT INTO users (nome, sobrenome, email, password_hash, role, ativo)
                VALUES (%s, %s, %s, %s, %s, 1)
            """, ("Administrador", "", "admin@admin.com", senha_hash, "admin"))
            db.connection.commit()
            print("✅ Usuário admin criado: admin@admin.com / senha: admin123")

        cursor.close()


