import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

class Database:
    def __init__(self):
        self.host = os.getenv("DB_HOST")
        self.user = os.getenv("DB_USER")
        self.password = os.getenv("DB_PASSWORD")
        self.database = os.getenv("DB_DATABASE")
        self.connection = None
        self.cursor = None

    def connect(self):
        """Estabelece conexão com o banco de dados."""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            self.cursor = self.connection.cursor(dictionary=True)
            print("✅ Conectado ao banco de dados MySQL!")
        except mysql.connector.Error as err:
            print(f"❌ Erro ao conectar ao banco de dados: {err}")
            self.connection = None
            self.cursor = None

    def close(self):
        """Fecha a conexão com o banco de dados."""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
            print("🔒 Conexão MySQL fechada.")

    def execute_query(self, query, params=None):
        """Executa uma query SQL (SELECT ou INSERT/UPDATE/DELETE)."""
        if not self.connection or not self.connection.is_connected():
            self.connect()
            if not self.connection:
                print("❌ Não foi possível estabelecer conexão com o banco de dados.")
                return None

        try:
            self.cursor.execute(query, params)
            if query.strip().upper().startswith("SELECT"):
                result = self.cursor.fetchall()
                return result
            else:
                self.connection.commit()
                return self.cursor.rowcount
        except mysql.connector.Error as err:
            print(f"⚠️ Erro ao executar query: {err}")
            self.connection.rollback()
            return None

# Instância global do banco
db = Database()

def init_db_schema():
    """Cria a tabela users caso não exista."""
    create_table_query = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nome VARCHAR(100) NOT NULL,
        sobrenome VARCHAR(100),
        cpf VARCHAR(11),
        email VARCHAR(100) UNIQUE NOT NULL,
        id_cartao VARCHAR(50),
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('admin', 'voluntario') NOT NULL DEFAULT 'voluntario'
    )
    """
    db.execute_query(create_table_query)
    print("🧩 Verificação do esquema do banco de dados para 'users' concluída.")
