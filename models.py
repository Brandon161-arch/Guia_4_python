from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy ()

class Usuario (db.Model):
    __tablename__ = "usuarios"
    
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique = True, nullable = False)
    
    password_hash = db.Column(db.String(255), nullable = False)
    rol = db.Column(db.String(20), default="Operario")

    def serializar(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "rol": self.rol,
        }