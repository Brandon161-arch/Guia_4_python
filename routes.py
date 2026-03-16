from flask import Blueprint, request, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from models import db, Usuario, Producto

api_bp = Blueprint('api', __name__)

# -----------------------------
# REGISTRAR USUARIO
# -----------------------------
@api_bp.route('/usuarios/registrar', methods=['POST'])
def registrar_usuario() -> tuple[Response, int]:
    try:
        payload = request.get_json()

        clave_segura = generate_password_hash(payload['password'])

        nuevo_user = Usuario(
            username=payload['username'],
            password_hash=clave_segura,
            rol=payload.get('rol', 'Operario')
        )

        db.session.add(nuevo_user)
        db.session.commit()

        return jsonify({
            "mensaje": "Éxito",
            "data": nuevo_user.serializar()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "error": "Fallo de integridad",
            "detalle": str(e)
        }), 400


# -----------------------------
# LISTAR USUARIOS
# -----------------------------
@api_bp.route('/usuarios', methods=['GET'])
def listar_usuarios() -> tuple[Response, int]:

    pagina = request.args.get('page', 1, type=int)

    paginacion = Usuario.query.paginate(
        page=pagina,
        per_page=10,
        error_out=False
    )

    resultado = [u.serializar() for u in paginacion.items]

    return jsonify({
        "pagina_actual": paginacion.page,
        "total_paginas": paginacion.pages,
        "usuarios": resultado
    }), 200


# -----------------------------
# LOGIN
# -----------------------------
@api_bp.route('/login', methods=['POST'])
def login() -> tuple[Response, int]:

    payload = request.get_json()

    usuario = Usuario.query.filter_by(
        username=payload.get('username')
    ).first()

    if usuario and check_password_hash(
        usuario.password_hash,
        payload.get('password')
    ):

        token_acceso = create_access_token(
            identity=usuario.username,
            additional_claims={
                "rol": usuario.rol
            }
        )

        return jsonify({
            "mensaje": "Login exitoso",
            "token": token_acceso
        }), 200

    return jsonify({
        "error": "Credenciales inválidas"
    }), 401


# -----------------------------
# CREAR PRODUCTO (SOLO ADMIN)
# -----------------------------
@api_bp.route('/productos', methods=['POST'])
@jwt_required()
def crear_producto() -> tuple[Response, int]:

    claims = get_jwt()

    if claims["rol"] != "Admin":
        return jsonify({
            "error": "Forbidden: Requiere privilegios de Administrador"
        }), 403

    payload = request.get_json()

    nuevo_producto = Producto(
        nombre=payload["nombre"],
        precio=payload["precio"]
    )

    db.session.add(nuevo_producto)
    db.session.commit()

    return jsonify({
        "mensaje": "Producto creado",
        "producto": nuevo_producto.serializar()
    }), 201