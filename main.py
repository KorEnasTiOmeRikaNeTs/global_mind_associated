import os
import jwt
import json
import jinja2
import aiohttp_jinja2
from aiohttp import web
from dotenv import load_dotenv

from models import APIUser, Device, Location, create_tables
from database import objects


load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")


create_tables()


app = web.Application()


aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader("templates"))


def create_jwt_token(user_id):
    payload = {"user_id": user_id}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token


@web.middleware
async def auth_middleware(request, handler):
    if request.path in ["/login", "/register"]:
        return await handler(request)

    auth_cookie = request.cookies.get("Authorization")
    if auth_cookie:
        try:
            token = auth_cookie.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request["user_id"] = payload["user_id"]
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return web.json_response({"error": "Invalid token"}, status=401)
    else:
        return web.json_response({"error": "Authorization header missing"}, status=401)

    return await handler(request)


app.middlewares.append(auth_middleware)


@aiohttp_jinja2.template("register_form.html")
async def register_form(request):
    return {}


async def register(request):
    if request.content_type == "application/json":
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
    else:
        data = await request.post()

    if not all(key in data for key in ("name", "email", "password")):
        return web.json_response({"error": "Missing fields"}, status=400)

    hashed_password = APIUser.hash_password(data["password"])
    user = await objects.create(
        APIUser, name=data["name"], email=data["email"], password=hashed_password
    )
    token = create_jwt_token(user.id)

    response = web.HTTPFound("/users/me")
    response.set_cookie("Authorization", f"Bearer {token}", httponly=True)
    return response


@aiohttp_jinja2.template("login_form.html")
async def login_form(request):
    return {}


async def login(request):
    if request.content_type == "application/json":
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
    else:
        data = await request.post()

    user = await objects.get_or_none(APIUser, APIUser.email == data["email"])
    if user and APIUser.verify_password(user.password, data["password"]):
        token = create_jwt_token(user.id)
        response = web.HTTPFound("/users/me")
        response.set_cookie("Authorization", f"Bearer {token}", httponly=True)
        return response
    return web.json_response({"error": "Invalid email or password"}, status=401)


