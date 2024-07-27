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


async def get_user(request):
    user_id = request["user_id"]
    user = await objects.get_or_none(APIUser, APIUser.id == user_id)
    if user:
        return web.json_response(
            {"id": user.id, "name": user.name, "email": user.email}
        )
    return web.json_response({"error": "User not found"}, status=404)


async def create_device(request):
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    required_fields = ["name", "type", "login", "password", "location_name"]
    if not all(field in data for field in required_fields):
        return web.json_response({"error": "Missing fields"}, status=400)

    hashed_password = Device.hash_password(data["password"])

    location_or_none = await objects.get_or_none(
        Location, Location.name == data["location_name"]
    )
    if location_or_none is None:
        location_or_none = await objects.create(Location, name=data["location_name"])

    device = await objects.create(
        Device,
        name=data["name"],
        type=data["type"],
        login=data["login"],
        password=hashed_password,
        location=location_or_none.id,
        api_user=request["user_id"],
    )
    return web.HTTPFound(f"/devices/{device.id}")


async def get_device(request):
    device_id = int(request.match_info["id"])
    device = await objects.get_or_none(Device, Device.id == device_id)
    if device:
        return web.json_response(
            {
                "id": device.id,
                "name": device.name,
                "type": device.type,
                "login": device.login,
                "location_name": device.location.name,
                "api_user_name": device.api_user.name,
            }
        )
    return web.json_response({"error": "Device not found"}, status=404)


async def update_device(request):
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    device_id = int(request.match_info["id"])

    update_fields = {
        Device.name: data.get("name"),
        Device.type: data.get("type"),
        Device.login: data.get("login"),
        Device.api_user: request["user_id"],
    }

    if data.get("location_name"):
        location_or_none = await objects.get_or_none(
            Location, Location.name == data.get("location_name")
        )
        if location_or_none is None:
            location_or_none = await objects.create(
                Location, name=data.get("location_name")
            )
        update_fields.update({Device.location: location_or_none.id})

    update_fields = {
        key: value for key, value in update_fields.items() if value is not None
    }

    if not update_fields:
        return web.json_response({"error": "No fields to update"}, status=400)

    query = Device.update(update_fields).where(Device.id == device_id)
    rows_affected = await objects.execute(query)

    if rows_affected:
        device = await objects.get(Device, Device.id == device_id)
        return web.HTTPFound(f"/devices/{device.id}")
    return web.json_response({"error": "Device not found"}, status=404)


async def upd_device_password(request):
    try:
        data = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    device_id = int(request.match_info["id"])

    required_fields = ["old_password", "new_password"]
    if not all(field in data for field in required_fields):
        return web.json_response({"error": "Missing fields"}, status=400)

    user = await objects.get_or_none(APIUser, APIUser.id == request["user_id"])

    if user and Device.verify_password(user.password, data["old_password"]):

        hashed_password = Device.hash_password(data["new_password"])
        query = Device.update({Device.password: hashed_password}).where(
            Device.id == device_id
        )

        rows_affected = await objects.execute(query)

        if rows_affected:
            device = await objects.get(Device, Device.id == device_id)
            return web.HTTPFound(f"/devices/{device.id}")
        return web.json_response({"error": "Device not found"}, status=404)

    return web.json_response({"error": "Invalid old_password"}, status=401)


async def delete_device(request):
    device_id = int(request.match_info["id"])
    query = Device.delete().where(Device.id == device_id)

    rows_deleted = await objects.execute(query)
    if rows_deleted:
        return web.json_response({"message": "Device deleted"})
    return web.json_response({"error": "Device not found"}, status=404)


app.router.add_get("/register", register_form)
app.router.add_post("/register", register)
app.router.add_get("/login", login_form)
app.router.add_post("/login", login)
app.router.add_get("/users/me", get_user)

app.router.add_post("/devices/create", create_device)
app.router.add_get("/devices/{id}", get_device)
app.router.add_put("/devices/{id}", update_device)
app.router.add_delete("/devices/{id}", delete_device)
app.router.add_put("/devices/{id}/update_password", upd_device_password)


if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8080)
