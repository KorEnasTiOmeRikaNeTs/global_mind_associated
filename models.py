import bcrypt
from peewee import Model, TextField, ForeignKeyField

from database import db


class BaseModel(Model):
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def verify_password(stored_password, provided_password):
        return bcrypt.checkpw(
            provided_password.encode("utf-8"), stored_password.encode("utf-8")
        )

    class Meta:
        database = db


class APIUser(BaseModel):
    name = TextField()
    email = TextField(unique=True)
    password = TextField()


class Location(BaseModel):
    name = TextField(unique=True)


class Device(BaseModel):
    name = TextField()
    type = TextField()
    login = TextField()
    password = TextField()
    api_user = ForeignKeyField(APIUser, backref="devices")
    location = ForeignKeyField(Location, backref="devices")


def create_tables():
    with db:
        db.create_tables([APIUser, Location, Device])


if __name__ == "__main__":
    create_tables()
