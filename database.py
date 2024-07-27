import os

from dotenv import load_dotenv
from peewee_async import PostgresqlDatabase, Manager


load_dotenv()


db = PostgresqlDatabase(
    "testtaskdb",
    user=os.getenv("POSTGRES_USER"),
    password=os.getenv("POSTGRES_PASSWORD"),
    host=os.getenv("POSTGRES_HOST"),
    port=int(os.getenv("POSTGRES_PORT")),
)

objects = Manager(db)
