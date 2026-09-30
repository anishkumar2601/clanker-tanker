import os
import sqlite3
import subprocess


def search_users(username: str):
    # Intentional harmless fixture: user input is interpolated into SQL.
    query = f"SELECT * FROM users WHERE name = '{username}'"
    connection = sqlite3.connect("demo.db")
    return connection.execute(query).fetchall()


def ping_host(host: str):
    # Intentional harmless fixture: shell command is assembled from input.
    os.system("echo Pinging " + host)

