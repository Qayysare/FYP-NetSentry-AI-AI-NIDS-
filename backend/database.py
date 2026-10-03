from contextlib import contextmanager
import mysql.connector
from mysql.connector import Error
from flask import current_app


def get_connection():
    """Create one MySQL connection using the application's configuration."""
    return mysql.connector.connect(
        host=current_app.config["DB_HOST"], port=current_app.config["DB_PORT"],
        database=current_app.config["DB_NAME"], user=current_app.config["DB_USER"],
        password=current_app.config["DB_PASSWORD"],
    )


@contextmanager
def database_cursor(dictionary=True):
    """Provide a cursor and always close its connection after the request."""
    connection = None
    cursor = None
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=dictionary)
        yield connection, cursor
        connection.commit()
    except Error:
        if connection:
            connection.rollback()
        raise
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()
