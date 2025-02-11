import os
import pymysql
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get the database URL from the environment variable
database_url = os.getenv('DATABASE_URL', 'sqlite:///DKRDB.db')

# If using MySQL, ensure the URL uses pymysql
if database_url.startswith('mysql:'):
    database_url = database_url.replace('mysql:', 'mysql+pymysql:')

def test_database_connection():
    try:
        # Create an engine
        engine = create_engine(database_url)

        # Try to connect and execute a simple query
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            print("Successfully connected to the database!")
            print("Query result:", result.scalar())

        # If we get here, the connection was successful
        return True
    except Exception as e:
        print("Failed to connect to the database.")
        print("Error:", str(e))
        return False

if __name__ == "__main__":
    print(f"Attempting to connect to: {database_url}")
    success = test_database_connection()
    if success:
        print("Database connection test passed.")
    else:
        print("Database connection test failed.")