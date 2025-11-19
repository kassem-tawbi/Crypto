from pymongo import MongoClient
import certifi

MONGO_URI = "mongodb+srv://trkhmz503_db_user:root@p2pfilesharing.l5vvizb.mongodb.net/?retryWrites=true&w=majority&appName=p2pFileSharing"

def main():
    client = MongoClient(
        MONGO_URI,
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=30_000,
    )
    print("Attempting to connect...")
    print(client.list_database_names())  # simple test
    print("OK!")

if __name__ == "__main__":
    main()
