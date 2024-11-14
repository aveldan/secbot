import getpass
import os
from dotenv import load_dotenv
from tqdm import tqdm
from time import sleep

from langchain_community.document_loaders import CSVLoader
from langchain_chroma import Chroma
from langchain_huggingface.embeddings import HuggingFaceEndpointEmbeddings
from huggingface_hub.utils import HfHubHTTPError

load_dotenv()

if not os.getenv("HUGGINGFACEHUB_API_TOKEN"):
    os.environ["HUGGINGFACEHUB_API_TOKEN"] = getpass.getpass("Enter your token: ")


def create_embeddings():
    loader = CSVLoader(
        file_path=os.getenv("CSV_FILE_PATH"),
        source_column="Name",
        csv_args={
            "fieldnames": ["Name", "Description"]
        })

    data = loader.load()
    print("Data Loading complete...\n")
    vector_db = db()

    i = 0
    with tqdm(total=15000) as pbar:
        while i < 15000:
            try:
                vector_db.add_documents(data[i:i+20])
                i += 20
                pbar.update(20)
                sleep(10)
            except HfHubHTTPError:
                print(f'TimeOut Error...{i}')
                sleep(180)

def db():
    hf_embedding = HuggingFaceEndpointEmbeddings(
        model="BAAI/bge-m3",
        task="feature-extraction"
    )

    vector_db = Chroma(
        persist_directory=os.getenv("CHROMA_PATH"),
        embedding_function=hf_embedding,
        collection_name="CVE"
    )

    return vector_db.as_retriever(k=5)