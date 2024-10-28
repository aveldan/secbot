import getpass
import os
from dotenv import load_dotenv

from langchain_community.document_loaders import CSVLoader
from langchain_chroma import Chroma
from langchain_huggingface.embeddings import HuggingFaceEndpointEmbeddings

load_dotenv()

if not os.getenv("HUGGINGFACEHUB_API_TOKEN"):
    os.environ["HUGGINGFACEHUB_API_TOKEN"] = getpass.getpass("Enter your token: ")

hf_embedding = HuggingFaceEndpointEmbeddings(
    model="BAAI/bge-m3",
    task="feature-extraction"
)

vector_db = Chroma(
    persist_directory=os.getenv("CHROMA_PATH"),
    embedding_function=hf_embedding,
    collection_name="CVE"
)


def create_embeddings():
    loader = CSVLoader(
        file_path=os.getenv("CSV_FILE_PATH"),
        source_column="Name",
        csv_args={
            "fieldnames": ["Name", "Description"]
        })

    data = loader.load()
    print("Data Loading complete\n")

    i = 0
    while i < len(data):
        vector_db.add_documents(data[i:i+100])
        i += 100
    
    return vector_db


def ret_test():
    
    
    query = "CVE-1999-0001?"

    relevant_docs = vector_db.similarity_search(query=query, k=3)

    print(f'Length: {len(relevant_docs)}\n\n\n\n')
    for r in relevant_docs:
        print(r,"\n\n\n\n")


create_embeddings()

# ret_test()