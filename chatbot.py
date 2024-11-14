import getpass
import os
from dotenv import load_dotenv

from langchain_huggingface import HuggingFaceEndpoint, ChatHuggingFace
from langchain.prompts import PromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate, ChatPromptTemplate
from langchain.schema.runnable import RunnablePassthrough
from langchain_chroma import Chroma
from langchain_huggingface.embeddings import HuggingFaceEndpointEmbeddings

load_dotenv()

if not os.getenv("HUGGINGFACEHUB_API_TOKEN"):
    os.environ["HUGGINGFACEHUB_API_TOKEN"] = getpass.getpass("Enter your token: ")

def prompt_template():

    system_msg = """You are a assistant knowledgeable about Common Vulnerabilities and Exposures (CVEs) in software systems. 
                  Only answer questions that involve CVEs and cybersecurity. Strictly do not answer any other questions
                  Use the following context to answer the question, if the context is relevant to the question.
                  But in your answer do not mention that you were provided context, Avoid sentences like "According to the provided context".
                  
                  {context}
                  """
    
    system_prompt = SystemMessagePromptTemplate(
        prompt=PromptTemplate(
            input_variables=['context'],
            template=system_msg
        )
    )

    human_prompt = HumanMessagePromptTemplate(
        prompt=PromptTemplate(
            input_variables=['question'],
            template='{question}'
        )
    )

    msgs = [system_prompt, human_prompt]

    prompt_template = ChatPromptTemplate(
        input_variables=['context', 'question'],
        messages=msgs
    )

    return prompt_template


def chat_model():
    chat_model = HuggingFaceEndpoint(
        repo_id="meta-llama/Meta-Llama-3-8B-Instruct",
        task="text-generation",
        max_new_tokens=512,
        do_sample=False,
        repetition_penalty=1.2
    )

    chat_model = ChatHuggingFace(llm=chat_model)

    return chat_model


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

def create_chain():
    chain = {'context': db(), 'question': RunnablePassthrough()} | prompt_template() | chat_model()

    return chain

if __name__ == "__main__":

    query = ""
    chat_bot = create_chain()

    while True:
        print("Type QUIT to quit\n")
        query = input("Query: ")
        
        if query == "QUIT":
            break
        
        print("\nBot: ", chat_bot.invoke(query).content, "\n\n")