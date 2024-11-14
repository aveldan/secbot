import dotenv
import argparse

from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate, ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import StrOutputParser
from langchain.agents import create_openai_functions_agent, Tool, AgentExecutor
from langchain_core.messages import HumanMessage
from langchain.chains.history_aware_retriever import create_history_aware_retriever
from langchain.chains.retrieval import create_retrieval_chain
from  langchain.chains.combine_documents import create_stuff_documents_chain

from spdx_analysis import req_body, find_vulnerabilities, params
from retriever import db

dotenv.load_dotenv()

filename = ""

def prompt_template(agent: bool = False, retrive_chain: bool = False, simple_chain: bool = False):

    if retrive_chain or simple_chain:
        system_msg = """You are an assistant knowledgeable about vulenrabilities in open source software packages. 
                        Please answer the questions (answer all of them) from the given context.
                        The context is from Open Source Vulnerabilities (OSV). Give your answers in a human readable format.

                        {context}
                    """
    else:
        system_msg = """You are an assistant knowledgeable about vulenrabilities in open source software packages. 
                        Please answer the questions (answer all of them) from the given context.
                        The context is from Open Source Vulnerabilities (OSV). Give your answers in a human readable format.
                    """
    
    system_prompt = SystemMessagePromptTemplate(
        prompt=PromptTemplate(
            template=system_msg
        )
    )

    human_prompt = HumanMessagePromptTemplate(
        prompt=PromptTemplate(
            input_variables=['question'],
            template='{question}'
        )
    )

    history_placeholder = MessagesPlaceholder("chat_history")
    agent_scratchpad = MessagesPlaceholder("agent_scratchpad")

    if agent:
        msgs = [system_prompt, human_prompt, history_placeholder, agent_scratchpad]
    elif simple_chain:
        msgs = [system_prompt, human_prompt]
    else:
        msgs = [system_prompt, human_prompt, history_placeholder]

    prompt_template = ChatPromptTemplate(
        input_variables=['question'],
        messages=msgs
    )

    return prompt_template


def create_retriver_chain():
    chat_model = ChatOpenAI(model="gpt-4o", temperature=0, max_tokens=None, timeout=None)
    
    tmp_system_prompt = """Given a chat history and the latest user question \
        which might reference context in the chat history, formulate a standalone question \
        which can be understood without the chat history. Do NOT answer the question, \
        just reformulate it if needed and otherwise return it as is."""
    
    tmp_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", tmp_system_prompt),
            MessagesPlaceholder("chat_history"),
            ("human", "{question}"),
        ]
    )
    
    history_aware_ret = create_history_aware_retriever(llm=chat_model, retriever=db(), prompt=tmp_prompt)

    pre_chain = create_stuff_documents_chain(llm=chat_model, prompt=prompt_template(retrive_chain=True))

    chain = create_retrieval_chain(history_aware_ret, pre_chain)

    return chain

def create_simple_chain():
    chat_model = ChatOpenAI(model="gpt-4o", temperature=0, max_tokens=None, timeout=None)
    output_parser = StrOutputParser()
    chain = prompt_template(simple_chain=True) | chat_model | output_parser
    
    return chain

def retrive_all_osv(tmp: str | None):
    packages = req_body(filename)

    ai_chain = create_simple_chain()
    question = """1) What is the package name and version. Give your answer as in this format Name:<package_name> Version:<package_version>
                    2) What are the vulnerabilities that this package have, please give a small description?
                    3) What is the CVE number for this vulberability?
                    4) What does their severity rating mean? please give a step by step explaination and also at the end classify it as either low, medium or high severity.
                    5) What is a possible solution to this vulberabilities?
               """
    
    for pkg in packages:
        vuls = find_vulnerabilities(pkg)
        if "vulns" not in vuls:
            continue
        vuls = vuls["vulns"]
        
        context = pkg
        context["vulnerabilities"] = []
        for v in vuls:
            reqVals = {}
            if "id" in v:
                reqVals["id"] = v["id"]
            if "summary" in v:
                reqVals["summary"] = v["summary"]
            if "details" in v:
                reqVals["details"] = v["details"]
            if "affected" in v:
                reqVals["affected"] = v["affected"]
            if "severity" in v:
                reqVals["severity"] = v["severity"]
            if "aliases" in v:
                reqVals["aliases"] = v["aliases"]
            context["vulnerabilities"].append(reqVals)
        
        print("\n\n\n")
        print(ai_chain.invoke({'context': context, 'question':question}))


def retrive_osv(package_name: str):
    b_params = params(filename)

    vuls = find_vulnerabilities(b_params[package_name])
    if "vulns" not in vuls:
        return "No vulnerabilities"
    vuls = vuls["vulns"]
    
    context = b_params[package_name]
    context["vulnerabilities"] = []
    for v in vuls:
        reqVals = {}
        if "id" in v:
            reqVals["id"] = v["id"]
        if "summary" in v:
            reqVals["summary"] = v["summary"]
        if "details" in v:
            reqVals["details"] = v["details"]
        if "affected" in v:
            reqVals["affected"] = v["affected"]
        if "severity" in v:
            reqVals["severity"] = v["severity"]
        if "aliases" in v:
            reqVals["aliases"] = v["aliases"]
        context["vulnerabilities"].append(reqVals)

    return context

def generate_tools():
    t1 = Tool(
        name="OSV_Data",
        func=retrive_osv,
        description="""This is usefull when answering questions about Open Source Vulnerabilties (OSV), or any vulnerability about one particular package.
                    This tools can only get extra information about that one package and it's OSV. Do not pass the word "package" as input.
                    If the user asked for information on the package "idna" just pass "idna" as input.
                    You should also invoke this tool to get the information about the package if a relevant package was mentioned in the chat history.
                    """,
    )

    t2 = Tool(
        name="ALL_Package_OSV_Data",
        func=retrive_all_osv,
        description="""This is usefull when answering questions about Open Source Vulnerabilties (OSV), or any vulnerability about many packages.
                    Call this tool when the user does not give you name of a specific package or gives you multiple names.
                    This tools does not take any input or provide any output. Do not pass any arguments to the function.
                    When the tools execution is finished you can just leave. Do not give any output od your own.
                    """
    )

    t3 = Tool(
        name="Retriver",
        func=create_retriver_chain.invoke,
        description="""This is usefull when answering questions about Common Vulnerabilities and Exposures (CVE).
                    Call this tool when the user asks about a particular or a few number of CVEs.
                    This tools just takes the question as a input, so pass on the "question" argument as it is to the tool.
                     """
    )

    tools = [t1, t2, t3]
    return tools


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', default="accelerate.spdx.json", type=str)
    args = parser.parse_args()

    filename = args.file

    tools = generate_tools()
    chat_model = ChatOpenAI(model="gpt-4o", temperature=0, max_tokens=None, timeout=None)
    
    prompt = prompt_template(agent=True)

    agent = create_openai_functions_agent(
        llm=chat_model,
        prompt=prompt,
        tools=tools
    )

    agent_executer = AgentExecutor(
        agent=agent,
        tools=tools,
        return_intermediate_steps=True,
        verbose=True
    )

    chat_history = []

    while True:
        print("\n\nType QUIT to quit")
        query = input("Query: ")
        
        if query == "QUIT":
            break
        
        ai_ans = agent_executer.invoke({
                "question": f"""{query}""",
                "chat_history": chat_history
            })
        
        chat_history.extend([HumanMessage(content=query), ai_ans["output"]])

        print(ai_ans["output"])