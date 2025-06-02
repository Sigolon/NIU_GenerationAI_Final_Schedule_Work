from openai import OpenAI
from dotenv import load_dotenv
import os
import requests
from bs4 import BeautifulSoup
import gradio as gr

def rewrite(client, user_prompt):
    def reply(system_prompt,
          user_prompt,
          reflection_client
          ):


        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        chat_completion = reflection_client.chat.completions.create(
            model= "gpt-4o-mini", # save money
            messages= messages,
            max_tokens= 500 # cot very expensive must be limit output token.
        )


        reply = chat_completion.choices[0].message.content

        return reply

    # Step 1: Writer 初稿
    system_writer = "你是一個優秀的資安分析顧問，請幫助使用者梳理情境，將使用者較不專業的言語轉換為便於資安研究員理解的版本"
    rewrite_version = reply(system_prompt= system_writer, 
                          user_prompt = user_prompt,
                          reflection_client= client
                          )
    
    return rewrite_version

def intelligence_find(file_sha256) : 
    intelligence = ""
    query_url = f"https://tria.ge/s?q={file_sha256}"
    try : 
        res = requests.get(url=query_url)
        soup = BeautifulSoup(res.text, 'html.parser')
        data_sample_id_list = soup.find_all("a", attrs= {
                                "data-sample-id" : True,
                                "href" : True,
                            })
        data_sample_id_href = data_sample_id_list[0]["href"]

        query_url = f"https://tria.ge{data_sample_id_href}/behavioral1"
        res = requests.get(query_url)
        soup = BeautifulSoup(res.text, 'html.parser')
        processes_node_list = soup.find_all("ul", attrs= {
                                "data-proc-id" : True,
                                "class" : "processes__node",
                            })
        for processe_index in range(len(processes_node_list)) : 
            intelligence += f"Step {processe_index}\n"

            processes_node_content = processes_node_list[processe_index].find("div", attrs= {"class" : "processes__content-cmd"}).text.strip()
            intelligence += f"{processes_node_content}\n"
            
            intelligence += "-----------\n"

        return intelligence
    except : 
        intelligence = "目前 Triage 情資網站暫無資料"
        return intelligence
    
def Attack_Path_Identify(client, user_filling, file_path, file_sha256):
    intelligence = intelligence_find(file_sha256)
    user_filling = rewrite(client= client, user_prompt= user_filling)

    system_prompt = '''
        目前有一個受懷疑的檔案，也有一些整理好的威脅情資，請根據情資內容與使用者提供的檔案路徑進行變通，並在 1000 token 內完成分析。
        協助使用者排除威脅或是鑑定是否為威脅。
        如果是威脅擇根據 process log 一步步分析，並逐步整理攻擊路徑。

        範例 : 
        雖然 Step 0 ~ 3 很可能屬於正常行為，但是 Step XX 存在 ... ...，最後結合你描述的情境，... ... 
        '''
    prompt_template = '''
        使用者感受 : 
            user filling : {user_filling}
            
        受懷疑檔案 : 
            file path : {file_path}

        相關資訊 : 
            intelligence : {intelligence}
        '''

    prompt = prompt_template.format(
        user_filling=user_filling,
        file_path=file_path,
        intelligence=intelligence
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt}
    ]

    chat_completion = client.chat.completions.create(
        model= "gpt-4o-mini", # save money
        messages= messages,
        max_tokens= 1000
    )

    chat_result = chat_completion.choices[0].message.content
    result = ""
    result += f"根據 Triage 情資網站的調查，發現該檔案會產生以下 Process Log : \n {intelligence}\n"
    result += f"以下是資安顧問的分析結果，希望對你有幫助 {chat_result}"
    return result

def gradio_interface(user_filling, file_path, file_sha256):
    load_dotenv()
    client = OpenAI(
        api_key = os.environ.get("OPENAI_API_KEY")
    )
    return Attack_Path_Identify(client, user_filling, file_path, file_sha256)

gr.Interface(
    fn=gradio_interface,
    inputs=[
        gr.Textbox(label="Prompt Summary (for context)", value=""),
        gr.Textbox(label="檔案路徑 File Path", value=""),
        gr.Textbox(label="SHA256", value="")
    ],
    outputs="text",
    title="Attack Path Identifier",
    description="檔案威脅分析機器人，sha256 可以將可疑檔案上傳至 https://emn178.github.io/online-tools/sha256_checksum.html 取得"
).launch()