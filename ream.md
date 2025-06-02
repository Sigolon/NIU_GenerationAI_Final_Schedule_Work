# 生成式 AI Final Work
回顧當前台灣的資安市場，新式的資安產品往往專屬於大企業進行使用。而對於一般非資安專業的大眾來說，一旦面對到新式的資安威脅時，往往陷入被動的情境。

是故，本專案將基於大型語言模型 (ChatGPT) 提出一套，能夠處理一般使用者對面資安威脅時的解決方案。**Attack Path Identifier**。

# **Attack Path Identifier** 的特色在於，

- 能夠根據可疑檔案的 Sha256 值，自動從大型惡意軟體分析網站 Triage 尋找該檔案威脅情資，像是沙箱測試結果、攻擊手法、可能的惡意行為種類。並在整合以後，交由大型語言模型，進行攻擊路徑分析，最後協助使用者分辨該檔案是否具有威脅，並在威脅成立時，提供更加準確且有效的緩解措施。
https://tria.ge/dashboard

    ![image](https://hackmd.io/_uploads/Sk4aPTczeg.png)

# **Attack Path Identifier** 的使用步驟如下，
- 首先使用者需要輸入三項內容，
    - 目前所遇到的情境或感受，可能是使用者為何覺得可疑，抑或當前出現的奇怪事情。如 CPU 過載、半夜 GPU 過熱、出現奇怪的目錄。
    - 可疑的檔案路徑，如 "C:/User/Desktop/google_offer.pdf"
    - 該可疑檔案的，SHA256 值
- 等待後端代碼產生威脅分析報告。
- 模擬執行 : 假設使用者輸入，
    - Prompt : 我最近面試 Google 以為被刷掉了，結果今天他們寄給我錄取通知書。但是我點開 PDF 以後，卻有一瞬間彈出 Powershell。
    - File Path : C:\Users\USER\Downloads\Google_錄取通知.pdf
    - 885b1052ee37f3e5873058e48818d0be79b628ec5f6f2062df24298a51fa8a74
    ![image](https://hackmd.io/_uploads/SkR2cT9Mxg.png)
![image](https://hackmd.io/_uploads/rJNdoa5Gxl.png)

    - 最終分析輸出，
        ```
        # 威脅情資整理
        根據 Triage 情資網站的調查，發現該檔案會產生以下 Process Log : 
        Step 0
        C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService
        -----------
        Step 1
        C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
        -----------
        Step 2
        C:\Windows\system32\svchost.exe -k netsvcs -p -s ProfSvc
        -----------
        Step 3
        sihost.exe
        -----------
        Step 4
        "C:\Users\Admin\AppData\Local\Temp\[System Process]5.exe"
        -----------
        Step 5
        "C:\Users\Admin\AppData\Local\Temp\is-1JMCT.tmp\[System Process]5.tmp" /SL5="$501D4,19894324,792064,C:\Users\Admin\AppData\Local\Temp\[System Process]5.exe"
        -----------
        Step 6
        "C:\ProgramData\shared\projec\hot.exe"
        -----------
        Step 7
        powershell -Command "Add-MpPreference -ExclusionPath 'C:\'"
        -----------
        Step 8
        C:\Windows\system32\wbem\WmiApSrv.exe
        -----------
        Step 9
        schtasks.exe /delete /tn "00F596E5-C67E-4A31-9418-9954C2A5DDA3" /f
        -----------
        ```

        ```
        # 語言模型分析
        以下是資安顧問的分析結果，希望對你有幫助 針對您所提供的使用者回饋和懷疑的檔案，我們將進行一系列分析，以判斷檔案是否含有潛在威脅，並揭示可能的攻擊路徑。

        # 使用者情境
        使用者在打開 PDF 檔案時，出現了短暫的 PowerShell 窗口。這一行為通常並不與正常的 PDF 檔案操作相關，因為 PDF 檔案本身不應該調用系統命令或執行任何形式的腳本。

        # 檔案路徑
        檔案位於 `C:\Users\USER\Downloads\Google_錄取通知.pdf`。下載的檔案經常被利用為載體來執行惡意代碼，值得在這裡進行深入的檢查。 

        # 威脅情資分析
        根據提供的威脅情資步驟：

        - **Step 0 - Step 3** 這些屬於正常系統行為，因為 `svchost.exe` 是 Windows 系統的合法進程，通常負責運行各種系統服務。

        - **Step 4 - Step 5** 偵測到 `C:\Users\Admin\AppData\Local\Temp\[System Process]5.exe` 和相對應的 `.tmp` 文件，這涉及到臨時資料夾涉及的可疑行為。惡意程式經常被設置在 Temp 文件夾中，這令其不容易被發現。

        - **Step 6** 中的 `C:\ProgramData\shared\projec\hot.exe` 是一個非標準路徑，這引起注意。該.exe 文件能夠暗示這是惡意軟體的一部分，因為它不應該出現在程序數據檔案夾中。

        - **Step 7** 使用 PowerShell 添加排除項目是可疑的，因為這意味著該過程可能試圖避免被安全防護措施檢測。

        - **Step 8** 中的 `WmiApSrv.exe` 是合法的系統文件，但若與惡意行為結合在一起，可能用於系統滲透。

        - **Step 9** 刪除計畫任務 `schtasks.exe` 證明該進程試圖隱藏其存在，並刪除相關的痕跡。

        # 結論與建議
        儘管前幾步看似正常，但隨後的行為（尤其是與 `Temp` 目錄和 `.exe` 的關聯）顯示這文件可能含有惡意代碼，並試圖在未被注意的情況下執行。

        建議立即檢查檔案的完整性並進行以下操作：
        1. 使用可靠的反惡意軟體進行全面掃描。
        2. 不要打開或執行任何來源不明的可執行檔或臨時檔案。
        3. 檢查系統的進程和啟動項目，以確保沒有異常行為。
        4. 考慮將此 PDF 檔案上傳至惡意軟體分析平台（如 VirusTotal），以獲取更多資訊。

        這些步驟可幫助確保系統的安全並排除威脅。
        ```
# **Attack Path Identifier** 後端運作流程
Source Code : https://github.com/Sigolon/NIU_GenerationAI_Final_Schedule_Work
威脅情資來源 : [Triage](https://tria.ge/dashboard)
```
[Gradio UI]
   │
   ▼
User inputs:
 - Prompt Summary (情境描述)
 - File Path (可疑檔案路徑)
 - SHA256 (檔案雜湊值)
   │
   ▼
[gradio_interface()]
   │
   ├── Load OpenAI API key via dotenv
   └── Call → Attack_Path_Identify(client, user_filling, file_path, file_sha256)
             │
             ├── Step 1: rewrite() 使用 GPT 將使用者描述轉為專業資安語氣
             │       └── model = gpt-4o-mini
             │       └── output: rewritten_prompt
             │
             ├── Step 2: intelligence_find() 從 Triage 平台查詢 SHA256 行為記錄
             │       └── GET https://tria.ge/s?q=<sha256>
             │       └── Parse /behavioral1 process logs
             │       └── output: multi-step process logs
             │
             ├── Step 3: Assemble final prompt to LLM
             │       └── Inject rewritten_prompt + file_path + intelligence
             │       └── Use gpt-4o-mini to analyze attack path
             │
             └── Step 4: 組合結果並回傳
                     └── [a] 原始 process logs
                     └── [b] LLM-based 資安顧問分析結論
   │
   ▼
[Gradio 顯示分析結果]

```