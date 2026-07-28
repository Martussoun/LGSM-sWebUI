# LGSM-sWebUI

A lightweight web interface with FastAPI backend and React frontend(currently only statically served by the backend) designed to manage existing LinuxGSM servers, mainly intended for use locally or via LAN.
Designed for Ubuntu 24.04 LTS servers, also tested on Rocky 9.8 minimal
##  Features

- **Server Management:** Perform basic actions (Start, Stop, Restart, etc.) via a clean UI and receive live script printouts of the current command.
- **Configuration:** Edit server configurations directly through the web interface.
- **Advanced Functions:** Supports custom `gamehandler` scripts (currently supporting **ETS2** and **CS2**).
- **Secure Authentication:**
    - SQLite database-backed login.
    - Admin credentials using **Argon2id** hashed passwords with customizable parameters.
    - API Key support.

## Screenshots
### Login Form
<img width="478" height="386" alt="swui_login" src="https://github.com/user-attachments/assets/a5f8fca1-cf8b-468a-b022-6cf85aa8d0a7" />

### Main page with server cards and config editor(1x ets2 server example on rocky 9.8)
<img width="1919" height="835" alt="swui_mainpage" src="https://github.com/user-attachments/assets/6fcc2393-33de-4534-ad0a-953e754103ce" />

##  Getting Started

### Prerequisites

- Python 3.9+
- LinuxGSM installed on your servers

### Installation

1. **Clone the repository:**

    
    <pre>git clone https://github.com/Martussoun/LGSM-sWebUI </pre>
    
2. **Set up the environment:**


    <pre>cd LGSM-sWebUI
   
    python3 -m venv venv_swui
   
    source venv_swui/bin/activate
   
    pip install -r requirements.txt</pre>
    
4. **Install your ASGI server of choice(uvicorn example):**

	<pre>pip install uvicorn</pre>
		
5. **Initialize the Database:**
    
    <pre>python3 backend/db/init_db.py</pre>

   Add an admin from the menu, minimum password length is 10 characters

   You can then choose to change individual argon2id params(defaults are in brackets), or simply press enter to continue with default value on each
    
    > **Note:** The database initializes on the first launch, but since there are no default credentials, you must create an admin account (this can also be done during runtime). On older python versions you will also need to install the *eval_type_backport* package via pip
    
7. **Run the application:**
    
     > Replace IP and PORT with your desired values
   
     <pre>uvicorn backend.app.main:app --reload --host <IP> --port <PORT> > swui.log 2>&1 &</pre>
    
8. **Connect via browser**

## ⚠️ Important Security Note

**This application runs on HTTP by default.** Do **NOT** expose this web UI to the public internet or shared LAN without at least setting up an SSL certificate (HTTPS).
