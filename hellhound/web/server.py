from flask import Flask, render_template_string
from flask_socketio import SocketIO
import sys

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Port handling
port = 8080
if len(sys.argv) > 1 and '--port=' in sys.argv[1]:
    port = int(sys.argv[1].split('=')[1])

MATRIX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HELLHOUND v0.5</title>
    <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
        *{margin:0;padding:0;box-sizing:border-box}
        body{
            background: #000;
            color: #00ff41;
            font-family: 'Orbitron', monospace;
            height: 100vh;
            overflow: hidden;
            position: relative;
        }
        canvas{background:#000;position:fixed;top:0;left:0;z-index:1}
        .overlay{position:fixed;top:0;left:0;right:0;bottom:0;z-index:2;background:rgba(0,0,0,0.8);padding:40px}
        .hellhound{font-size:48px;text-align:center;margin-bottom:20px;background:linear-gradient(45deg,#00ff41,#ff00ff,#00ffff);background-size:300% 300%;-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:gradient 3s ease infinite;font-weight:900;text-shadow:0 0 30px #00ff41}
        @keyframes gradient{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
        .status-bar{background:rgba(0,255,65,0.1);padding:15px;border:1px solid #00ff41;border-radius:8px;margin:20px 0;font-size:18px;text-align:center;box-shadow:0 0 20px rgba(0,255,65,0.3)}
        .terminal{background:rgba(0,0,0,0.9);border:2px solid #00ff41;border-radius:12px;padding:25px;height:400px;overflow-y:auto;margin:20px 0;box-shadow:inset 0 0 30px rgba(0,255,65,0.1)}
        button{
            background:linear-gradient(45deg,#ff4444,#cc3333);
            color:white;border:none;
            padding:15px 30px;font-family:'Orbitron',monospace;
            cursor:pointer;border-radius:8px;
            font-size:16px;font-weight:700;
            margin:10px;box-shadow:0 0 20px rgba(255,68,68,0.5);
            transition:all 0.3s;
        }
        button:hover{transform:scale(1.05);box-shadow:0 0 30px rgba(255,68,68,0.8)}
        .prompt{color:#00ff41;font-weight:bold}
        ::-webkit-scrollbar{width:8px;background:rgba(0,255,65,0.1)}
        ::-webkit-scrollbar-thumb{background:#00ff41;border-radius:4px}
    </style>
</head>
<body>
    <canvas id="matrix"></canvas>
    <div class="overlay">
        <div class="hellhound">HELLHOUND v0.5</div>
        <div class="status-bar">Target: 192.168.56.6 | Status: LIVE | recon.txt generated</div>
        <div class="terminal" id="terminal">
            <span class="prompt">hellhound@pentest:~$</span> dashboard loaded<br>
            <span class="prompt">hellhound@pentest:~$</span> nmap recon complete (21 ports open)<br>
            <span class="prompt">hellhound@pentest:~$</span> 
        </div>
        <center>
            <button onclick="nmapScan()">🔍 Nmap Full Scan</button>
            <button onclick="exploit()">💀 Exploit Chain</button>
            <button onclick="report()">📊 Generate Report</button>
        </center>
    </div>
    <script>
        const canvas=document.getElementById('matrix'),ctx=canvas.getContext('2d');
        canvas.height=window.innerHeight;canvas.width=window.innerWidth;
        const chars='01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン',fontSize=14;
        const columns=canvas.width/fontSize;const drops=[];
        for(let i=0;i<columns;i++)drops[i]=1;
        function draw(){ctx.fillStyle='rgba(0,0,0,0.05)';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle='#00ff41';ctx.font=fontSize+'px monospace';drops.forEach((y,i)=>{if(y*fontSize>canvas.height&&Math.random()>0.975){drops[i]=0}else{y+=fontSize;ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*fontSize,y);drops[i]=y}});};setInterval(draw,50);
        
        const socket=io(),term=document.getElementById('terminal');
        function log(cmd,msg){term.innerHTML+='<span class="prompt">hellhound@pentest:~$ '+cmd+'</span> '+msg+'<br>';term.scrollTop=term.scrollHeight;}
        function nmapScan(){log('nmap -A 192.168.56.6','vsftpd 2.3.4 detected');}
        function exploit(){log('exploit vsftpd_backdoor','shell acquired');}
        function report(){log('generate_report','hellhound_report.pdf created');}
    </script>
</body></html>
"""

@app.route('/')
def index():
    return render_template_string(MATRIX_HTML)

if __name__ == '__main__':
    print(f"[+] Hellhound web server: *:{port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
