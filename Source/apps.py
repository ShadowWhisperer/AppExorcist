import os                #Folder Deletion
import ctypes            #Check if ran as an admin
import subprocess        #Run Powershell / var other processes
import json              #Read json file
import shutil            #Folder deletion
import fnmatch           #File deletion *String match
import sys               #Get Admin permissions
import getpass           #Take Permissions
import winreg            #Modify Windows Registry
import shutil            #Delete folders
import win32con             #Set registry permissions
import win32api             #Set registry permissions
import pywintypes           #Set registry permissions
import win32security        #Set registry permissions
import threading              #Used in status window *Commands execute before window shows
import glob                   #Search files/folders
import requests               #Download Apps list from Github
import tkinter as tk                #GUI
from tkinter import messagebox, ttk #GUI
import tkinter.font as tkfont       #GUI - Font
from tkinter.scrolledtext import ScrolledText #GUI - Scroll text


#
# cd C:\Program Files\Python312
# python.exe -m pip install --upgrade pip
# cd C:\Program Files\Python312\Scripts
# pip.exe install pywin32 pyinstaller requests wmid
#


#Denied
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageFamily\Index\PackageFamilyName
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplicationUserModelId
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageFamily\Data
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Protocol\Index\Name


#Reintalls App on reboot - Not certain how ?
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Config
#  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\{user_sid}



#Check if running as Admin
if not ctypes.windll.shell32.IsUserAnAdmin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    os._exit(0)


#================================================================================================#
#   Variables                                                                                    #
#================================================================================================#
#Hide CMD/Powershell
def hide_console():
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.dwFlags |= subprocess.CREATE_NO_WINDOW
    return startupinfo

my_name = getpass.getuser()
# user_sid = subprocess.check_output(["powershell", "(Get-LocalUser -Name $env:USERNAME).SID.Value"], startupinfo=hide_console()).decode().strip()   *Does no work on older systems
user_sid = subprocess.check_output(["powershell", "(New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value"], startupinfo=hide_console()).decode().strip()

hide_native_button_pressed = False
all_apps_selected = False
REM = False
RegValue = False
opt = ""

#Database - Create, dir & file
database_path = r'C:\ProgramData\ShadowWhisperer\Apps\database.json' #Database of just what is installed
if not os.path.exists(database_path):
    os.makedirs(os.path.dirname(database_path), exist_ok=True)
    open(database_path, 'w').close()

#Set paths to database / icon file
app_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
icon_cross = os.path.join(app_dir, "cross.ico")
database_sw = os.path.join(app_dir, "apps.json")

#Downloaded from GitHub
if os.path.exists(r"C:\ProgramData\ShadowWhisperer\Apps\database_new.json"):
    database_sw = r"C:\ProgramData\ShadowWhisperer\Apps\database_new.json"


#================================================================================================#
#   Check for system errors                                                                      #
#================================================================================================#
def service_check(service_name):
    global error_found  # Define error_found as a global variable
    cmd = f"sc query {service_name} | findstr RUNNING"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    if result.returncode == 0:
        return
    else:
        subprocess.run(r"reg add HKLM\SYSTEM\CurrentControlSet\Services\{service_name} /v Start /t REG_DWORD /d 3 /f", shell=True, startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(f"sc config {service_name} start= demand", startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(f"sc start {service_name}", shell=True, startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        counter = 0
        while counter < 10:
            result = subprocess.run(cmd, shell=True, capture_output=True)
            if result.returncode == 0:
                return
            counter += 1
            for _ in range(10_000_000):
                pass
        #Update the GUI with error info
        listbox.delete(0, tk.END)
        listbox.insert(tk.END, "")
        root.update()
        error_label = tk.Label(listbox,text=f" {service_name} service is not running!\n\n Repairs were attempted.\n\n Reboot your PC to finish repairs.",fg="red")
        error_label.pack()
        root.update()
        error_found = True
        #Button - Reboot PC
        button_reboot = tk.Button(root, text="Reboot PC", command=reboot_pc)
        button_reboot.pack(side=tk.BOTTOM, padx=5, pady=5)
        #Button - Exit
        button_exit = tk.Button(root, text="Exit", command=exit_program)
        button_exit.pack(side=tk.BOTTOM, padx=5, pady=5)
        #Wait for window to be closed
        root.wait_window(root)

def download_database():
    tmp_path = r"C:\ProgramData\ShadowWhisperer\Apps\db.tmp"
    final_path = r"C:\ProgramData\ShadowWhisperer\Apps\database_new.json"
    try:
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)
        response = requests.get("https://raw.githubusercontent.com/ShadowWhisperer/AppExorcist/main/Source/apps.json")
        if response.status_code == 200:
            with open(tmp_path, 'wb') as file:
                file.write(response.content)
            line_count = sum(1 for _ in open(tmp_path, 'r'))
            os.replace(tmp_path, final_path) if line_count >= 4000 else os.remove(tmp_path)
    except:
        pass

def check_errors():
    #Enable system restore
    subprocess.call([r'reg', 'add', r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore', '/v', 'DisableSR', '/t', 'REG_DWORD', '/d', '0', '/f'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['powershell', '-Command', 'Enable-ComputerRestore -Drive C:\\'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    #Download current list from Github
    download_database()
    #Disable automatic app download/re-installation
    subprocess.call([r'reg', 'add', r'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore', '/v', 'AutoDownload', '/t', 'REG_DWORD', '/d', '2', '/f'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call([r'reg', 'add', r'HKLM\Software\Policies\Microsoft\Windows\CloudContent', '/v', 'DisableWindowsConsumerFeatures', '/t', 'REG_DWORD', '/d', '1', '/f'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call([r'reg', 'add', r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager', '/v', 'SilentInstalledAppsEnabled', '/t', 'REG_DWORD', '/d', '0', '/f'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.call([r'reg', 'add', r'HKCU\SOFTWARE\Policies\Microsoft\Windows\Appx', '/v', 'AllowDeploymentBlock', '/t', 'REG_DWORD', '/d', '1', '/f'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    global error_found  # Define error_found as a global variable
    error_label = tk.Label(listbox, text=f" Checking for issues...\n")
    error_label.pack()
    root.update()
    error_found = False
    #Services
    service_check("PcaSvc")  #Program Capability Assistant Service - Prevents Get-AppxPackage removal from working
    service_check("AppXSvc") #AppX Deployment Service              - Prevents Get-AppxPackage from getting app list
    #Not on Windows 8
    if sys.platform != "win32" or sys.getwindowsversion().major > 6:  #OS is not Windows 8 (version 6.2)
            service_check("camsvc")  #Capability Access Manager Service  - Prevents Get-AppxPackage removal from working
def exit_program():
    root.destroy()
def reboot_pc():
    subprocess.call("shutdown /r /t 0", shell=True, startupinfo=hide_console())

root = tk.Tk()
root.title("Pre-launch Check")
root.geometry("350x130")
root.resizable(False, False)
root.iconbitmap(icon_cross)
listbox = tk.Listbox(selectmode=tk.MULTIPLE, width=100, height=15)
listbox.configure(bg="#f0f0f0")
listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
check_errors()

#Close error checker
if not error_found:
    root.destroy() #Continue to main script
else:
    sys.exit()     #Stop script completely


#================================================================================================
#   Update Database                                                                             #
#================================================================================================
def get_display_name(full_name):  #Get 'DisplayName' from registry
    registry_path = r'SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages'
    key_path = os.path.join(registry_path, full_name)
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        try:
            display_name, _ = winreg.QueryValueEx(key, 'DisplayName')
            winreg.CloseKey(key)
            display_name = display_name.strip()
            if '@' in display_name:
                display_name = '[Not in database]'
            if display_name == '':
                display_name = '[Not in database]'
            elif display_name != '[Not in database]':
                display_name += ' [?]'
            return display_name
        except FileNotFoundError:
            winreg.CloseKey(key)
            return '?'
    except FileNotFoundError:
        return '?'

def rebuild_database():
    ctypes.windll.shell32.SHChangeNotify(0x8000000, 0, None, None)  #Clear app cache
    with open(os.devnull, 'w') as devnull:
        subprocess.run('PowerShell -NoProfile -Command "Get-AppxPackage -AllUsers | foreach { $_.PackageFullName }"', startupinfo=hide_console(), stdout=devnull, stderr=subprocess.STDOUT)
    #Get list of installed Appx
    powershell_command = 'Get-AppxPackage -AllUsers | Where-Object { $_.Name -notlike "Microsoft.VCLibs.*" -and $_.Name -notlike "Microsoft.NET.*" } | Select-Object Name | Format-Table -AutoSize | Out-String -Width 10000'
    powershell_process = subprocess.Popen(['powershell', '-Command', powershell_command], startupinfo=hide_console(), stdout=subprocess.PIPE)
    powershell_output, _ = powershell_process.communicate()
    powershell_output = powershell_output.decode('ascii')
    #Parse output into app names
    installed_app_names = [line.strip() for line in powershell_output.strip().split('\n')[2:]]
    #Load JSON database
    with open(database_path, 'r') as json_file:
        database = json.load(json_file)
    #Keep only remaining apps
    remaining_apps = [app for app in database if app['name'] in installed_app_names]
    #Save updated database
    with open(database_path, 'w') as json_file:
        json.dump(remaining_apps, json_file, indent=4)

def build_database():
    ctypes.windll.shell32.SHChangeNotify(0x8000000, 0, None, None)  # Clear app cache
    with open(os.devnull, 'w') as devnull:
        subprocess.run('PowerShell -NoProfile -Command "Get-AppxPackage -AllUsers | foreach { $_.PackageFullName }"', stdout=devnull, stderr=subprocess.STDOUT)
    #List of installed Appx
    powershell_command = 'Get-AppxPackage -AllUsers | Where-Object { $_.Name -notlike "Microsoft.VCLibs.*" -and $_.Name -notlike "Microsoft.NET.*" } | Select-Object Name, PackageFullName | Format-Table -AutoSize | Out-String -Width 10000'
    powershell_process = subprocess.Popen(['powershell', '-Command', powershell_command], startupinfo=hide_console(), stdout=subprocess.PIPE)
    powershell_output, _ = powershell_process.communicate()
    powershell_output = powershell_output.decode('ascii')
    powershell_output_lines = powershell_output.strip().split('\n')[2:]                #Remove header lines
    app_full_name_pairs = [line.split(maxsplit=1) for line in powershell_output_lines] #Parse output into pairs
    # Load JSON database_sw
    with open(database_sw, 'r') as json_file:
        global json_data
        json_data = json.load(json_file)
    matching_apps = {}   #Create a dictionary to store app versions
    #Iterate over app pairs
    for app_name, full_name in app_full_name_pairs:
        app_name = app_name.strip()
        full_name = full_name.strip()
        # heck if the app exists in the database_sw and is not hidden
        if app_name in matching_apps or any(app['name'] == app_name and app.get('hide') != 'yes' for app in json_data):
            app_info = matching_apps.get(app_name)
            if app_info is None:
                existing_apps = [app for app in json_data if app['name'] == app_name and app.get('hide') != 'yes']
                app_info = existing_apps[0].copy()
                matching_apps[app_name] = app_info
                if 'full_name' not in app_info:
                    app_info['full_name'] = []
            app_info['full_name'].append(full_name)  #Append the new version to the existing versions
            app_info.pop('hide', None) #Remove the 'hide' category
            if 'info' not in app_info or app_info['info'] == '?':
                app_info['info'] = get_display_name(full_name)  #Update the info if not present or unknown
        else:
            #Check if the app is set to hidden: yes in database_sw
            existing_hidden_apps = [app for app in json_data if app['name'] == app_name and app.get('hide') == 'yes']
            if not existing_hidden_apps:
                new_app = {
                    'name': app_name,
                    'info': get_display_name(full_name),
                    'issues': '[Not in database]',
                    'native': '[Not in database]',
                    'bloat': '[Not in database]',
                    'full_name': [full_name],
                }
                matching_apps[app_name] = new_app
    matching_apps_list = [app_info for app_info in matching_apps.values() if app_info.get('hide') != 'yes']
    #Save updated database_path
    with open(database_path, 'w') as output_file:
        for app_info in matching_apps_list:
            app_info['full_name'] = ','.join(app_info['full_name']) if 'full_name' in app_info else ''
        json.dump(matching_apps_list, output_file, indent=4)
#Build app databse
build_database()


#================================================================================================#
#   Registry                                                                                     #
#================================================================================================#
#Print / Take permissions / delete
def registry(key_path,text_box):
    if key_path: #Be certain it's not blank
        display_status(key_path, text_box)
        registry_perms(key_path)
        if RegValue is True:
            last_backslash_index = key_path.rfind('\\')
            path = key_path[:last_backslash_index]
            value = key_path[last_backslash_index + 1:]
            subprocess.run(['reg', 'delete', path, '/v', value, '/f'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
           subprocess.run(['reg', 'delete', key_path, '/f'], startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

#Take Permissions
def registry_perms(key_path):
    try:
        root_key_name, subkey_path = key_path.split("\\", 1)
        root_key_map = {
            "HKEY_CLASSES_ROOT": win32con.HKEY_CLASSES_ROOT,
            "HKEY_CURRENT_USER": win32con.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": win32con.HKEY_LOCAL_MACHINE,
            "HKEY_USERS": win32con.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": win32con.HKEY_CURRENT_CONFIG
        }
        root_key = root_key_map.get(root_key_name.upper())
        if root_key is None:
            raise ValueError("Invalid root key: {}".format(root_key_name))
        key = win32api.RegOpenKey(root_key, subkey_path, 0, win32con.KEY_ALL_ACCESS)
        ksd = win32api.RegGetKeySecurity(key, win32security.DACL_SECURITY_INFORMATION)
        acl = pywintypes.ACL()
        acl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, win32security.ConvertStringSidToSid('S-1-5-18'))
        acl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_ALL, win32security.ConvertStringSidToSid('S-1-5-32-544'))
        ksd.SetDacl(True, acl, False)
        win32api.RegSetKeySecurity(key, win32security.DACL_SECURITY_INFORMATION, ksd)
    except FileNotFoundError:
        return
    except Exception as e:
        return

#Registry - Remove open with context menu
# HKEY_CLASSES_ROOT\SystemFileAssociations
#                                         \*\Shell\
#                                                  3D Edit
def RegContext(package_name,text_box):
    #Paint 3D
    if package_name == "Microsoft.MSPaint":
        search_for = "3D Edit"
    #Print 3D
    elif package_name == "Microsoft.Print3D":
        search_for = "3D Print"
    else:
        return
    def find_keys(search_for):
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r'SystemFileAssociations') as key:
                subkeys = []
                try:
                    index = 0
                    while True:
                        subkey = winreg.EnumKey(key, index)
                        subkey_path = os.path.join(r'SystemFileAssociations', subkey, 'Shell', search_for)
                        try:
                            winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, subkey_path)
                            subkeys.append(subkey_path)
                        except FileNotFoundError:
                            pass
                        index += 1
                except OSError:
                    pass
                return subkeys
        except FileNotFoundError:
            return []
    keys = find_keys(search_for)
    if keys:
        for key in keys:
            key_path = os.path.join(r'HKEY_CLASSES_ROOT', key)
            registry(key_path, text_box)


#Specific locations that do not specify the app name
def registry_specific(package_name,user_sid,text_box):
    registry_locations = {
        "Microsoft.BingWeather": [
            "HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ADMX_UserExperienceVirtualization\\Weather",
            "HKCU\\SOFTWARE\\Classes\\bingweather",
            "HKCU\\SOFTWARE\\Classes\\msnweather",
            "HKCR\\bingweather"
        ],
        "Microsoft.Getstarted": [
            f"HKU\\{user_sid}\\SOFTWARE\\Classes\\ms-get-started",
            "HKCU\\SOFTWARE\\Classes\\ms-get-started",
            "HKCR\\ms-get-started",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\ms-get-started",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\ms-get-started"
        ],
        "Microsoft.Microsoft3DViewer": [
            "HKCU\\SOFTWARE\\Classes\\com.microsoft.3dviewer",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\com.microsoft.3dviewer",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\com.microsoft.3dviewer"
        ],
        "Microsoft.Print3D": [
            "HKCU\\SOFTWARE\\Classes\\com.microsoft.print3d"
        ],
        "Microsoft.WindowsCamera": [
            "HKCU\\SOFTWARE\\Classes\\microsoft.windows.camera",
            "HKCU\\SOFTWARE\\Classes\\microsoft.windows.camera.picker",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.camera",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.camera.picker",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.camera",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.camera.picker"
        ],
        "Microsoft.MicrosoftEdge": [
            "HKCU\\SOFTWARE\\Classes\\microsoft-edge-holographic",
            "HKCR\\microsoft-edge-holographic",
            "HKCU\\SOFTWARE\\Classes\\microsoft-edge",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft-edge-holographic",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft-edge",
            f"HKU\\{user_sid}\\SOFTWARE\\Classes\\microsoft-edge-holographic",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft-edge"
        ],
        "Microsoft.ZuneMusic": [
            "HKCU\\SOFTWARE\\Classes\\microsoftmusic",
            "HKCU\\SOFTWARE\\Classes\\mswindowsmusic",
            "HKCU\\SOFTWARE\\Classes\\zune",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoftmusic",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoftmusic",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\mswindowsmusic",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\zune",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\zune",
            "HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ADMX_UserExperienceVirtualization\\Music"
        ],
        "Microsoft.ZuneVideo": [
            "HKCU\\SOFTWARE\\Classes\\microsoftvideo",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoftvideo",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoftvideo",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\mswindowsvideo",
            "HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\default\\ADMX_UserExperienceVirtualization\\Video"
        ],
        "Microsoft.WindowsFeedbackHub": [
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\feedback-hub",
            "HKCU\\SOFTWARE\\Classes\\feedback-hub",
            "HKCR\\feedback-hub",
            "HKCU\\SOFTWARE\\Classes\\windows-feedback",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\windows-feedback",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\windows-feedback",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\feedback-hub"
        ],
        "Microsoft.Office.OneNote": [
            "HKCU\\SOFTWARE\\Classes\\onenote",
            "HKCU\\SOFTWARE\\Classes\\onenote-cmd",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\onenote",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\onenote-cmd",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\onenote",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\onenote-cmd"
        ],
        "Microsoft.SkypeApp": [
            "HKCU\\SOFTWARE\\Classes\\skype",
            "HKCU\\SOFTWARE\\Classes\\skypewin",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\skype",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\skypewin",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\skype",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\skypewin"
        ],
        "Microsoft.WindowsMaps": [
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\bingmaps",
            "HKCR\\bingmaps",
            "HKCU\\SOFTWARE\\Classes\\bingmaps"
        ],
        "Microsoft.Windows.Photos": [
            "HKCU\\SOFTWARE\\Classes\\microsoft.windows.photos.crop",
            "HKCU\\SOFTWARE\\Classes\\microsoft.windows.photos.picker",
            "HKCU\\SOFTWARE\\Classes\\microsoft.windows.photos.search",
            "HKCU\\SOFTWARE\\Classes\\microsoft.windows.photos.videoedit",
            "HKCU\\SOFTWARE\\Classes\\ms-photos",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.photos.crop",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.photos.picker",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.photos.videoedit",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\ms-photos",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.photos.crop",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.photos.picker",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\microsoft.windows.photos.videoedit",
            f"HKU\\{user_sid}\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\ms-photos"
        ]
    }
    if package_name in registry_locations:
        keys = registry_locations[package_name]
        if keys:
            for key_path in keys:
                registry(key_path, text_box)
    else:
        pass



# HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\
#                                                                        app_name
def registry_wild(package_name, user_sid):
    ROOT_KEY_NAMES = {
        winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
        winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
        winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
        winreg.HKEY_USERS: "HKEY_USERS",
        winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG",
    }
    keys = [
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.ShareTarget\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"ActivatableClasses\Package"),
    (winreg.HKEY_CLASSES_ROOT, r"AppUserModelId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.AppService\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.BackgroundTasks\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.FileOpenPicker\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.File\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.Launch\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.Protocol\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Extensions\ContractId\Windows.UpdateTask\PackageId"),
    (winreg.HKEY_CLASSES_ROOT, r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages"),
    (winreg.HKEY_CLASSES_ROOT, r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache"),
    (winreg.HKEY_CLASSES_ROOT, r"Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\ActivatableClasses\Package"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.AppService\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.FileOpenPicker\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.File\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.Launch\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.ShareTarget\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.Protocol\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Extensions\ContractId\Windows.UpdateTask\PackageId"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Phone\ShellUI\WindowSizing"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\AppUserModelId"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\UEV\Agent\Configuration\Windows8AppList"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\{}".format(user_sid)),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-18"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Staged"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\activity\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\appDiagnostics\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\appointments\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\appointmentsSystem\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\backgroundSpatialPerception\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\bluetoothSync\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\broadFilesystemAccess\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\cellularData\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\chat\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\chatSystem\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\contacts\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\contactsSystem\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\documentsLibrary\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\email\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\emailSystem\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\gazeInput\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\microphone\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\phoneCall\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\phoneCallHistory\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\phoneCallHistorySystem\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\picturesLibrary\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\radios\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\userAccountInformation\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\userDataTasks\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\userDataTasksSystem\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\videosLibrary\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\webcam\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\wiFiControl\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities\wifiData\Apps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\QuietHours\Profiles\Microsoft.QuietHoursProfile.PriorityOnly\AllowedApps"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Config"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\Applications"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\AppxAllUserStore\{}".format(user_sid)),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\AppxAllUserStore\Staged"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\AppxAllUserStore\Applications"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\AppxAllUserStore\Config"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\AppxAllUserStore\{}".format(user_sid)),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\AppxAllUserStore\InboxApplications"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\BundleManifestInfo"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\{}".format(user_sid)),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\InstalledPackages\Bundle"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\InstalledPackages\Main"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\InstalledPackages\Resource"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\PackageInstallState"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\DownlevelGather\SisDirectory"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\PackagesToCheckForStagingCompletion"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\PackagesToReRegister"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\Setup\Upgrade\Appx\PackagesToReRegister\{}".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\ActivatableClasses\Package".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.AppService\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.Device\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.FileOpenPicker\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.File\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.Launch\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.Protocol\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Extensions\ContractId\Windows.UpdateTask\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache".format(user_sid)),
    (winreg.HKEY_USERS, r"{}_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\ActivatableClasses\Package".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.AppService\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.BackgroundTasks\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.Device\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.FileOpenPicker\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.File\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.Launch\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.Protocol\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Extensions\ContractId\Windows.UpdateTask\PackageId".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PolicyCache".format(user_sid)),
    (winreg.HKEY_USERS, r"{}\SOFTWARE\Microsoft\Windows NT\CurrentVersion\HostActivityManager\CommitHistory".format(user_sid)),
    ]
    found_keys = []
    for root_key, path in keys:
        try:
            key = winreg.OpenKey(root_key, path, 0, winreg.KEY_READ)
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                    if subkey_name.startswith(package_name + "_"):
                        root_key_name = ROOT_KEY_NAMES.get(root_key, str(root_key))
                        full_key_path = f"{root_key_name}\\{path}\\{subkey_name}"
                        class_name = winreg.QueryValue(key, subkey_name)
                        full_key_path = f"{full_key_path}\\{class_name}"
                        found_keys.append(full_key_path.rstrip("\\"))
                    index += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass
    return found_keys

# HKEY_CURRENT_USER
#          SOFTWARE
#        Registered
#      Applications
#                  value
#                       | data - if data match, delete value
def registry_values(root_key_str, base_key_path, package_name):
    key_paths = []
    try:
        root_key = getattr(winreg, root_key_str)
        key = winreg.OpenKey(root_key, base_key_path)
        num_values = winreg.QueryInfoKey(key)[1]
        for i in range(num_values):
            try:
                value_name, value_data, _ = winreg.EnumValue(key, i)
                if package_name.lower() in value_data.lower():
                    full_path = root_key_str + "\\" + base_key_path + "\\" + value_name
                    key_paths.append(full_path)
            except:
                pass
        key.Close()
    except:
        pass
    return key_paths

#  Read    HKEY_CURRENT_USER\SOFTWARE\Classes\ * \FriendlyTypeName
#  Delete  HKEY_CURRENT_USER\SOFTWARE\Classes\ *
def traverse_registry_keys(root_key_str, key_path, package_name, base_key_path, subkey):
    root_key_map = {
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG
    }
    root_key = root_key_map.get(root_key_str.upper())
    if root_key is None:
        raise ValueError("Invalid root key: {}".format(root_key_str))
    key_paths = []
    try:
        key = winreg.OpenKey(root_key, key_path)
        num_subkeys = winreg.QueryInfoKey(key)[0]
        for i in range(num_subkeys):
            subkey_name = winreg.EnumKey(key, i)
            full_subkey_path = key_path + "\\" + subkey_name
            friendly_type_name = read_registry_value(root_key, full_subkey_path, subkey)
            if friendly_type_name and package_name.lower() in friendly_type_name.lower():
                key_paths.append(f"{root_key_str}\\{full_subkey_path}")
            key_paths.extend(traverse_registry_keys(root_key_str, full_subkey_path, package_name, base_key_path, subkey))
    except FileNotFoundError:
        pass
    return key_paths
def read_registry_value(root_key, key_path, value_name):
    try:
        key = winreg.OpenKey(root_key, key_path)
        value, _ = winreg.QueryValueEx(key, value_name)
        return value
    except FileNotFoundError:
        return None

#================================================================================================#
#   Delete Files / Folders                                                                       #
#================================================================================================#

#Take ownership & delete files
printed_paths = set() #Don't print duplicate lines
def delete_it(match, text_box):
    for path in match:
        if path not in printed_paths:
            printed_paths.add(path)
            display_status(path, text_box)
        subprocess.run(f'icacls "{path}" /inheritance:e /grant "{my_name}:(OI)(CI)F" /T /C', startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
        try:
            if os.path.isfile(path):
                os.remove(path)
            else:
                subprocess.run(f'takeown /f "{path}" /a /r /d y', startupinfo=hide_console(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
                shutil.rmtree(path)
        except Exception:
            pass

# [1] C:\Program Files\WindowsApps\Deleted\*
def file_folders1():
    locations = [
        r'C:\Program Files\WindowsApps\Deleted',
        r'C:\Program Files\WindowsApps\DeletedAllUserPackages'
    ]
    match = [os.path.join(loc, subdir) for loc in locations if os.path.exists(loc) for subdir in next(os.walk(loc))[1]]
    delete_it(match)
    delete_it(match)
# [2] Multiple
def file_folders2(package_name, text_box):
    locations = [
        r'c:\ProgramData\Microsoft\Windows\AppRepository',
        r'c:\ProgramData\Microsoft\Windows\AppRepository\Packages',
        r'c:\ProgramData\Packages',
        r'c:\Program Files\WindowsApps',
        r'c:\Windows\SystemApps',
    ]
    for location in locations:
        search_pattern = fr'{location}\{package_name}*_*'
        match = glob.glob(search_pattern, recursive=False)
        delete_it(match, text_box)
        delete_it(match, text_box)
# [3] C:\Windows\WinSxS\FileMaps\
def file_folders3(package_name, text_box):
    pattern = fr'c:\Windows\WinSxS\FileMaps\$$_systemapps_{package_name}_*'
    match = glob.glob(pattern, recursive=False)
    delete_it(match, text_box)
    delete_it(match, text_box)
# [4] C:\Users\NAME\AppData\Local\Packages
def file_folders4(package_name, text_box):
    usernames = [name for name in os.listdir(r"C:\Users") if os.path.isdir(os.path.join(r"C:\Users", name))]
    for username in usernames:
        user_directory = os.path.join(r"C:\Users", username, r"AppData\Local\Packages")
        if os.path.isdir(user_directory):
            for root, dirs, files in os.walk(user_directory):
                for folder_name in list(dirs):
                    if folder_name.startswith(package_name + "_"):
                        match = os.path.join(root, folder_name)
                        delete_it([match], text_box)
                        delete_it([match], text_box)

#================================================================================================#
#   Button Functions                                                                             #
#================================================================================================#
def display_status(message, text_box, is_green=False):
    if not message:  # Check if the message is empty or None
        return       # Ignore the function
    if is_green:
        text_box.insert(tk.END, message + '\n', 'green')  #Apply 'green' tag to the message
        text_box.tag_config('green', foreground='green')  #Configure the 'green' tag
    else:
        text_box.configure(font=tkfont.Font(size=8))      #Configure the font size
        text_box.insert(tk.END, message + '\n')           #Insert only the first 50 characters of the message
    text_box.see(tk.END)
    # Save Log
    with open(r'C:\ProgramData\ShadowWhisperer\Apps\uninstall.log', 'a') as log_file:
        log_file.write(message + '\n')


#Goes through all version of the app
def remove_apps_vers(package_name):
    app_full = next((app_data["full_name"].split(',') for app_data in app_data_list if app_data["name"] == package_name), None)
    if app_full is not None:
        for full_name in app_full:
          #################################################################
            #Create end of life / Deprovisioned keys
            winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\EndOfLife\\{user_sid}\\{full_name}")
            winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\EndOfLife\\S-1-5-18\\{full_name}")
            winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, f"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore\\Deprovisioned\\{full_name}")
          #################################################################
          # Run uninstaller
            subprocess.run(f'PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Remove-AppxPackage -Package \'{full_name}\'" -ErrorAction SilentlyContinue', startupinfo=hide_console())
            subprocess.run(f'PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxProvisionedPackage -Online | where-object {{ $_.PackageFullName -eq \'{full_name}\' }} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue"', startupinfo=hide_console())
          #################################################################
          # Run uninstaller - Again
            subprocess.run(f'PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Remove-AppxPackage -Package \'{full_name}\'" -ErrorAction SilentlyContinue', startupinfo=hide_console())
            subprocess.run(f'PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxProvisionedPackage -Online | where-object {{ $_.PackageFullName -eq \'{full_name}\' }} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue"', startupinfo=hide_console())
          #################################################################
    else:
        return


#Start Uninstaller
def remove_apps():
    status_window = tk.Toplevel()
    if REM: #Remnants
        status_window.title("Remnants")
    else:
        status_window.title("Performing Exorcism")
    status_window.geometry("1250x200")  #width x height
    status_window.iconbitmap(icon_cross)
    status_window.attributes('-topmost', True)  #Make the window appear above everything else
    text_box = ScrolledText(status_window)
    text_box.pack(fill=tk.BOTH, expand=True)
    if opt != 'fast': subprocess.run(['powershell', '-Command', 'Checkpoint-Computer -Description "ShadowWhisperer - AppExorcist"'], check=True, startupinfo=hide_console())
    if REM: #Remnants
        display_status(f"Performing deep cleanse ...", text_box, is_green=True)
    def remove_apps_thread():
        total_apps = len(selected_apps)
        current_app = 0
        for item in selected_apps:
            current_app += 1
            if REM: #Remnants
                package_name = item
            else:
                package_name = app_list.set(item, "Package Name")
                if not package_name:
                    continue
                if opt == 'ext':
                    display_status("\n", text_box)
                display_status(f"({current_app}/{total_apps})  { package_name}", text_box, is_green=True)
                #Remove context menu
                RegContext(package_name,text_box)
                #Remove App
                remove_apps_vers(package_name)
                if opt == 'fast':
                    continue
          #################################################################
            wildcard_keys = registry_wild(package_name, user_sid)
            for key_path in wildcard_keys:
                registry(key_path,text_box)
          ##=============================================================##
            registry_specific(package_name,user_sid,text_box)
          ##=============================================================##
            root_key_str = "HKEY_CURRENT_USER"
            base_key_path = "SOFTWARE\\Classes"
            subkey = "FriendlyTypeName"
            for key_path in traverse_registry_keys(root_key_str, base_key_path, package_name, base_key_path, subkey):
                registry(key_path,text_box)
          ##=============================================================##
            root_key_str = "HKEY_CURRENT_USER"
            base_key_path = r"SOFTWARE\RegisteredApplications"
            global RegValue
            RegValue = True
            key_paths = registry_values(root_key_str, base_key_path, package_name)
            for key_path in key_paths:
                registry(key_path, text_box)
            RegValue = False
          ##=============================================================##
            root_key_str = "HKEY_USERS"
            base_key_path = fr"{user_sid}\SOFTWARE\RegisteredApplications"
            RegValue = True
            key_paths = registry_values(root_key_str, base_key_path, package_name)
            for key_path in key_paths:
                registry(key_path, text_box)
            RegValue = False
          #################################################################
            #Delete folders
            file_folders1                         #Deleted Apps
            file_folders2(package_name, text_box) #Multiple
            file_folders3(package_name, text_box) #C:\Windows\WinSxS\FileMaps\
            file_folders4(package_name, text_box) #C:\Users\NAME\AppData\Local\Packages
          #################################################################

        #Run these after the loop completes
        rebuild_database()                 #Rebuild list of installed apps
        hide_native_button_pressed = False #Native not hidden
        rebuild_list()                     #Rebuild shown lsit of apps

        #Fast =  Close logger
        if opt == 'fast':
            status_window.destroy()
            return

        #Finished message
        display_status("\nFinished!", text_box, is_green=True)
        display_status("Log: C:\\ProgramData\\ShadowWhisperer\\Apps\\uninstall.log", text_box)

    #Start the removal process in a separate thread
    remove_thread = threading.Thread(target=remove_apps_thread)
    remove_thread.start()
#################################################################

def remnants():
    buttons_disable()
    def remnants_close():
        REM = False   #Not removing remnants
        buttons_enable()
        remnants_box.destroy()
###############################################
    remnants_box = tk.Toplevel()
    remnants_box.title("Remnants")
    remnants_box.geometry("260x120")  #width x height
    remnants_box.iconbitmap(icon_cross)
    remnants_box.resizable(False, False)
    def remnants_remove():  #Perform the remnants removal process
#===========#
        with open(database_sw, "r") as f_sw, open(database_path, "r") as f_path:
            database_sw_data = json.load(f_sw)
            database_path_data = json.load(f_path)
        #Ignore Hidden Apps
        hide_no_apps_sw = [app["name"] for app in database_sw_data if app["hide"] == "no"]
        #Make sure selected apps are not installed
        global selected_apps
        selected_apps = [app for app in hide_no_apps_sw if app not in [entry["name"] for entry in database_path_data]]
        global REM
        REM = True
        remove_apps()
#===========#
        # Enable the remnants button after the process is complete
        remnants_close()
    #Text / buttons
    message_label = tk.Label(remnants_box, text="Delete traces of apps that are not installed?\n\nThis process will take a very long time.")
    message_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="n")
    confirm_button = tk.Button(remnants_box, text="Start", width=12, command=remnants_remove)
    confirm_button.grid(row=1, column=0, padx=10, pady=10, sticky="e")
    cancel_button = tk.Button(remnants_box, text="Cancel", width=12, command=remnants_close)
    cancel_button.grid(row=1, column=1, padx=10, pady=10, sticky="w")
    remnants_box.grid_columnconfigure(0, weight=1)
    remnants_box.grid_columnconfigure(1, weight=1)
    remnants_box.grid_rowconfigure(0, weight=1)
    remnants_box.grid_rowconfigure(1, weight=1)
    #Close button = remnants_close
    remnants_box.protocol("WM_DELETE_WINDOW", remnants_close)
    #Get the coordinates of the root window
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    #Calculate the center position relative to the root window
    center_x = root_x + root_width // 2 - remnants_box.winfo_reqwidth() // 2
    center_y = root_y + root_height // 2 - remnants_box.winfo_reqheight() // 2
    #Set the position of the remnants_box window
    remnants_box.geometry(f"+{center_x}+{center_y}")
    remnants_box.wait_window()

def select_bloat():
    apps_data = read_data()
    bloat_apps = [app_data["name"] for app_data in apps_data if app_data.get("bloat") == "yes"]
    for child in app_list.get_children():
        package_name = app_list.set(child, "Package Name")
        if package_name in bloat_apps:
            if child not in selected_apps:
                app_list.set(child, "✔", "✔")
                app_list.item(child, tags=("selected",))
                selected_apps.add(child)
        else:
            pass
    app_list.tag_configure("selected", foreground="green")


#Save list of apps not in main database
def save_apps_list():
    with open(database_path, 'r') as json_file:
        database_data = json.load(json_file)
    with open(database_sw, 'r') as json_file:
        database_sw_data = json.load(json_file)
    new_apps = []
    for app in database_data:
        if not any(entry['name'] == app['name'] for entry in database_sw_data):
            new_apps.append(app)
    apps_text = "\n".join([f"{app['name']},{app['info']}" for app in new_apps])
    save_path = r"C:\apps.txt"
    with open(save_path, "w") as file:
        file.write(apps_text)

def hide_native():
    global hide_native_button_pressed
    hide_native_button_pressed = not hide_native_button_pressed
    if hide_native_button_pressed:
        native_button.config(text="Show All")
        save_apps_list()
    else:
        native_button.config(text="Hide Native")
    rebuild_list()


#================================================================================================#
#   Button Enabled / Disabled                                                                    #
#================================================================================================#
def buttons_disable():
    bloat_button.config(state="disabled")
    native_button.config(state="disabled")
    remnants_button.config(state="disabled")
    remove_button.config(state="disabled")

def buttons_enable():
    bloat_button.config(state="normal")
    native_button.config(state="normal")
    remnants_button.config(state="normal")
    remove_button.config(state="normal")

#================================================================================================#
#   App List Box                                                                                 #
#================================================================================================#
def read_data():
    with open(database_path, 'r') as json_file:
        data = json.load(json_file)
    return data
def sort_column(treeview, col, reverse):
    data = [(treeview.set(child, col), child) for child in treeview.get_children()]
    data.sort(key=lambda x: x[0].lower() if x[0] not in ('', '?') else '[Not in database]', reverse=reverse)
    for index, (val, child) in enumerate(data):
        treeview.move(child, "", index)
    treeview.heading(col, command=lambda: sort_column(treeview, col, not reverse))
def clear_selection():
    global selected_apps
    selected_apps = set()
    app_list.tag_configure("selected", foreground="")
    for item in app_list.selection():
        app_list.set(item, "✔", "✘")
        app_list.item(item, tags="")
def rebuild_list():
    buttons_enable()
    REM = False                               #Not doing remnants
    clear_selection()                         #Clear selected list
    app_list.delete(*app_list.get_children()) #Clear app list
    app_data_list = list(read_data())         #Filtered app data list
    if hide_native_button_pressed:            #Check if Hide Native button is pressed
        app_data_list = [app_data for app_data in app_data_list if app_data.get("native") != "yes" and app_data.get("bloat") != "yes"]
    for app_data in app_data_list:
        values = ("\u2716",) + tuple('[Not in database]' if value in ('', '?', None) else value for value in app_data.values())
        app_list.insert("", tk.END, values=values)

#Fast or extended uninstall
def remove_type():
    confirm_box = tk.Toplevel()
    confirm_box.title("Removal Type")
    confirm_box.geometry("300x120")  #width x height
    confirm_box.iconbitmap(icon_cross)
    confirm_box.resizable(False, False)
    def type_fast():
        global opt
        opt="fast"
        confirm_box.destroy()
    def type_ext():
        global opt
        opt="ext"
        confirm_box.destroy()

    #Text / buttons
    message_text = """Basic:  Basic Removal

Purge:  Extended Scan"""
    message_label = tk.Label(confirm_box, text=message_text, justify="left", anchor="w")
    message_label.pack()
    message_label.grid(row=0, column=0, columnspan=2, padx=6, pady=6, sticky="n")
    fast_button = tk.Button(confirm_box, text="Basic", width=14, command=type_fast)
    fast_button.grid(row=1, column=0, padx=8, pady=8, sticky="e")
    ext_button = tk.Button(confirm_box, text="Purge", width=14, command=type_ext)
    ext_button.grid(row=1, column=1, padx=8, pady=8, sticky="w")
    confirm_box.grid_columnconfigure(0, weight=1)
    confirm_box.grid_columnconfigure(1, weight=1)
    confirm_box.grid_rowconfigure(0, weight=1)
    confirm_box.grid_rowconfigure(1, weight=1)
    #Get the coordinates of the root window
    root_x = root.winfo_rootx()
    root_y = root.winfo_rooty()
    root_width = root.winfo_width()
    root_height = root.winfo_height()
    #Calculate the center position relative to the root window
    center_x = root_x + root_width // 2 - confirm_box.winfo_reqwidth() // 2
    center_y = root_y + root_height // 2 - confirm_box.winfo_reqheight() // 2
    #Set the position of the confirm_box window
    confirm_box.geometry(f"+{center_x}+{center_y}")
    confirm_box.wait_window()


def remove_check():
    if not selected_apps: #Selected apps not blank
        return
    buttons_disable()     #Disable buttons
######################
    if REM: #Make sure Remnants is not set
        rebuild_list()
    else:
        remove_type()
######################
    if not opt:
        buttons_enable()
        return
    remove_apps()


#================================================================================================#
#   Main GUI                                                                                     #
#================================================================================================#
root = tk.Tk()
root.title("App Exorcist - 1/31/2024 - ShadowWhisperer")
root.geometry("1100x550")  #width x height
root.iconbitmap(icon_cross)

#Frame - buttons
button_frame = ttk.Frame(root)
button_frame.pack()
#Frame - app_list / scrollbar
frame = ttk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

#Buttons
remove_button = ttk.Button(button_frame, text="Remove", width=20, command=remove_check)
remove_button.grid(row=0, column=0, padx=10, pady=5)
bloat_button = ttk.Button(button_frame, text="Select Bloat", width=20, command=select_bloat)
bloat_button.grid(row=0, column=1, padx=10, pady=5)
native_button = ttk.Button(button_frame, text="Hide Native", width=20, command=hide_native)
native_button.grid(row=0, column=2, padx=10, pady=5)
remnants_button = ttk.Button(button_frame, text="Remnants", width=20, command=remnants)
remnants_button.grid(row=0, column=3, padx=10, pady=5)
exit_button = ttk.Button(button_frame, text="Exit", width=20, command=root.destroy)
exit_button.grid(row=0, column=4, padx=10, pady=5)

#Create / configure the treeview with sortable categories
app_list = ttk.Treeview(frame, columns=("✔", "Package Name", "Info", "Issues"), show="headings", selectmode=tk.BROWSE)
app_list.grid(row=0, column=0, sticky=tk.NSEW)
frame.rowconfigure(0, weight=1)

#Scrollbar
scrollbar = ttk.Scrollbar(frame, orient="vertical", command=app_list.yview)
scrollbar.grid(row=0, column=1, sticky=tk.NS)
frame.columnconfigure(1, weight=0)
app_list.configure(yscrollcommand=scrollbar.set)

#Heading / Column Settings
app_list.heading("Package Name", anchor="w")
app_list.heading("✔", anchor="w")
app_list.heading("Info", text="Name", anchor="w")
app_list.heading("Issues", anchor="w")
app_list.column("✔", width=30, anchor="center", stretch='no')  # Make 'Select' column small
app_list.column("Package Name", anchor="w", stretch='yes')
app_list.column("Info", anchor="w", stretch='yes')
app_list.column("Issues", anchor="w", stretch='yes')

#Populate the app list
app_data_list = list(read_data())
for app_data in app_data_list:
    values = ("\u2716",) + tuple('[Not in database]' if value in ('', '?', None) else value for value in app_data.values())
    app_list.insert("", tk.END, values=values)
selected_apps = set() #Keep track of selected apps

#Config the treeview column headings and sorting
columns = ("✔", "Package Name", "Info", "Issues")
sort_column(app_list, "Info", False) #Sort "Info" A-Z *On launch
for col in columns:
    app_list.heading(col, text=col, command=lambda c=col: sort_column(app_list, c, False))

#Config grid layout to expand both columns (Make list fill the window)
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=0)

#Toggle the checkbox, text color
def toggle_checkbox(event):
    item = app_list.identify_row(event.y)
    checkbox_state = app_list.set(item, "✔")
    if checkbox_state == "✔":
        new_state = "✘"
        selected_apps.discard(item)
    else:
        new_state = "✔"
        selected_apps.add(item)
    app_list.set(item, "✔", new_state)
    app_list.item(item, tags=("selected" if new_state == "✔" else "",))
    app_list.tag_configure("selected", foreground="green")
    app_list.tag_configure("", foreground="")

app_list.bind("<Button-1>", toggle_checkbox) #Double-click to toggle checkbox

# Start
root.mainloop()
