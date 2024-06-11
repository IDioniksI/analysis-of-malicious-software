import psutil


def is_dll_injection(process):
    """The function checks the process for DLL injection"""
    suspicious_dlls = ["KERNEL32.dll", "CRYPT32.dll", "encryption.dll"]
    if process['cmdline'] is not None:
        for dll in process['cmdline']:
            if any(sus_dll.lower() in dll.lower() for sus_dll in suspicious_dlls):
                return True
    return False


def is_process_hollowing(process):
    """The function checks the process for Process Hollowing"""
    try:
        process_info = psutil.Process(process['pid'])
        original_size = process_info.memory_info().rss
        current_size = process_info.memory_info().rss

        if current_size != original_size:
            return True

        elif process['cmdline'] is not None:
            suspicious_args = ["stealth", "hide", "delete", "destroy", "malware", "trojan", "hollow", "privileged"]
            for arg in process['cmdline']:
                if any(sus_arg.lower() in arg.lower() for sus_arg in suspicious_args):
                    return True

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    return False


def detect_injection(process):
    """The function detects DLL injection and Process Hollowing"""
    if is_dll_injection(process):
        print(f"Potential DLL injection detected in process {process['name']} (PID: {process['pid']})")

    if is_process_hollowing(process):
        print(f"Potential Process Hollowing detected in process {process['name']} (PID: {process['pid']})")


def main():
    """The main function that runs the script"""
    try:
        while True:
            for process in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                detect_injection(process.info)
    except KeyboardInterrupt:
        print("The user canceled the execution of the script.")


main()
