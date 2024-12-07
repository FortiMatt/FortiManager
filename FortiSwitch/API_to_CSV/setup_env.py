import os
import subprocess

def create_virtual_environment(env_name="venv"):
    """Create a virtual environment."""
    if os.path.exists(env_name):
        print(f"[!] Virtual environment '{env_name}' already exists.")
        return

    print(f"[+] Creating virtual environment '{env_name}'...")
    subprocess.run(["python3", "-m", "venv", env_name], check=True)
    print(f"[+] Virtual environment '{env_name}' created successfully.")

def install_dependencies(env_name="venv"):
    """Install required dependencies and generate requirements.txt."""
    requirements = [
        "requests",
        "urllib3",
        "retry"
    ]

    print("[+] Activating the virtual environment...")
    activate_script = os.path.join(env_name, "bin", "activate") if os.name != "nt" else os.path.join(env_name, "Scripts", "activate.bat")
    
    if not os.path.exists(activate_script):
        print(f"[-] Activation script not found at '{activate_script}'. Ensure the virtual environment was created successfully.")
        return

    # Install dependencies
    print("[+] Installing required dependencies...")
    for req in requirements:
        subprocess.run([os.path.join(env_name, "bin", "pip") if os.name != "nt" else os.path.join(env_name, "Scripts", "pip"), "install", req], check=True)
    print("[+] Dependencies installed successfully.")

    # Generate requirements.txt
    print("[+] Generating requirements.txt...")
    subprocess.run([os.path.join(env_name, "bin", "pip") if os.name != "nt" else os.path.join(env_name, "Scripts", "pip"), "freeze"], stdout=open("requirements.txt", "w"), check=True)
    print("[+] requirements.txt generated successfully.")

def main():
    print("This script will help you set up a virtual environment and generate a requirements.txt file.")
    env_name = input("Enter the name for your virtual environment (default: 'venv'): ").strip() or "venv"

    try:
        create_virtual_environment(env_name)
        install_dependencies(env_name)
        print("\n[+] Setup complete. To activate the virtual environment, run:")
        if os.name == "nt":
            print(f"   {env_name}\\Scripts\\activate")
        else:
            print(f"   source {env_name}/bin/activate")
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred: {e}")
    except Exception as ex:
        print(f"[-] Unexpected error: {ex}")

if __name__ == "__main__":
    main()

