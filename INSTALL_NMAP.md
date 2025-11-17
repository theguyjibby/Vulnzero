# Installing Nmap on Windows

The `dashboard/targets` endpoint requires the Nmap executable to be installed on your system. Follow one of these methods:

## Method 1: Install via Chocolatey (Recommended - Requires Admin)

1. Open PowerShell or Command Prompt **as Administrator**
2. Run: `choco install nmap -y`
3. Restart your terminal/IDE

## Method 2: Manual Installation

1. Download Nmap from: https://nmap.org/download.html
   - Choose the Windows installer (latest stable release)
   
2. Run the installer and **IMPORTANT**: 
   - Check the box "Add Nmap to system PATH" during installation
   - Complete the installation

3. **Restart your terminal/IDE** (or restart your computer) to refresh the PATH

4. Verify installation:
   ```powershell
   nmap --version
   ```

## Method 3: Add to PATH Manually (If Already Installed)

If Nmap is already installed but not in PATH:

1. Find where Nmap is installed (usually `C:\Program Files (x86)\Nmap\` or `C:\Program Files\Nmap\`)

2. Add to PATH:
   - Press `Win + R`, type `sysdm.cpl`, press Enter
   - Go to "Advanced" tab → "Environment Variables"
   - Under "System variables", select "Path" → "Edit"
   - Click "New" and add: `C:\Program Files (x86)\Nmap\` (or your Nmap installation path)
   - Click "OK" to save
   - **Restart your terminal/IDE**

3. Verify:
   ```powershell
   nmap --version
   ```

## After Installation

Once Nmap is installed, the `scan.py` module will automatically detect it. If it's installed in a standard location but not in PATH, the code will try to find it automatically.

If you still encounter issues, make sure to:
- Restart your terminal/IDE after installation
- Verify nmap works: `nmap --version`
- Check that the path is correct in Environment Variables

