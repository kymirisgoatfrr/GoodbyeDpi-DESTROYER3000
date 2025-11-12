# GoodbyeDpi-DESTROYER3000
This script comprehensively searches the entire system for all files, services, and components related to GoodbyeDPI and GoodbyeDPI-Turkey and forcefully removes them using powershell and safe mode.

> [!CAUTION]
> ### Use at your own risk. See [LICENSE](LICENSE) and read gray text below.

> I wrote this for a friend struggling to delete GoodbyeDPI. This is untested long code and I advise you to check and tweak the code yourself if you see something that could potentially harm your computer trying to delete and stop GoodbyeDPI and all of it's relics.

> I do not advise you to run this without checking for security mistakes YOURSELF. Learn coding.

> This is a very powerful tool. I do not want you to compeletly and blindly trust me on this tool.


Tutorial:

1-Install/Clone this repository

2-Open a Powershell with Admin Privileges and run "Get-ExecutionPolicy"

2,5-If the result isn't Bypass or Allsigned, run "Set-ExecutionPolicy -ExecutionPolicy AllSigned"

3-Reboot in SafeMode

4-Either Sign the script yourself, or make a new text file and copy the script there

5-Run that script [(Remove-GoodbyeDPI-Complete.ps1)](Remove-GoodbyeDPI-Complete.ps1) in an Admin Powershell

6-You're free of GoodbyeDPI and all the misery it caused to your mental health trying to remove it and your computer's connection. You can restart your computer now and enjoy the remaining of your life as a free man.

### SCRIPT INFO
    
   Features:
   - Kills all running GoodbyeDPI processes (including process trees)
   - Searches ALL drives on the system for related files (including network shares)
   - Content-based file scanning (scans file contents for GoodbyeDPI strings)
   - Archive file handling (ZIP/7Z/RAR/TAR/GZ - extracts and verifies before deletion)
   - File signature verification (verifies files are actually GoodbyeDPI, not system files)
   - Protects Windows system files from accidental deletion with multiple safety checks
   - Detects Safe Mode and optimizes behavior accordingly
   - Removes services, scheduled tasks, registry entries, and files
   - Handles driver files in system directories safely with content verification
   - Multi-user support (checks all user profiles)
   - Browser download folder checking (Chrome, Firefox, Edge)
   - Recycle Bin cleanup
   - Temp directory scanning for all users
   - Network share scanning
   - File association checking
   - Event log checking
   - Shadow copy awareness
   - Retry logic with exponential backoff for locked files
   - Reboot scheduling for files that can't be deleted immediately
   - Comprehensive summary report with detailed statistics
    
PARAMETERS

This script does not accept parameters. Run it as Administrator.

NOTES
- MUST be run as Administrator
- Best results when run in Safe Mode (prevents GoodbyeDPI from running)
- System directories are protected to prevent accidental deletion of Windows files
- If files can't be deleted, reboot into Safe Mode and run again
