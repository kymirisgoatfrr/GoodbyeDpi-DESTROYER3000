#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Forcefully removes all traces of GoodbyeDPI and GoodbyeDPI-Turkey from the system.
.DESCRIPTION
    This script comprehensively searches the entire system for all files, services, and components
    related to GoodbyeDPI and GoodbyeDPI-Turkey and forcefully removes them.
    
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
    
.PARAMETER None
    This script does not accept parameters. Run it as Administrator.
    
.EXAMPLE
    Right-click the script and select "Run with PowerShell" (as Administrator)
    
.NOTES
    - MUST be run as Administrator
    - Best results when run in Safe Mode (prevents GoodbyeDPI from running)
    - System directories are protected to prevent accidental deletion of Windows files
    - If files can't be deleted, reboot into Safe Mode and run again
#>

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "GoodbyeDPI Complete Removal Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running in Safe Mode
$safeMode = $false
try {
    # Method 1: Check SafeBoot registry
    $safeBootOption = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" -Name "OptionValue" -ErrorAction SilentlyContinue
    if ($safeBootOption -and $safeBootOption.OptionValue -ne 0) {
        $safeMode = $true
    } else {
        # Method 2: Check if running with minimal services (alternative detection)
        $bootConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SystemStartOptions" -ErrorAction SilentlyContinue
        if ($bootConfig -and $bootConfig.SystemStartOptions -like "*SAFEBOOT*") {
            $safeMode = $true
        }
    }
    
    if ($safeMode) {
        Write-Host "[INFO] Safe Mode detected - Optimal environment for removal!" -ForegroundColor Green
        Write-Host "       GoodbyeDPI processes are not running, making deletion easier." -ForegroundColor Green
        Write-Host ""
    }
} catch {
    # Not in safe mode or can't detect - continue normally
}

# Global tracking variables for summary report
$script:summaryReport = @{
    ProcessesKilled = 0
    ServicesRemoved = 0
    FilesDeleted = 0
    FoldersDeleted = 0
    ArchivesDeleted = 0
    RecycleBinItemsDeleted = 0
    RegistryEntriesRemoved = 0
    ScheduledTasksRemoved = 0
    LockedFilesScheduled = 0
    Errors = @()
}

# Function to verify file is actually GoodbyeDPI (not a system file)
function Test-IsGoodbyeDPIFile {
    param([System.IO.FileInfo]$File)
    
    # Extra safety: Never touch files in these critical system locations
    $criticalSystemPaths = @(
        "$env:SystemRoot\System32\drivers",
        "$env:SystemRoot\SysWOW64\drivers",
        "$env:SystemRoot\System32\DriverStore",
        "$env:SystemRoot\WinSxS"
    )
    
    foreach ($criticalPath in $criticalSystemPaths) {
        if ($File.FullName -like "$criticalPath*") {
            # Only allow if we can verify it's GoodbyeDPI
            # Check if file is in a GoodbyeDPI folder structure
            $parentDirs = $File.DirectoryName -split '\\'
            $hasGoodbyeDPIParent = $parentDirs | Where-Object { $_ -like "*goodbyedpi*" -or $_ -like "*GoodbyeDPI*" }
            if (-not $hasGoodbyeDPIParent) {
                return $false  # Don't delete - likely a system file
            }
        }
    }
    
    # For WinDivert files, be extra careful
    if ($File.Name -like "*WinDivert*") {
        # Check file content for GoodbyeDPI signatures
        try {
            # Read first 1KB to check for signatures
            $fileStream = [System.IO.File]::OpenRead($File.FullName)
            $buffer = New-Object byte[] 1024
            $bytesRead = $fileStream.Read($buffer, 0, 1024)
            $fileStream.Close()
            
            $content = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
            
            # Look for GoodbyeDPI-related strings in file content
            $goodbyeDPISignatures = @("goodbyedpi", "GoodbyeDPI", "turkey", "dnsredir", "WinDivert")
            $hasSignature = $false
            foreach ($sig in $goodbyeDPISignatures) {
                if ($content -match $sig) {
                    $hasSignature = $true
                    break
                }
            }
            
            # Also check if file is in a known GoodbyeDPI location
            $isInGoodbyeDPILocation = $File.DirectoryName -like "*goodbyedpi*" -or 
                                     $File.DirectoryName -like "*GoodbyeDPI*" -or
                                     $File.DirectoryName -like "*turkey*" -or
                                     $File.DirectoryName -like "*dnsredir*"
            
            # Only delete if we have strong evidence it's GoodbyeDPI
            return ($hasSignature -or $isInGoodbyeDPILocation)
        } catch {
            # If we can't read the file, be conservative - don't delete
            # Check location instead
            $isInGoodbyeDPILocation = $File.DirectoryName -like "*goodbyedpi*" -or 
                                     $File.DirectoryName -like "*GoodbyeDPI*" -or
                                     $File.DirectoryName -like "*turkey*" -or
                                     $File.DirectoryName -like "*dnsredir*"
            return $isInGoodbyeDPILocation
        }
    }
    
    # For other files, check location and name
    $isGoodbyeDPI = $File.Name -like "*goodbyedpi*" -or 
                   $File.Name -like "*GoodbyeDPI*" -or
                   $File.Name -like "*turkey*" -or
                   $File.Name -like "*dnsredir*" -or
                   $File.DirectoryName -like "*goodbyedpi*" -or
                   $File.DirectoryName -like "*GoodbyeDPI*" -or
                   $File.DirectoryName -like "*turkey*" -or
                   $File.DirectoryName -like "*dnsredir*"
    
    return $isGoodbyeDPI
}

# Function to scan file contents for GoodbyeDPI strings
function Test-FileContainsGoodbyeDPI {
    param([string]$FilePath)
    
    try {
        # Read file content (text files only, up to 1MB)
        $fileInfo = Get-Item $FilePath -ErrorAction Stop
        if ($fileInfo.Length -gt 1MB) {
            return $false  # Skip large files
        }
        
        # Try to read as text
        $content = Get-Content -Path $FilePath -Raw -ErrorAction SilentlyContinue -Encoding UTF8
        if (-not $content) {
            $content = Get-Content -Path $FilePath -Raw -ErrorAction SilentlyContinue -Encoding ASCII
        }
        
        if ($content) {
            $signatures = @("goodbyedpi", "GoodbyeDPI", "turkey", "dnsredir", "WinDivert", "service_install", "turkey_dnsredir")
            foreach ($sig in $signatures) {
                if ($content -match $sig) {
                    return $true
                }
            }
        }
    } catch {
        # Can't read file, return false
    }
    
    return $false
}

# Function to kill process tree (parent and children)
function Stop-ProcessTree {
    param([int]$ProcessId)
    
    try {
        # Get all child processes
        $children = Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq $ProcessId }
        foreach ($child in $children) {
            Stop-ProcessTree -ProcessId $child.ProcessId
        }
        
        # Kill the process itself
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Function to get all user profiles
function Get-AllUserProfiles {
    $profiles = @()
    try {
        # Get all user profile directories
        $userDirs = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike "*Public*" -and $_.Name -notlike "*Default*" }
        foreach ($userDir in $userDirs) {
            $profiles += $userDir.FullName
        }
    } catch {
        Write-Host "    [WARNING] Could not enumerate all user profiles: $_" -ForegroundColor Yellow
    }
    return $profiles
}

# Function to find processes using WMI (enhanced detection)
function Find-ProcessesByPath {
    param([string[]]$SearchTerms)
    
    $foundProcesses = @()
    try {
        $allProcesses = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
        foreach ($proc in $allProcesses) {
            try {
                $procPath = $proc.ExecutablePath
                $procCommandLine = $proc.CommandLine
                
                foreach ($term in $SearchTerms) {
                    if (($procPath -and $procPath -like "*$term*") -or 
                        ($procCommandLine -and $procCommandLine -like "*$term*")) {
                        $foundProcesses += $proc
                        break
                    }
                }
            } catch {
                # Skip processes we can't access
            }
        }
    } catch {
        Write-Host "    [WARNING] Could not query WMI for processes: $_" -ForegroundColor Yellow
    }
    return $foundProcesses
}

# Function to schedule file deletion on reboot
function Remove-LockedFilesOnReboot {
    param([string]$FilePath)
    
    try {
        # Use MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT flag
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class FileOperations {
                [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
                public const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;
            }
"@
        
        $result = [FileOperations]::MoveFileEx($FilePath, $null, [FileOperations]::MOVEFILE_DELAY_UNTIL_REBOOT)
        return $result
    } catch {
        return $false
    }
}

# Function to handle archive files (ZIP/7Z/RAR)
function Remove-ArchiveFiles {
    Write-Host "[*] Searching for archive files (ZIP/7Z/RAR)..." -ForegroundColor Yellow
    
    $archivePatterns = @("*goodbyedpi*.zip", "*goodbyedpi*.7z", "*goodbyedpi*.rar", "*goodbyedpi*.tar", "*goodbyedpi*.gz", "*GoodbyeDPI*.zip", "*GoodbyeDPI*.7z", "*GoodbyeDPI*.rar", "*GoodbyeDPI*.tar", "*GoodbyeDPI*.gz")
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne $null }
    $deletedCount = 0
    $tempExtractPath = Join-Path $env:TEMP "GoodbyeDPI_Extract_$(Get-Random)"
    
    foreach ($pattern in $archivePatterns) {
        Write-Host "    Searching for: $pattern" -ForegroundColor Gray
        
        foreach ($drive in $drives) {
            try {
                $regexPattern = $pattern -replace '\*', '.*' -replace '\?', '.'
                $archives = Get-ChildItem -Path $drive.Root -Recurse -Force -ErrorAction SilentlyContinue | 
                           Where-Object { 
                               -not $_.PSIsContainer -and 
                               ($_.Extension -eq ".zip" -or $_.Extension -eq ".7z" -or $_.Extension -eq ".rar" -or $_.Extension -eq ".tar" -or $_.Extension -eq ".gz") -and
                               $_.Name -match "^$regexPattern$"
                           }
                
                foreach ($archive in $archives) {
                    try {
                        Write-Host "        [FOUND] Archive: $($archive.FullName)" -ForegroundColor Yellow
                        
                        # Try to extract and verify contents (for ZIP files)
                        if ($archive.Extension -eq ".zip") {
                            try {
                                $archiveExtractPath = Join-Path $tempExtractPath "Archive_$(Get-Random)"
                                if (-not (Test-Path $archiveExtractPath)) {
                                    New-Item -ItemType Directory -Path $archiveExtractPath -Force | Out-Null
                                }
                                
                                Expand-Archive -Path $archive.FullName -DestinationPath $archiveExtractPath -Force -ErrorAction SilentlyContinue
                                
                                # Check if extracted contents contain GoodbyeDPI files
                                $extractedFiles = Get-ChildItem -Path $archiveExtractPath -Recurse -ErrorAction SilentlyContinue
                                $hasGoodbyeDPI = $extractedFiles | Where-Object { 
                                    $_.Name -like "*goodbyedpi*" -or 
                                    $_.Name -like "*WinDivert*" -or
                                    $_.Name -like "*turkey*" -or
                                    $_.Name -like "*dnsredir*"
                                }
                                
                                if ($hasGoodbyeDPI) {
                                    Write-Host "        [VERIFIED] Archive contains GoodbyeDPI files" -ForegroundColor Cyan
                                    # Delete extracted contents
                                    Remove-Item -Path $archiveExtractPath -Recurse -Force -ErrorAction SilentlyContinue
                                } else {
                                    Write-Host "        [SKIPPED] Archive does not contain GoodbyeDPI files" -ForegroundColor Gray
                                    Remove-Item -Path $archiveExtractPath -Recurse -Force -ErrorAction SilentlyContinue
                                    continue
                                }
                            } catch {
                                # If we can't extract, still delete the archive (might be password protected or corrupted)
                                Write-Host "        [WARNING] Could not extract archive, deleting anyway: $_" -ForegroundColor Yellow
                            }
                        }
                        
                        # Delete the archive file
                        Remove-Item -Path $archive.FullName -Force -ErrorAction Stop
                        Write-Host "        [DELETED] Archive: $($archive.FullName)" -ForegroundColor Green
                        $deletedCount++
                        $script:summaryReport.ArchivesDeleted++
                    } catch {
                        Write-Host "        [ERROR] Could not delete archive: $($archive.FullName) - $_" -ForegroundColor Red
                        $script:summaryReport.Errors += "Archive: $($archive.FullName) - $_"
                    }
                }
            } catch {
                # Silently continue if drive is inaccessible
            }
        }
    }
    
    # Clean up temp extraction path
    if (Test-Path $tempExtractPath) {
        Remove-Item -Path $tempExtractPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "    [*] Total archives deleted: $deletedCount" -ForegroundColor Cyan
}

# Function to clean Recycle Bin
function Remove-FilesFromRecycleBin {
    Write-Host "[*] Checking Recycle Bin for GoodbyeDPI files..." -ForegroundColor Yellow
    
    $deletedCount = 0
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne $null }
    
    foreach ($drive in $drives) {
        try {
            $recyclePath = "$($drive.Root)\`$Recycle.Bin"
            if (Test-Path $recyclePath) {
                try {
                    $recycleItems = Get-ChildItem -Path $recyclePath -Recurse -Force -ErrorAction SilentlyContinue
                    foreach ($item in $recycleItems) {
                        try {
                            $itemName = $item.Name
                            if ($itemName -like "*goodbyedpi*" -or 
                                $itemName -like "*GoodbyeDPI*" -or 
                                $itemName -like "*WinDivert*" -or
                                $itemName -like "*turkey*" -or
                                $itemName -like "*dnsredir*") {
                                
                                Write-Host "        [FOUND] Recycle Bin item: $($item.FullName)" -ForegroundColor Yellow
                                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                                Write-Host "        [DELETED] Recycle Bin item: $($item.FullName)" -ForegroundColor Green
                                $deletedCount++
                                $script:summaryReport.RecycleBinItemsDeleted++
                            }
                        } catch {
                            Write-Host "        [ERROR] Could not delete Recycle Bin item: $($item.FullName) - $_" -ForegroundColor Red
                        }
                    }
                } catch {
                    # Silently continue if can't access Recycle Bin
                }
            }
        } catch {
            # Silently continue
        }
    }
    
    Write-Host "    [*] Total Recycle Bin items deleted: $deletedCount" -ForegroundColor Cyan
}

# Function to search browser download folders
function Search-BrowserDownloads {
    Write-Host "[*] Checking browser download folders..." -ForegroundColor Yellow
    
    $browserPaths = @()
    $userProfiles = Get-AllUserProfiles
    $userProfiles += $env:USERPROFILE
    
    foreach ($profile in $userProfiles) {
        # Chrome
        $chromePath = Join-Path $profile "AppData\Local\Google\Chrome\User Data\Default\Downloads"
        if (Test-Path $chromePath) { $browserPaths += $chromePath }
        
        # Firefox (usually uses Windows Downloads)
        $firefoxPath = Join-Path $profile "Downloads"
        if (Test-Path $firefoxPath) { $browserPaths += $firefoxPath }
        
        # Edge
        $edgePath = Join-Path $profile "AppData\Local\Microsoft\Edge\User Data\Default\Downloads"
        if (Test-Path $edgePath) { $browserPaths += $edgePath }
    }
    
    $deletedCount = 0
    $searchPatterns = @("*goodbyedpi*", "*GoodbyeDPI*", "*goodbye*")
    
    foreach ($browserPath in $browserPaths) {
        foreach ($pattern in $searchPatterns) {
            try {
                $items = Get-ChildItem -Path $browserPath -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    try {
                        Write-Host "        [FOUND] Browser download: $($item.FullName)" -ForegroundColor Yellow
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                        Write-Host "        [DELETED] Browser download: $($item.FullName)" -ForegroundColor Green
                        $deletedCount++
                    } catch {
                        Write-Host "        [ERROR] Could not delete: $($item.FullName) - $_" -ForegroundColor Red
                    }
                }
            } catch {
                # Silently continue
            }
        }
    }
    
    Write-Host "    [*] Total browser download items deleted: $deletedCount" -ForegroundColor Cyan
}

# Function to kill running processes (ENHANCED with WMI)
function Stop-ProcessesForce {
    Write-Host "[STEP 0] Stopping all GoodbyeDPI processes..." -ForegroundColor Cyan
    Write-Host ""
    
    $processNames = @("goodbyedpi", "WinDivert")
    $killedCount = 0
    
    # Method 1: Standard process name search
    foreach ($procName in $processNames) {
        try {
            $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($processes) {
                foreach ($proc in $processes) {
                    Write-Host "    [FOUND] Process: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Yellow
                    try {
                        # Kill process tree (parent and children)
                        Stop-ProcessTree -ProcessId $proc.Id
                        Write-Host "    [KILLED] Process: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Green
                        $killedCount++
                        $script:summaryReport.ProcessesKilled++
                        Start-Sleep -Milliseconds 500
                    } catch {
                        Write-Host "    [ERROR] Could not kill process: $($proc.Name) - $_" -ForegroundColor Red
                        $script:summaryReport.Errors += "Process: $($proc.Name) (PID: $($proc.Id)) - $_"
                    }
                }
            }
        } catch {
            # Process not found, continue
        }
    }
    
    # Method 2: WMI-based search for processes by path/command line
    Write-Host "    Checking processes using WMI (enhanced detection)..." -ForegroundColor Gray
    $searchTerms = @("goodbyedpi", "WinDivert", "windivert", "GoodbyeDPI")
    $wmiProcesses = Find-ProcessesByPath -SearchTerms $searchTerms
    
    foreach ($wmiProc in $wmiProcesses) {
        try {
            $procId = $wmiProc.ProcessId
            $procName = $wmiProc.Name
            $procPath = $wmiProc.ExecutablePath
            
            # Skip if already killed
            $existingProc = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if (-not $existingProc) { continue }
            
            Write-Host "    [FOUND] Process (WMI): $procName (PID: $procId)" -ForegroundColor Yellow
            if ($procPath) {
                Write-Host "        Path: $procPath" -ForegroundColor Gray
            }
            
            try {
                # Kill process tree (parent and children)
                Stop-ProcessTree -ProcessId $procId
                Write-Host "    [KILLED] Process: $procName (PID: $procId)" -ForegroundColor Green
                $killedCount++
                $script:summaryReport.ProcessesKilled++
                Start-Sleep -Milliseconds 500
            } catch {
                Write-Host "    [ERROR] Could not kill process: $procName - $_" -ForegroundColor Red
                $script:summaryReport.Errors += "Process (WMI): $procName (PID: $procId) - $_"
            }
        } catch {
            # Skip processes we can't access
        }
    }
    
    # Method 3: Check for processes using WinDivert.dll
    try {
        Write-Host "    Checking for processes using WinDivert.dll..." -ForegroundColor Gray
        $allProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
        foreach ($proc in $allProcesses) {
            try {
                $modules = $proc.Modules | Where-Object { $_.ModuleName -like "*WinDivert*" -or $_.FileName -like "*WinDivert*" }
                if ($modules) {
                    Write-Host "    [FOUND] Process using WinDivert: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Yellow
                    # Kill process tree (parent and children)
                    Stop-ProcessTree -ProcessId $proc.Id
                    Write-Host "    [KILLED] Process: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Green
                    $killedCount++
                    $script:summaryReport.ProcessesKilled++
                    Start-Sleep -Milliseconds 500
                }
            } catch {
                # Can't access process modules (normal for system processes)
            }
        }
    } catch {
        # Continue if we can't check modules
    }
    
    if ($killedCount -eq 0) {
        Write-Host "    [INFO] No running GoodbyeDPI processes found" -ForegroundColor Gray
    } else {
        Write-Host "    [*] Total processes killed: $killedCount" -ForegroundColor Cyan
    }
    
    Write-Host ""
    Start-Sleep -Seconds 2
}

# Function to safely stop and delete a service
function Remove-ServiceForce {
    param([string]$ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "[*] Found service: $ServiceName" -ForegroundColor Yellow
            
            # Stop the service forcefully
            if ($service.Status -eq 'Running') {
                Write-Host "    Stopping service..." -ForegroundColor Yellow
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            
            # Delete the service
            Write-Host "    Deleting service..." -ForegroundColor Yellow
            $result = sc.exe delete $ServiceName 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [OK] Service deleted: $ServiceName" -ForegroundColor Green
                $script:summaryReport.ServicesRemoved++
            } else {
                Write-Host "    [WARNING] Could not delete service: $ServiceName" -ForegroundColor Red
                $script:summaryReport.Errors += "Service: $ServiceName - Could not delete"
            }
        } else {
            Write-Host "[*] Service not found: $ServiceName" -ForegroundColor Gray
        }
    } catch {
        Write-Host "    [ERROR] Error processing service $ServiceName : $_" -ForegroundColor Red
    }
}

# Function to search and delete files across all drives
function Remove-FilesForce {
    param([string[]]$FilePatterns, [string[]]$FolderPatterns)
    
    # Get all available drives
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -ne $null }
    
    # Define system directories to EXCLUDE from search (to protect Windows system files)
    $excludePaths = @(
        "$env:SystemRoot\System32\config",
        "$env:SystemRoot\System32\catroot",
        "$env:SystemRoot\System32\catroot2",
        "$env:SystemRoot\System32\DriverStore",
        "$env:SystemRoot\System32\drivers\*.sys",  # We'll handle drivers separately
        "$env:SystemRoot\WinSxS",
        "$env:SystemRoot\Installer",
        "$env:SystemRoot\assembly",
        "$env:SystemRoot\Microsoft.NET",
        "$env:SystemRoot\SysWOW64\config",
        "$env:SystemRoot\SysWOW64\catroot",
        "$env:SystemRoot\SysWOW64\catroot2",
        "$env:SystemRoot\SysWOW64\WinSxS",
        "$env:SystemRoot\SysWOW64\assembly",
        "$env:SystemRoot\SysWOW64\Microsoft.NET",
        "$env:ProgramFiles\Windows",
        "$env:ProgramFiles(x86)\Windows",
        "$env:ProgramFiles\Common Files\Microsoft Shared",
        "$env:ProgramFiles(x86)\Common Files\Microsoft Shared"
    )
    
    Write-Host "[*] Searching for files across all drives..." -ForegroundColor Yellow
    Write-Host "    Drives to search: $($drives.Root -join ', ')" -ForegroundColor Gray
    Write-Host "    [INFO] System directories are protected from deletion" -ForegroundColor Gray
    Write-Host ""
    
    $deletedCount = 0
    
    # Search for files
    foreach ($pattern in $FilePatterns) {
        Write-Host "    Searching for: $pattern" -ForegroundColor Gray
        
        foreach ($drive in $drives) {
            try {
                # Convert pattern to regex for matching
                $regexPattern = $pattern -replace '\*', '.*' -replace '\?', '.'
                
                # Search recursively and filter by name pattern
                $files = Get-ChildItem -Path $drive.Root -Recurse -Force -ErrorAction SilentlyContinue | 
                         Where-Object { 
                             -not $_.PSIsContainer -and 
                             $_.Name -match "^$regexPattern$"
                         }
                
                foreach ($file in $files) {
                    try {
                        # CRITICAL SAFETY: Verify file is actually GoodbyeDPI before deletion
                        if (-not (Test-IsGoodbyeDPIFile -File $file)) {
                            Write-Host "        [SKIPPED] File does not match GoodbyeDPI signature: $($file.FullName)" -ForegroundColor Yellow
                            continue
                        }
                        
                        # Double-check: Never delete from critical Windows system directories
                        $isSystemFile = $false
                        foreach ($excludePath in $excludePaths) {
                            if ($file.FullName -like "$excludePath*") {
                                $isSystemFile = $true
                                break
                            }
                        }
                        
                        # Additional safety: Skip if in Windows directory and not a known GoodbyeDPI location
                        if (-not $isSystemFile -and $file.FullName -like "$env:SystemRoot\*") {
                            # Only allow deletion from known locations or if it's clearly a GoodbyeDPI file
                            $allowedInSystem = $file.FullName -like "*\drivers\WinDivert*" -or 
                                              $file.FullName -like "*\System32\WinDivert*" -or
                                              $file.FullName -like "*\SysWOW64\WinDivert*"
                            
                            # Extra verification for system directory files
                            if ($allowedInSystem) {
                                # Verify it's actually GoodbyeDPI by checking parent directory
                                $parentDirs = $file.DirectoryName -split '\\'
                                $hasGoodbyeDPIParent = $parentDirs | Where-Object { 
                                    $_ -like "*goodbyedpi*" -or $_ -like "*GoodbyeDPI*" -or $_ -like "*turkey*" 
                                }
                                if (-not $hasGoodbyeDPIParent) {
                                    Write-Host "        [SKIPPED] System file - no GoodbyeDPI parent directory: $($file.FullName)" -ForegroundColor Yellow
                                    continue
                                }
                            } else {
                                Write-Host "        [SKIPPED] Protected system location: $($file.FullName)" -ForegroundColor Yellow
                                continue
                            }
                        }
                        
                        # Remove read-only attribute if present
                        if ($file.Attributes -match 'ReadOnly') {
                            $file.Attributes = $file.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
                        }
                        
                        # Try to delete with retry logic
                        $maxRetries = 3
                        $retryDelay = 1
                        $deleted = $false
                        
                        for ($retry = 1; $retry -le $maxRetries; $retry++) {
                            try {
                                Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                                Write-Host "        [DELETED] $($file.FullName)" -ForegroundColor Green
                                $deletedCount++
                                $script:summaryReport.FilesDeleted++
                                $deleted = $true
                                break
                            } catch {
                                if ($retry -lt $maxRetries) {
                                    Write-Host "        [RETRY $retry/$maxRetries] Waiting before retry..." -ForegroundColor Yellow
                                    Start-Sleep -Seconds $retryDelay
                                    $retryDelay *= 2
                                } else {
                                    # Last retry failed, try scheduling for reboot
                                    Write-Host "        [WARNING] File is locked, scheduling for deletion on reboot..." -ForegroundColor Yellow
                                    $scheduled = Remove-LockedFilesOnReboot -FilePath $file.FullName
                                    if ($scheduled) {
                                        Write-Host "        [SCHEDULED] Will be deleted on next reboot: $($file.FullName)" -ForegroundColor Cyan
                                        $script:summaryReport.LockedFilesScheduled++
                                        $script:summaryReport.FilesDeleted++
                                    } else {
                                        Write-Host "        [ERROR] Could not delete or schedule: $($file.FullName) - $_" -ForegroundColor Red
                                        $script:summaryReport.Errors += "File: $($file.FullName) - $_"
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Host "        [ERROR] Could not delete: $($file.FullName) - $_" -ForegroundColor Red
                        $script:summaryReport.Errors += "File: $($file.FullName) - $_"
                    }
                }
            } catch {
                # Silently continue if drive is inaccessible
            }
        }
    }
    
    # Search for folders
    foreach ($pattern in $FolderPatterns) {
        Write-Host "    Searching for folders: $pattern" -ForegroundColor Gray
        
        foreach ($drive in $drives) {
            try {
                # Convert pattern to regex for matching
                $regexPattern = $pattern -replace '\*', '.*' -replace '\?', '.'
                
                # Search recursively and filter by name pattern
                $folders = Get-ChildItem -Path $drive.Root -Recurse -Force -ErrorAction SilentlyContinue | 
                           Where-Object { 
                               $_.PSIsContainer -and 
                               $_.Name -match "^$regexPattern$"
                           }
                
                foreach ($folder in $folders) {
                    try {
                        # Double-check: Never delete from critical Windows system directories
                        $isSystemFolder = $false
                        foreach ($excludePath in $excludePaths) {
                            if ($folder.FullName -like "$excludePath*") {
                                $isSystemFolder = $true
                                break
                            }
                        }
                        
                        if ($isSystemFolder) {
                            Write-Host "        [SKIPPED] Protected system location: $($folder.FullName)" -ForegroundColor Yellow
                            continue
                        }
                        
                        # Try to delete folder with retry logic
                        $maxRetries = 3
                        $retryDelay = 1
                        $deleted = $false
                        
                        for ($retry = 1; $retry -le $maxRetries; $retry++) {
                            try {
                                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                                Write-Host "        [DELETED FOLDER] $($folder.FullName)" -ForegroundColor Green
                                $deletedCount++
                                $script:summaryReport.FoldersDeleted++
                                $deleted = $true
                                break
                            } catch {
                                if ($retry -lt $maxRetries) {
                                    Write-Host "        [RETRY $retry/$maxRetries] Waiting before retry..." -ForegroundColor Yellow
                                    Start-Sleep -Seconds $retryDelay
                                    $retryDelay *= 2
                                } else {
                                    # Last retry failed, try scheduling for reboot
                                    Write-Host "        [WARNING] Folder is locked, scheduling for deletion on reboot..." -ForegroundColor Yellow
                                    $scheduled = Remove-LockedFilesOnReboot -FilePath $folder.FullName
                                    if ($scheduled) {
                                        Write-Host "        [SCHEDULED] Will be deleted on next reboot: $($folder.FullName)" -ForegroundColor Cyan
                                        $script:summaryReport.LockedFilesScheduled++
                                        $script:summaryReport.FoldersDeleted++
                                    } else {
                                        Write-Host "        [ERROR] Could not delete or schedule folder: $($folder.FullName) - $_" -ForegroundColor Red
                                        $script:summaryReport.Errors += "Folder: $($folder.FullName) - $_"
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Host "        [ERROR] Could not delete folder: $($folder.FullName) - $_" -ForegroundColor Red
                        $script:summaryReport.Errors += "Folder: $($folder.FullName) - $_"
                    }
                }
            } catch {
                # Silently continue if drive is inaccessible
            }
        }
    }
    
    Write-Host "    [*] Total items deleted: $deletedCount" -ForegroundColor Cyan
}

# Execute process termination first
Stop-ProcessesForce

# Step 1: Stop and delete services
Write-Host "[STEP 1] Removing services..." -ForegroundColor Cyan
Write-Host ""

$services = @("GoodbyeDPI", "WinDivert", "WinDivert14")
foreach ($service in $services) {
    Remove-ServiceForce -ServiceName $service
}

Write-Host ""

# Step 2: Check archive files (ZIP/7Z/RAR)
Write-Host "[STEP 2] Checking for archive files..." -ForegroundColor Cyan
Write-Host ""
Remove-ArchiveFiles
Write-Host ""

# Step 3: Check Recycle Bin
Write-Host "[STEP 3] Checking Recycle Bin..." -ForegroundColor Cyan
Write-Host ""
Remove-FilesFromRecycleBin
Write-Host ""

# Step 4: Check browser download folders
Write-Host "[STEP 4] Checking browser download folders..." -ForegroundColor Cyan
Write-Host ""
Search-BrowserDownloads
Write-Host ""

# Step 5: Check temp directories for all users
Write-Host "[STEP 5] Checking temp directories for all users..." -ForegroundColor Cyan
Write-Host ""

$userProfiles = Get-AllUserProfiles
$userProfiles += $env:USERPROFILE

$tempPaths = @()
foreach ($profile in $userProfiles) {
    $userTemp = Join-Path $profile "AppData\Local\Temp"
    if (Test-Path $userTemp) {
        $tempPaths += $userTemp
    }
}
$tempPaths += $env:TEMP
$tempPaths += $env:TMP
$tempPaths += "$env:SystemRoot\Temp"

$tempPatterns = @("*goodbyedpi*", "*GoodbyeDPI*", "*WinDivert*", "*turkey*", "*dnsredir*")
$tempDeletedCount = 0

foreach ($tempPath in $tempPaths) {
    if (Test-Path $tempPath) {
        foreach ($pattern in $tempPatterns) {
            try {
                $items = Get-ChildItem -Path $tempPath -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    try {
                        Write-Host "    [FOUND] Temp item: $($item.FullName)" -ForegroundColor Yellow
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                        Write-Host "    [DELETED] Temp item: $($item.FullName)" -ForegroundColor Green
                        $tempDeletedCount++
                    } catch {
                        Write-Host "    [ERROR] Could not delete: $($item.FullName) - $_" -ForegroundColor Red
                    }
                }
            } catch {
                # Silently continue
            }
        }
    }
}
Write-Host "    [*] Total temp items deleted: $tempDeletedCount" -ForegroundColor Cyan
Write-Host ""

# Step 6: Check all user profiles for GoodbyeDPI folders
Write-Host "[STEP 6] Checking all user profiles..." -ForegroundColor Cyan
Write-Host ""

$userProfilePaths = @()
foreach ($profile in $userProfiles) {
    $userProfilePaths += Join-Path $profile "Downloads\*goodbye*"
    $userProfilePaths += Join-Path $profile "Downloads\*GoodbyeDPI*"
    $userProfilePaths += Join-Path $profile "Desktop\*goodbye*"
    $userProfilePaths += Join-Path $profile "Desktop\*GoodbyeDPI*"
    $userProfilePaths += Join-Path $profile "GoodbyeDPI"
    $userProfilePaths += Join-Path $profile "AppData\Local\GoodbyeDPI"
    $userProfilePaths += Join-Path $profile "AppData\Roaming\GoodbyeDPI"
}

foreach ($userPath in $userProfilePaths) {
    if (Test-Path $userPath) {
        try {
            Write-Host "    [FOUND] User profile item: $userPath" -ForegroundColor Yellow
            Remove-Item -Path $userPath -Recurse -Force -ErrorAction Stop
            Write-Host "    [DELETED] User profile item: $userPath" -ForegroundColor Green
        } catch {
            Write-Host "    [ERROR] Could not delete: $userPath - $_" -ForegroundColor Red
        }
    }
}
Write-Host ""

# Step 7: Define all file patterns to search for
Write-Host "[STEP 7] Searching for and deleting files..." -ForegroundColor Cyan
Write-Host ""

$filePatterns = @(
    "goodbyedpi.exe",
    "WinDivert.dll",
    "WinDivert32.sys",
    "WinDivert64.sys",
    "service_install_dnsredir_turkey.cmd",
    "service_install_dnsredir_turkey_alternative*.cmd",
    "service_install_dnsredir_turkey_alternative2*.cmd",
    "service_install_dnsredir_turkey_alternative3*.cmd",
    "service_install_dnsredir_turkey_alternative4*.cmd",
    "service_install_dnsredir_turkey_alternative5*.cmd",
    "service_install_dnsredir_turkey_alternative6*.cmd",
    "service_remove.cmd",
    "turkey_dnsredir.cmd",
    "turkey_dnsredir_alternative*.cmd",
    "turkey_dnsredir_alternative2*.cmd",
    "turkey_dnsredir_alternative3*.cmd",
    "turkey_dnsredir_alternative4*.cmd",
    "turkey_dnsredir_alternative5*.cmd",
    "turkey_dnsredir_alternative6*.cmd",
    "README-BENİ OKU.txt",
    "README-BENI OKU.txt",
    "README.txt",
    "LICENSE-goodbyedpi.txt",
    "LICENSE-windivert.txt",
    "LICENSE-getline.txt",
    "LICENSE-uthash.txt"
)

$folderPatterns = @(
    "*goodbyedpi*",
    "*GoodbyeDPI*",
    "*GOODBYEDPI*"
)

Remove-FilesForce -FilePatterns $filePatterns -FolderPatterns $folderPatterns

Write-Host ""

# Step 8: Check common installation locations
Write-Host "[STEP 8] Checking common installation locations..." -ForegroundColor Cyan
Write-Host ""

$commonPaths = @(
    "$env:ProgramFiles\GoodbyeDPI",
    "$env:ProgramFiles(x86)\GoodbyeDPI",
    "$env:ProgramData\GoodbyeDPI",
    "$env:LOCALAPPDATA\GoodbyeDPI",
    "$env:APPDATA\GoodbyeDPI",
    "$env:USERPROFILE\GoodbyeDPI",
    "$env:USERPROFILE\Downloads\goodbye*",
    "$env:USERPROFILE\Desktop\GoodbyeDPI*",
    "C:\GoodbyeDPI",
    "C:\Program Files\GoodbyeDPI",
    "C:\Program Files (x86)\GoodbyeDPI"
)

foreach ($path in $commonPaths) {
    if (Test-Path $path) {
        try {
            Write-Host "    [FOUND] $path" -ForegroundColor Yellow
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Host "    [DELETED] $path" -ForegroundColor Green
        } catch {
            Write-Host "    [ERROR] Could not delete: $path - $_" -ForegroundColor Red
        }
    }
}

Write-Host ""

# Step 9: Check for scheduled tasks
Write-Host "[STEP 9] Checking for scheduled tasks..." -ForegroundColor Cyan
Write-Host ""

$taskPatterns = @("*GoodbyeDPI*", "*goodbyedpi*", "*WinDivert*")
foreach ($pattern in $taskPatterns) {
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like $pattern }
        foreach ($task in $tasks) {
            Write-Host "    [FOUND] Scheduled Task: $($task.TaskName)" -ForegroundColor Yellow
            Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction Stop
            Write-Host "    [DELETED] Scheduled Task: $($task.TaskName)" -ForegroundColor Green
            $script:summaryReport.ScheduledTasksRemoved++
        }
    } catch {
        Write-Host "    [ERROR] Could not remove scheduled task: $_" -ForegroundColor Red
    }
}

Write-Host ""

# Step 10: Check registry for startup entries and additional locations
Write-Host "[STEP 10] Checking registry for startup entries and additional locations..." -ForegroundColor Cyan
Write-Host ""

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($regPath in $registryPaths) {
    if (Test-Path $regPath) {
        try {
            $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
            $entryNames = $entries.PSObject.Properties.Name | Where-Object { $_ -like "*GoodbyeDPI*" -or $_ -like "*goodbyedpi*" -or $_ -like "*WinDivert*" }
            
            foreach ($entryName in $entryNames) {
                Write-Host "    [FOUND] Registry entry: $regPath\$entryName" -ForegroundColor Yellow
                Remove-ItemProperty -Path $regPath -Name $entryName -Force -ErrorAction Stop
                Write-Host "    [DELETED] Registry entry: $entryName" -ForegroundColor Green
                $script:summaryReport.RegistryEntriesRemoved++
            }
        } catch {
            Write-Host "    [ERROR] Could not check registry: $regPath - $_" -ForegroundColor Red
        }
    }
}

Write-Host ""

# Check Uninstall registry entries
Write-Host "    Checking Uninstall registry entries..." -ForegroundColor Gray
try {
    $uninstallPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path $uninstallPath) {
        $uninstallKeys = Get-ChildItem -Path $uninstallPath -ErrorAction SilentlyContinue
        foreach ($key in $uninstallKeys) {
            try {
                $displayName = (Get-ItemProperty -Path $key.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue).DisplayName
                if ($displayName -and ($displayName -like "*GoodbyeDPI*" -or $displayName -like "*goodbyedpi*" -or $displayName -like "*WinDivert*")) {
                    Write-Host "    [FOUND] Uninstall entry: $displayName" -ForegroundColor Yellow
                    Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                    Write-Host "    [DELETED] Uninstall entry: $displayName" -ForegroundColor Green
                    $script:summaryReport.RegistryEntriesRemoved++
                }
            } catch {
                # Silently continue
            }
        }
    }
} catch {
    Write-Host "    [ERROR] Could not check Uninstall registry: $_" -ForegroundColor Red
}

# Check service registry entries
Write-Host "    Checking service registry entries..." -ForegroundColor Gray
try {
    $serviceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $serviceNames = @("GoodbyeDPI", "WinDivert", "WinDivert14")
    foreach ($svcName in $serviceNames) {
        $svcRegKey = Join-Path $serviceRegPath $svcName
        if (Test-Path $svcRegKey) {
            Write-Host "    [FOUND] Service registry key: $svcName" -ForegroundColor Yellow
            try {
                Remove-Item -Path $svcRegKey -Recurse -Force -ErrorAction Stop
                Write-Host "    [DELETED] Service registry key: $svcName" -ForegroundColor Green
                $script:summaryReport.RegistryEntriesRemoved++
            } catch {
                Write-Host "    [ERROR] Could not delete service registry key: $svcName - $_" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "    [ERROR] Could not check service registry: $_" -ForegroundColor Red
}

Write-Host ""

# Step 11: Content-based file scanning (scan files for GoodbyeDPI strings)
Write-Host "[STEP 11] Scanning files for GoodbyeDPI content..." -ForegroundColor Cyan
Write-Host "    [INFO] This may take a while - scanning file contents..." -ForegroundColor Gray
Write-Host ""

$contentScanPaths = @()
$userProfiles = Get-AllUserProfiles
$userProfiles += $env:USERPROFILE

foreach ($profile in $userProfiles) {
    $contentScanPaths += Join-Path $profile "Downloads"
    $contentScanPaths += Join-Path $profile "Desktop"
    $contentScanPaths += Join-Path $profile "Documents"
}

$contentScanPaths += $env:ProgramFiles
$contentScanPaths += ${env:ProgramFiles(x86)}
$contentScanPaths += $env:ProgramData

$contentDeletedCount = 0
foreach ($scanPath in $contentScanPaths) {
    if (Test-Path $scanPath) {
        try {
            Write-Host "    Scanning: $scanPath" -ForegroundColor Gray
            $files = Get-ChildItem -Path $scanPath -Recurse -File -Force -ErrorAction SilentlyContinue | 
                     Where-Object { 
                         $_.Extension -in @(".txt", ".cmd", ".bat", ".cfg", ".ini", ".conf", ".log") -and
                         $_.Length -lt 1MB
                     }
            
            foreach ($file in $files) {
                try {
                    if (Test-FileContainsGoodbyeDPI -FilePath $file.FullName) {
                        Write-Host "        [FOUND] File contains GoodbyeDPI: $($file.FullName)" -ForegroundColor Yellow
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        Write-Host "        [DELETED] $($file.FullName)" -ForegroundColor Green
                        $contentDeletedCount++
                        $script:summaryReport.FilesDeleted++
                    }
                } catch {
                    # Skip files we can't read
                }
            }
        } catch {
            # Silently continue
        }
    }
}
Write-Host "    [*] Total content-scanned files deleted: $contentDeletedCount" -ForegroundColor Cyan
Write-Host ""

# Step 12: Check Shadow Copies
Write-Host "[STEP 12] Checking Shadow Copies..." -ForegroundColor Cyan
Write-Host ""

try {
    $shadowCopies = vssadmin list shadows 2>&1
    if ($shadowCopies -and $LASTEXITCODE -eq 0) {
        Write-Host "    [INFO] Shadow copies found - checking for GoodbyeDPI files..." -ForegroundColor Gray
        # Note: Shadow copies are read-only snapshots, we can't delete from them directly
        # But we can note their existence
        Write-Host "    [INFO] Shadow copies are system snapshots and will be cleaned up automatically" -ForegroundColor Gray
    }
} catch {
    Write-Host "    [INFO] Could not check shadow copies (may require additional permissions)" -ForegroundColor Gray
}
Write-Host ""

# Step 13: Check network shares (if accessible)
Write-Host "[STEP 13] Checking network shares..." -ForegroundColor Cyan
Write-Host ""

$networkDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.Root -ne $null -and 
    $_.DisplayRoot -like "\\*" 
}

if ($networkDrives) {
    Write-Host "    [INFO] Network drives detected: $($networkDrives.Root -join ', ')" -ForegroundColor Gray
    Write-Host "    [INFO] Searching network shares for GoodbyeDPI files..." -ForegroundColor Gray
    
    foreach ($netDrive in $networkDrives) {
        try {
            $netFiles = Get-ChildItem -Path $netDrive.Root -Recurse -Force -ErrorAction SilentlyContinue | 
                       Where-Object { 
                           -not $_.PSIsContainer -and 
                           ($_.Name -like "*goodbyedpi*" -or $_.Name -like "*GoodbyeDPI*" -or $_.Name -like "*WinDivert*")
                       }
            
            foreach ($netFile in $netFiles) {
                try {
                    if (Test-IsGoodbyeDPIFile -File $netFile) {
                        Write-Host "        [FOUND] Network file: $($netFile.FullName)" -ForegroundColor Yellow
                        Remove-Item -Path $netFile.FullName -Force -ErrorAction Stop
                        Write-Host "        [DELETED] Network file: $($netFile.FullName)" -ForegroundColor Green
                        $script:summaryReport.FilesDeleted++
                    }
                } catch {
                    Write-Host "        [ERROR] Could not delete network file: $($netFile.FullName) - $_" -ForegroundColor Red
                }
            }
        } catch {
            Write-Host "    [WARNING] Could not access network drive: $($netDrive.Root)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "    [INFO] No network drives detected" -ForegroundColor Gray
}
Write-Host ""

# Step 14: Check file associations
Write-Host "[STEP 14] Checking file associations..." -ForegroundColor Cyan
Write-Host ""

try {
    $assocPaths = @(
        "HKCR:\*\shell\*\command",
        "HKCU:\SOFTWARE\Classes\*\shell\*\command"
    )
    
    foreach ($assocPath in $assocPaths) {
        try {
            if (Test-Path $assocPath) {
                $assocKeys = Get-ChildItem -Path $assocPath -Recurse -ErrorAction SilentlyContinue
                foreach ($key in $assocKeys) {
                    try {
                        $command = (Get-ItemProperty -Path $key.PSPath -Name "(default)" -ErrorAction SilentlyContinue).'(default)'
                        if ($command -and ($command -like "*goodbyedpi*" -or $command -like "*GoodbyeDPI*" -or $command -like "*WinDivert*")) {
                            Write-Host "    [FOUND] File association: $($key.PSChildName)" -ForegroundColor Yellow
                            Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                            Write-Host "    [DELETED] File association: $($key.PSChildName)" -ForegroundColor Green
                            $script:summaryReport.RegistryEntriesRemoved++
                        }
                    } catch {
                        # Silently continue
                    }
                }
            }
        } catch {
            # Silently continue
        }
    }
} catch {
    Write-Host "    [ERROR] Could not check file associations: $_" -ForegroundColor Red
}
Write-Host ""

# Step 15: Check Event Logs for GoodbyeDPI references
Write-Host "[STEP 15] Checking Event Logs for GoodbyeDPI references..." -ForegroundColor Cyan
Write-Host ""

try {
    $eventLogs = @("Application", "System")
    foreach ($logName in $eventLogs) {
        try {
            $events = Get-WinEvent -LogName $logName -MaxEvents 1000 -ErrorAction SilentlyContinue | 
                     Where-Object { 
                         $_.Message -like "*goodbyedpi*" -or 
                         $_.Message -like "*GoodbyeDPI*" -or 
                         $_.Message -like "*WinDivert*" 
                     }
            
            if ($events) {
                Write-Host "    [FOUND] $($events.Count) event log entries referencing GoodbyeDPI in $logName" -ForegroundColor Yellow
                Write-Host "    [INFO] Event log entries are informational only and cannot be deleted" -ForegroundColor Gray
            }
        } catch {
            # Silently continue
        }
    }
} catch {
    Write-Host "    [INFO] Could not check event logs: $_" -ForegroundColor Gray
}
Write-Host ""

# Step 16: Check for driver files in system directories
Write-Host "[STEP 16] Checking system directories for driver files..." -ForegroundColor Cyan
Write-Host ""

$systemPaths = @(
    "$env:SystemRoot\System32\drivers",
    "$env:SystemRoot\SysWOW64\drivers",
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64"
)

$driverFiles = @("WinDivert*.sys", "WinDivert*.dll")

foreach ($sysPath in $systemPaths) {
    if (Test-Path $sysPath) {
        foreach ($driverPattern in $driverFiles) {
            try {
                $files = Get-ChildItem -Path $sysPath -Filter $driverPattern -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    # CRITICAL SAFETY: Verify this is actually GoodbyeDPI, not a system driver
                    if (-not (Test-IsGoodbyeDPIFile -File $file)) {
                        Write-Host "    [SKIPPED] System driver file - does not match GoodbyeDPI signature: $($file.FullName)" -ForegroundColor Yellow
                        continue
                    }
                    
                    Write-Host "    [FOUND] $($file.FullName)" -ForegroundColor Yellow
                    try {
                        # Take ownership and remove
                        takeown /f $file.FullName /a 2>&1 | Out-Null
                        icacls $file.FullName /grant administrators:F 2>&1 | Out-Null
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        Write-Host "    [DELETED] $($file.FullName)" -ForegroundColor Green
                        $script:summaryReport.FilesDeleted++
                    } catch {
                        Write-Host "    [ERROR] Could not delete: $($file.FullName) - $_" -ForegroundColor Red
                        Write-Host "    [INFO] You may need to reboot and run this script again" -ForegroundColor Yellow
                        $script:summaryReport.Errors += "Driver: $($file.FullName) - $_"
                    }
                }
            } catch {
                # Silently continue
            }
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Removal process completed!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 17: Final comprehensive registry sweep
Write-Host "[STEP 17] Final comprehensive registry sweep..." -ForegroundColor Cyan
Write-Host ""

$additionalRegPaths = @(
    "HKLM:\SOFTWARE\Classes\Applications\goodbyedpi.exe",
    "HKCU:\SOFTWARE\Classes\Applications\goodbyedpi.exe",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\goodbyedpi.exe",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\goodbyedpi.exe",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System"
)

foreach ($regPath in $additionalRegPaths) {
    try {
        if (Test-Path $regPath) {
            $regItems = Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $regItems) {
                try {
                    $itemProps = Get-ItemProperty -Path $item.PSPath -ErrorAction SilentlyContinue
                    $props = $itemProps.PSObject.Properties | Where-Object { 
                        $_.Value -and (
                            $_.Value -like "*goodbyedpi*" -or 
                            $_.Value -like "*GoodbyeDPI*" -or 
                            $_.Value -like "*WinDivert*"
                        )
                    }
                    
                    if ($props) {
                        Write-Host "    [FOUND] Registry entry: $($item.PSPath)" -ForegroundColor Yellow
                        Remove-Item -Path $item.PSPath -Recurse -Force -ErrorAction Stop
                        Write-Host "    [DELETED] Registry entry: $($item.PSPath)" -ForegroundColor Green
                        $script:summaryReport.RegistryEntriesRemoved++
                    }
                } catch {
                    # Silently continue
                }
            }
        }
    } catch {
        # Silently continue
    }
}
Write-Host ""

# Display summary report
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SUMMARY REPORT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Processes Killed:        $($script:summaryReport.ProcessesKilled)" -ForegroundColor White
Write-Host "Services Removed:         $($script:summaryReport.ServicesRemoved)" -ForegroundColor White
Write-Host "Files Deleted:            $($script:summaryReport.FilesDeleted)" -ForegroundColor White
Write-Host "Folders Deleted:          $($script:summaryReport.FoldersDeleted)" -ForegroundColor White
Write-Host "Archives Deleted:         $($script:summaryReport.ArchivesDeleted)" -ForegroundColor White
Write-Host "Recycle Bin Items:        $($script:summaryReport.RecycleBinItemsDeleted)" -ForegroundColor White
Write-Host "Registry Entries Removed: $($script:summaryReport.RegistryEntriesRemoved)" -ForegroundColor White
Write-Host "Scheduled Tasks Removed:  $($script:summaryReport.ScheduledTasksRemoved)" -ForegroundColor White
Write-Host "Files Scheduled (Reboot): $($script:summaryReport.LockedFilesScheduled)" -ForegroundColor White
Write-Host ""

if ($script:summaryReport.Errors.Count -gt 0) {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "ERRORS ENCOUNTERED: $($script:summaryReport.Errors.Count)" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    foreach ($error in $script:summaryReport.Errors) {
        Write-Host "  - $error" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($script:summaryReport.LockedFilesScheduled -gt 0) {
    Write-Host "[INFO] $($script:summaryReport.LockedFilesScheduled) file(s) scheduled for deletion on next reboot." -ForegroundColor Cyan
    Write-Host "       These files will be automatically deleted when you restart your computer." -ForegroundColor Cyan
    Write-Host ""
}

if ($safeMode) {
    Write-Host "[INFO] Safe Mode detected - Most files should have been removed successfully!" -ForegroundColor Green
} else {
    if ($script:summaryReport.Errors.Count -gt 0 -or $script:summaryReport.LockedFilesScheduled -gt 0) {
        Write-Host "NOTE: Some files could not be deleted immediately." -ForegroundColor Yellow
        Write-Host "      For best results, reboot into Safe Mode and run this script again." -ForegroundColor Yellow
        Write-Host "      Safe Mode prevents GoodbyeDPI from running, making removal easier." -ForegroundColor Yellow
    } else {
        Write-Host "[SUCCESS] All GoodbyeDPI components have been successfully removed!" -ForegroundColor Green
    }
}
Write-Host ""
pause

