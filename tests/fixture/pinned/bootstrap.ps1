# bootstrap.ps1 - the Windows check line's one script (P+ I03, I09a1, section 16): it fetches, hashes and verifies, then runs
# carrier-check. ASCII only: the zh-TW text is printed by the Python stage. The check installs nothing, needs no admin and
# writes only under one new temp folder, which it deletes. The line carries -Serial and -MinSerial, and one optional mode
# switch (-Install -Update -Uninstall -Status; -GwSerial for install and update only, H1). $Grammar is line.GRAMMAR, and
# line.parse_args its oracle. Status and uninstall are answered from this file and the
# installed state alone; install and update elevate (H4: a loader that fetches this file into a protected stage and runs it
# with -Elevated), the elevated copy runs the chain again and then H3 (invite, gateway.json, bundle, closure, stage.py);
# uninstall elevates the same way but runs the installed copy of this file (I12: Invoke-Removal, or Invoke-FixedRemoval when the
# install is not as journaled); with no usable copy (AF36: missing, or not the journal's sha256) the loader's exit 6 runs the loader once more
# with $RemoveLoader: the line's own file, fetched and hash-checked, runs Invoke-FixedRemoval alone. The pure rules are fleet/install/boot/winspec.py.
#   1 refuse early: args, language mode, PowerShell, not Windows, 32-bit, curl.exe, execution policy, ssh-keygen without -Y
#   2 refuse an unbaked key, then a past baked expiry     3 fetch install.json and its .sig, verify with the baked owner key
#   4 fetch and hash kit.json, the five kit files and python.org's embeddable ZIP     5 run carrier-check
#   6 print the code, copy it, delete the temp folder
# Printed in this order: `bootstrap sha256 <hex>` and `key SHA256:<fingerprint>` straight after the args and machine checks
# (before any network), `serial N valid_until T` straight after the signature verifies. A refusal is always the last two
# lines, `REFUSED <code>` and its sentence; the exit status is 1. Expiry (valid_until and the baked Expires) refuses when
# now >= it, manifest.py's `valid_until <= now`.
# Trust: only the baked OwnerKey and the OS ssh-keygen; every hash comes from the signed install.json and the kit.json it
# names. If Defender, EDR, Edge or policy blocks the pasted line, do the same by hand with the kit folder's VERIFY.txt.
# A refusal prints one line, REFUSED <code>, and its sentence from the $Words table below (that table is the code list).
# The signed bootstrap sha256 is over the file exactly as downloaded (LF, no CR, no BOM); a CRLF checkout is refused boot-hash.
# The two baked values below are filled in by the owner's release step (one assignment line each); unbaked, the script
# refuses key before it touches the network.
# There is no param() block: PowerShell would bind -Ser or -Min by abbreviation and turn 007 into 7, so $args is parsed by
# hand below (each name once, case-sensitive, any order, no other token).
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$OwnerKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE+5MqONUoRXkjct3UeFr+xffINGAYa4ZytdHK//67CE'
$Expires = '2026-12-24T00:00:00Z'
$Release = 'https://github.com/mirrorstack-ai/fleet-disk/releases/download'
$PythonUrl = 'https://www.python.org/ftp/python/{0}/python-{0}-embed-amd64.zip'
$Namespace = 'mirrorstack-fleet-install'
$SshKeygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
$CmdExe = 'C:\Windows\System32\cmd.exe'
$CurlExe = 'C:\Windows\System32\curl.exe'
$KitFiles = @('VERIFY.txt', 'carrier-check.py', 'carrier-check.sh', 'check.ps1', 'verify-archive.py')
$InstallDir = 'C:\ProgramData\MirrorStack Fleet'  # H11: the carrier's data folder (install.FLEET_DIR): boot\bootstrap.ps1, the uninstall.json journal
$ProgramDir = 'C:\Program Files\MirrorStack Fleet'  # install.PROGRAM: the carrier's files (WIN_FILES), bin\fleet-carrier.py
$PythonExe = 'C:\Program Files\Python314\python.exe'  # X29's CPython, the installed removal's interpreter
$SchtasksExe = 'C:\Windows\System32\schtasks.exe'
$IcaclsExe = 'C:\Windows\System32\icacls.exe'
$LinksDir = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\MirrorStack Fleet'  # the sensor's shortcuts (all users)
$StageRoot = 'C:\Program Files\MirrorStack Fleet Stage'  # H4 step 4: the protected parent of every stage folder
$PowerShellExe = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$StageSddl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'  # the stage, its parent and priv\: protected, SYSTEM and Administrators, no Users ACE
$ResultSddl = 'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'  # `result` alone: the same plus Users read
$PinNamespace = 'mirrorstack-fleet-pin'  # gateway.json and deploy-pin.json are signed in this namespace
$BundleMax = 268435456  # H3: bundle.tar is at most 256 MiB (bundle.MAX_TAR; the producers refuse a bigger one, manifest.MAX_BUNDLE is wider)
$StageStale = 86400  # H4 step 8, AF30: seconds before an earlier run's stage folder may be removed (a live stage is far younger)
# H4 step 2: the elevated loader, one statement per line (joined with ;), no double quote, no brace but the six values:
# {0} serial {1} min-serial {2} gw-serial (numbers), {3} the stage's GUID (32 hex), {4} this file's sha256 (64 hex), {5} Install or Update.
# A parent that already exists is not re-read here (a stated residual: only an administrator can have made it, under Program Files);
# the elevated copy refuses `temp` on any parent or stage whose ACL is not exactly $StageSddl, before it fetches anything.
# AF30: both children start from one ProcessStartInfo with UseShellExecute=$false, so they share the loader's console (no second
# window); the guards are `$z=` assignments so no True line prints; after the copy exits the loader waits 10 s (the parent has read
# `result` by then) and removes its stage, the empty parent stays.
$Loader = (@'
$ErrorActionPreference='Stop'
$env:PSModulePath=$PSHOME+'\Modules'
[Net.ServicePointManager]::SecurityProtocol='Tls12'
$StageRoot=[Environment]::GetFolderPath('ProgramFiles')
$z=($StageRoot -ceq 'C:\Program Files') -or [Environment]::Exit(2)
$StageRoot+='\MirrorStack Fleet Stage'
$Stage=$StageRoot+'\{3}'
$z=(-not [IO.Directory]::Exists($Stage)) -or [Environment]::Exit(2)
$a=[Security.AccessControl.DirectorySecurity]::new()
$a.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
[void][IO.Directory]::CreateDirectory($StageRoot,$a)
[void][IO.Directory]::CreateDirectory($Stage,$a)
$f=$Stage+'\bootstrap.ps1'
$d=[char]34
$i=[Diagnostics.ProcessStartInfo]::new('C:\Windows\System32\curl.exe','-fsSL --max-redirs 3 --proto =https --proto-redir =https --tlsv1.2 --max-time 120 --max-filesize 262144 -o '+$d+$f+$d+' https://github.com/mirrorstack-ai/fleet-disk/releases/download/install-{0}/bootstrap.ps1')
$i.UseShellExecute=$false
$k=[Diagnostics.Process]::Start($i)
$k.WaitForExit()
$h=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($f))).Replace('-','').ToLower()
$z=($h -ceq '{4}') -or [Environment]::Exit(3)
$i.FileName=$PSHOME+'\powershell.exe'
$i.Arguments='-NoProfile -ExecutionPolicy Bypass -File '+$d+$f+$d+' -{5} -Serial {0} -MinSerial {1} -GwSerial {2} -Elevated'
$r=[Diagnostics.Process]::Start($i)
$r.WaitForExit()
Start-Sleep -Seconds 10
Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
[Environment]::Exit($r.ExitCode)
'@).Replace("`n", ';')
# AF36: the uninstall loader for a PC with no usable removal copy ($UninstallLoader's exit 6): $Loader's fetch of install-{0}/bootstrap.ps1
# into a new protected stage, its hash against this file's sha256, then that copy with -Uninstall -Elevated (no -GwSerial: Get-Args refuses it
# for uninstall). It never reads the data folder; the copy runs Invoke-FixedRemoval alone. Placeholders: {0} serial, {1} min-serial,
# {2} the stage's GUID, also handed over in MIRRORSTACK_STAGE, {3} this file's sha256. Exit 2 the stage is not new, 3 the hash is not {3}.
$RemoveLoader = (@'
$ErrorActionPreference='Stop'
$env:PSModulePath=$PSHOME+'\Modules'
[Net.ServicePointManager]::SecurityProtocol='Tls12'
$StageRoot=[Environment]::GetFolderPath('ProgramFiles')
$z=($StageRoot -ceq 'C:\Program Files') -or [Environment]::Exit(2)
$StageRoot+='\MirrorStack Fleet Stage'
$Stage=$StageRoot+'\{2}'
$z=(-not [IO.Directory]::Exists($Stage)) -or [Environment]::Exit(2)
$a=[Security.AccessControl.DirectorySecurity]::new()
$a.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
[void][IO.Directory]::CreateDirectory($StageRoot,$a)
[void][IO.Directory]::CreateDirectory($Stage,$a)
$f=$Stage+'\bootstrap.ps1'
$d=[char]34
$i=[Diagnostics.ProcessStartInfo]::new('C:\Windows\System32\curl.exe','-fsSL --max-redirs 3 --proto =https --proto-redir =https --tlsv1.2 --max-time 120 --max-filesize 262144 -o '+$d+$f+$d+' https://github.com/mirrorstack-ai/fleet-disk/releases/download/install-{0}/bootstrap.ps1')
$i.UseShellExecute=$false
$k=[Diagnostics.Process]::Start($i)
$k.WaitForExit()
$h=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($f))).Replace('-','').ToLower()
$z=($h -ceq '{3}') -or [Environment]::Exit(3)
$env:MIRRORSTACK_STAGE='{2}'
$i.FileName=$PSHOME+'\powershell.exe'
$i.Arguments='-NoProfile -ExecutionPolicy Bypass -File '+$d+$f+$d+' -Uninstall -Serial {0} -MinSerial {1} -Elevated'
$r=[Diagnostics.Process]::Start($i)
$r.WaitForExit()
Start-Sleep -Seconds 10
Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
[Environment]::Exit($r.ExitCode)
'@).Replace("`n", ';')
# H4 steps 2 and 6 for uninstall: the same protected stage, then the installed copy. The copy checks its own sha256 against the journal
# once it runs elevated: the unelevated parent reads nothing from the data folder.
# Placeholders: {0} serial, {1} min-serial, {2} the stage's GUID, also handed over in MIRRORSTACK_STAGE.
# AF05: before the stage is made the loader (never the file it starts) asks who owns the data folder. No uninstall.json is exit 5
# (nothing installed). A folder that is not a plain directory, or whose owner and DACL are not SYSTEM or Administrators with protected,
# allow-only ACEs for SY BA OW CO, is exit 4 (folder-owner). Only the folder is checked: boot\ and the journal inherit its protected DACL.
# AF36: then, still before any stage, the copy must be there and the journal must name its sha256 (Get-FileHash, Select-String -ea 0: an unreadable
# or unparseable journal names nothing; both paths are constants without a wildcard); else exit 6, the only code that makes the parent run $RemoveLoader. Exit 4 and 5 come first and never fall back.
# After the copy exits the loader waits 10 s (the parent has read `result` by then) and removes the stage and its parent when empty.
$UninstallLoader = (@'
$ErrorActionPreference='Stop'
$env:PSModulePath=$PSHOME+'\Modules'
$e=[Environment]
$p='C:/ProgramData/MirrorStack Fleet'
$z=[IO.File]::Exists($p+'/uninstall.json') -or $e::Exit(5)
$z=([int][IO.File]::GetAttributes($p) -band 1040) -eq 16 -or $e::Exit(4)
$s=[IO.Directory]::GetAccessControl($p).GetSecurityDescriptorSddlForm('Owner,Access')
$z=$s -cmatch '^O:(BA|SY)D:P(AI)?(\(A;[^;()]*;[^;()]*;;;(SY|BA|OW|CO)\))+\z' -or $e::Exit(4)
$b=$p+'/boot/bootstrap.ps1'
$z=([IO.File]::Exists($b) -and (Select-String -Path ($p+'/uninstall.json') -Pattern ('bootstrap_sha256\W+'+(Get-FileHash $b).Hash+'\W') -Quiet -ea 0)) -or $e::Exit(6)
$StageRoot=$e::GetFolderPath('ProgramFiles')
$z=$StageRoot -ceq 'C:\Program Files' -or $e::Exit(2)
$StageRoot+='\MirrorStack Fleet Stage'
$Stage=$StageRoot+'\{2}'
$z=(-not [IO.Directory]::Exists($Stage)) -or $e::Exit(2)
$a=[Security.AccessControl.DirectorySecurity]::new()
$a.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
[void][IO.Directory]::CreateDirectory($StageRoot,$a)
[void][IO.Directory]::CreateDirectory($Stage,$a)
$env:MIRRORSTACK_STAGE='{2}'
$d=[char]34
$i=[Diagnostics.ProcessStartInfo]::new($PSHOME+'\powershell.exe','-NoProfile -ExecutionPolicy Bypass -File '+$d+$b+$d+' -Uninstall -Serial {0} -MinSerial {1} -Elevated')
$i.UseShellExecute=$false
$r=[Diagnostics.Process]::Start($i)
$r.WaitForExit()
Start-Sleep -Seconds 10
Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
$z=@(Get-ChildItem -LiteralPath $StageRoot -Force).Count -eq 0 -and (Remove-Item -LiteralPath $StageRoot -Force -ErrorAction SilentlyContinue)
$e::Exit($r.ExitCode)
'@).Replace("`n", ';')
$StatusFile = 'C:\ProgramData\MirrorStack Fleet\public\status.json'  # H11: the carrier's public status, display only
$MinKitSerial = 5  # the first kit with verify-archive --closure and its hardened _safe (H2): install and update refuse an older one
$StatusShape = '^\{("[a-z_]{1,32}":("[^"\\]{0,200}"|-?[0-9]{1,12}|true|false|null)(,"[a-z_]{1,32}":("[^"\\]{0,200}"|-?[0-9]{1,12}|true|false|null))*)?\}\z'  # H2: the flat JSON status.json may be, as bootstrap.sh STATUS_JSON
$Grammar = @{  # H1: mode = the numbers its line carries; the same table as line.GRAMMAR, a test holds both
    'check'     = @('-Serial', '-MinSerial')
    'install'   = @('-Serial', '-MinSerial', '-GwSerial')
    'update'    = @('-Serial', '-MinSerial', '-GwSerial')
    'uninstall' = @('-Serial', '-MinSerial')
    'status'    = @('-Serial', '-MinSerial')
}
$Rules = @{  # H8: what each mode does with the notices a verified release can carry; the same table as bootstrap.sh RULES, a test holds both
    'check'     = @('clock', 'successor')
    'install'   = @('clock', 'rotated')
    'update'    = @('clock', 'rotated')
    'uninstall' = @()
    'status'    = @('successor')
}
$ClockSlack = 86400  # seconds this PC's clock may run behind the server's Date before `clock`
$CodePattern = '(?m)^Code +((?:[0-9A-Z]{5} ){7}[0-9A-Z]{5})'
$Work = $null
$Stage = $null  # the elevated copy's stage folder (H4)
$Elevated = $false
$Done = @('', '')  # the two closing lines Stop-Done printed
$Words = @{
    'args'          = 'The line must carry -Serial and -MinSerial. Paste the whole line again.'
    'language-mode' = 'PowerShell is in a restricted language mode on this PC, so this check cannot run. Tell the owner.'
    'ps-version'    = 'This needs Windows PowerShell 5.1 or newer. Update Windows or ask the owner.'
    'os'            = 'This line is for Windows. On Ubuntu or macOS use the shell line.'
    'arch'          = 'Open the 64-bit PowerShell and paste the line again. If this PC is not 64-bit Windows, ask the owner.'
    'policy'        = 'This is a managed PC: a group policy sets its PowerShell execution policy. Nothing was changed. Tell the owner.'
    'tools'         = 'curl.exe was not found on this PC. Update Windows or ask the owner.'
    'ssh-keygen'    = 'Windows OpenSSH 8.0 or newer (signature checks) was not found. Update Windows or ask the owner.'
    'temp'          = 'Your temp folder path has a character this check refuses. Ask the owner.'
    'key'           = 'This script has no owner key baked in. Do not use it; ask the owner for a new line.'
    'expired'       = 'This line has expired. Ask the owner for a new one.'
    'fetch'         = 'A download failed or was not https. Check the network and try again.'
    'size'          = 'A download was empty or larger than allowed. Nothing was run. Tell the owner.'
    'sig'           = 'The signature did not verify. Nothing was run. Tell the owner.'
    'form'          = 'The signed release file is not in the expected form. Nothing was run. Tell the owner.'
    'kind'          = 'The signed release file is not an install file. Nothing was run. Tell the owner.'
    'serial'        = 'The release number in the file is not the one in your line. Nothing was run. Tell the owner.'
    'rollback'      = 'The release is older than the number in your line. Nothing was run. Tell the owner.'
    'boot-hash'     = 'This script is not the one the owner signed. Nothing was run. Tell the owner.'
    'kit-hash'      = 'kit.json does not match the signed release. Nothing was run. Tell the owner.'
    'file-hash'     = 'A kit file does not match kit.json. Nothing was run. Tell the owner.'
    'zip-hash'      = 'The Python ZIP does not match kit.json. Nothing was run. Tell the owner.'
    'check-failed'  = 'The check did not finish or printed no code. Tell the owner.'
    'unexpected'    = 'Something unexpected stopped the check. Nothing was installed. Tell the owner.'
    # amendment H5: the words the install, update and rotation slices raise
    'elevate'          = 'Windows did not give this window administrator rights. Run the line again and accept the prompt, or ask the owner.'
    'invite'           = 'The invite code is not in the right form. Check it and run the line again, or ask the owner.'
    'invite-refused'   = 'The invite code was not accepted. Ask the owner for a new one.'
    'rate-limited'     = 'Too many tries came from this network, or the server is busy. Wait an hour, then try again.'
    'gateway-not-live' = 'The owner has not switched the fleet on yet. Nothing was changed. Tell the owner.'
    'gateway-pin'      = 'The fleet address file is not the one the owner signed. Nothing was changed. Tell the owner.'
    'bundle-hash'      = 'The download is not the file the owner signed. Nothing was changed. Tell the owner.'
    'closure'          = 'The downloaded files do not match their signed list. Nothing was changed. Tell the owner.'
    'pin-mismatch'     = 'The release and its pin do not agree. Nothing was changed. Tell the owner.'
    'carrier-lock'     = 'The fleet lock does not match the release. Nothing was changed. Tell the owner.'
    'kit-old'          = 'This release is too old to install; ask the owner for a new line.'
    'installed'        = 'This computer is already installed. Use the update line, or ask the owner.'
    'not-installed'    = 'Nothing is installed on this computer. Use the install line, or ask the owner.'
    'clock'            = 'Your clock is wrong. Fix the time and run the line again. Nothing was run.'
    'rotated'          = 'The owner has replaced this line. Ask for the new one.'
    'install-failed'   = 'The install or removal did not finish. Run the uninstall line, then the install line. If the uninstall line says this too, tell the owner.'
    # amendment H11 (I12): the update and uninstall words
    'config-schema'    = 'config.json is not in the form this release reads. Nothing was changed. Use the uninstall line, then the install line.'
    'learned-schema'   = 'learned.json is not in the form this release reads. Nothing was changed. Use the uninstall line, then the install line.'
    'tampered'         = 'The installed files are not the ones the install made. Nothing was changed. Use the uninstall line, then the install line.'
    # INT1 (G-I11-3): the words stage.py, run.py, pyinstall.py, install.py, update.py and spike.py write
    'consent'           = 'The sheet was not accepted. Nothing was changed. Run the line again to read it, or ask the owner.'
    'consent-managed'   = 'A managed computer cannot join. Nothing was changed. Tell the owner.'
    'consent-declined'  = 'Every administrator must agree. Nothing was changed. Tell the owner.'
    'consent-not-owner' = 'Only the owner of this computer may install it. Nothing was changed. Tell the owner.'
    'owner-pin'         = 'The owner''s key file cannot be read. Nothing was changed. Tell the owner.'
    'gateway-json'      = 'The fleet address file is not the owner''s. Nothing was changed. Tell the owner.'
    'store-gb'          = 'The store disk is too small. Nothing was changed. Tell the owner.'
    'free-space'        = 'There is not enough free disk space. Nothing was changed. Tell the owner.'
    'ram'               = 'This computer needs 16 GB of memory or more. Nothing was changed. Tell the owner.'
    'bios'              = 'Turn on virtualization in the BIOS first. Nothing was changed. Tell the owner.'
    'firewall'          = 'Windows Firewall must be on and not replaced. Nothing was changed. Tell the owner.'
    'hypervisor-off'    = 'This computer''s hypervisor is off. Nothing was changed, and nothing turns it on. Tell the owner.'
    # the next three: the steps print only in the elevated (administrator) window, so this console points there (run.SAY says 'above' in that window)
    'hyperv-feature'    = 'Turn the Hyper-V feature on with the command in the administrator window, restart, and run the line again.'
    'game-conflict'     = 'A game conflicts with this install. Follow the steps in the administrator window.'
    'security-changed'  = 'The security state moved. Follow the steps in the administrator window.'
    'python'            = 'The Python 3.14 this install needs is not there. Nothing was changed. Tell the owner.'
    'python-lock'       = 'The Python pin in this release is not whole. Nothing was changed. Tell the owner.'
    'python-download'   = 'The Python installer could not be downloaded. Check the network and run the line again.'
    'python-hash'       = 'The Python installer is not the file the owner signed. Nothing was changed. Tell the owner.'
    'python-install'    = 'The Python installer did not finish, and what it left was removed. Tell the owner.'
    'python-old'        = 'The Python on this computer is older than this release needs. Nothing was changed. Tell the owner.'
    'not-admin'         = 'This step needs an administrator. Nothing was changed. Run the line again and accept the prompt.'
    'folder'            = 'The install was not run from its own folder. Nothing was changed. Tell the owner.'
    'folder-owner'      = 'The install folder is not for administrators only. Nothing was changed. Tell the owner.'
    'head'              = 'The release number given to the install is not valid. Nothing was changed. Tell the owner.'
    'unpinned'          = 'This release has no pinned disk image yet. Nothing was changed. Tell the owner.'
    'unverified'        = 'The install files are not the verified release. Nothing was changed. Tell the owner.'
    'usage'             = 'The install was given the wrong arguments. Nothing was changed. Tell the owner.'
    'arm64'             = 'This computer cannot join. Nothing was changed. Tell the owner.'
    'not-x64'           = 'This computer cannot join. Nothing was changed. Tell the owner.'
    's-mode'            = 'This computer cannot join. Nothing was changed. Tell the owner.'
    'managed'           = 'This computer cannot join. Nothing was changed. Tell the owner.'
    'managed-policy'    = 'This computer cannot join. Nothing was changed. Tell the owner.'
    'home'              = 'This computer cannot join. Nothing was changed. Tell the owner.'
    'home-win10'        = 'This computer cannot join. Nothing was changed. Tell the owner.'
    'amd-win10'         = 'This computer cannot join. Nothing was changed. Tell the owner.'
    'app-control'       = 'This computer cannot join. Nothing was changed. Tell the owner.'
}

function Stop-Refused([string]$Code) {
    # a refusal is a code alone, never the input that earned it
    throw ('REFUSED ' + $Code)
}

function Test-Machine {
    # the early refusals, cheapest first; each is a read, none changes anything
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { Stop-Refused 'language-mode' }
    $ps = $PSVersionTable.PSVersion
    if ([version]('{0}.{1}' -f $ps.Major, $ps.Minor) -lt [version]'5.1') { Stop-Refused 'ps-version' }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') { Stop-Refused 'os' }
    if (-not [Environment]::Is64BitOperatingSystem) { Stop-Refused 'arch' }
    # H1: a 32-bit PowerShell on 64-bit Windows would run the changing modes under WOW64 file redirection
    if (@('install', 'update', 'uninstall') -ccontains $Mode -and -not [Environment]::Is64BitProcess) { Stop-Refused 'arch' }
    if ($Mode -cne 'uninstall') {  # the removal needs no network
        if (-not (Test-Path -LiteralPath $CurlExe)) { Stop-Refused 'tools' }
    }
    foreach ($entry in @(Get-ExecutionPolicy -List)) {
        if ($entry.Scope -eq 'MachinePolicy' -and [string]$entry.ExecutionPolicy -ne 'Undefined') { Stop-Refused 'policy' }
    }
    # no shipped launch reaches this test (-ExecutionPolicy Bypass puts Process first; the pasted line refuses a policy scope before -File, AF18)
    if ([string](Get-ExecutionPolicy) -eq 'AllSigned') { Stop-Refused 'policy' }
    if (@('uninstall', 'status') -ccontains $Mode) { return }  # no signature is checked here (a status that cannot says `latest: unknown`)
    if (-not (Test-Path -LiteralPath $SshKeygen)) { Stop-Refused 'ssh-keygen' }
    # an OpenSSH without -Y answers "unknown option"; the 1809-era figure is unverified, so this is a probe
    $probe = Invoke-Proc $CmdExe ('/d /s /c ""{0}" -Y verify < NUL 2>&1"' -f $SshKeygen) $true 30
    if ($probe.Code -eq 127 -or $probe.Out -match '(?i)unknown option|illegal option|invalid option') { Stop-Refused 'ssh-keygen' }
}

function Invoke-Proc([string]$File, [string]$ArgLine, [bool]$Capture, [int]$Seconds) {
    # one child with a raw command line (PowerShell mangles quotes for cmd.exe); not captured, it inherits the console.
    # $Seconds -le 0 is no limit (AF30): the child is never killed, the stage.py run waits for a person
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = $ArgLine
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $Capture
    $proc = [System.Diagnostics.Process]::Start($psi)
    # read the pipe asynchronously: a blocking ReadToEnd before the wait would make the timeout inert on a hung child
    $task = $null
    if ($Capture) { $task = $proc.StandardOutput.ReadToEndAsync() }
    $limit = -1  # WaitForExit(-1) waits for ever
    if ($Seconds -gt 0) { $limit = $Seconds * 1000 }
    if (-not $proc.WaitForExit($limit)) {
        try { $proc.Kill() } catch { }
        return [pscustomobject]@{ Code = 127; Out = '' }
    }
    $out = ''
    if ($Capture -and $task.Wait(5000)) { $out = $task.Result }
    return [pscustomobject]@{ Code = $proc.ExitCode; Out = $out }
}

function Get-Url([string]$Url, [string]$To, [long]$Max, [int]$MaxTime = 120, [string]$Headers = '') {
    # https only, TLS 1.2, curl.exe only (no Invoke-WebRequest fallback: it notices an https->http hop after the body is
    # written); the file lands at $To under the temp folder and is at most $Max bytes; $Headers, when given, is where curl
    # dumps the response headers (H8's clock reads the Date there)
    if ($Url -notmatch '^https://') { Stop-Refused 'fetch' }
    $code = 1
    $dump = ''
    if ($Headers) { $dump = ' -D "' + $Headers + '"' }
    try {
        $args1 = '-fsSL --max-redirs 3 --proto "=https" --proto-redir "=https" --tlsv1.2 --connect-timeout 20 --max-time {3} --max-filesize {0} -o "{1}"{4} "{2}"'
        $code = (Invoke-Proc $CurlExe ($args1 -f $Max, $To, $Url, $MaxTime, $dump) $false ($MaxTime + 30)).Code
    } catch { }
    if ($code -eq 63) { Stop-Refused 'size' }  # curl's own over --max-filesize exit; outside the try, which would turn it into fetch
    if ($code -ne 0) { Stop-Refused 'fetch' }
    if (-not (Test-Path -LiteralPath $To)) { Stop-Refused 'fetch' }
    $size = (Get-Item -LiteralPath $To).Length
    if ($size -le 0 -or $size -gt $Max) { Stop-Refused 'size' }
}

function Get-Sha([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Get-Prop($Obj, [string]$Name) {
    # a property or $null; StrictMode would throw on a missing one
    if ($null -eq $Obj) { return $null }
    $prop = $Obj.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return , $prop.Value  # the comma: a bare return would unroll [] to $null and [5] to 5, and the caller then could not tell them from absent and 5
}

function Get-Utc($Value) {
    if ($Value -isnot [string] -or $Value -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z') { Stop-Refused 'form' }
    $style = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $when = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($Value, 'yyyy-MM-dd\THH:mm:ss\Z', [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$when)) {
        Stop-Refused 'form'
    }
    return $when
}

function Get-ServerDate([string]$Path) {
    # the Date of the last response in curl's header dump (the final block alone: a final hop without one is absent), by exactly `Wed, 07 Oct 2026 12:00:00 GMT`'s shape
    # (the weekday is not read); $null when it is absent, garbled or oversized
    $last = $null
    try { foreach ($ln in [IO.File]::ReadAllLines($Path)) { if ($ln -cmatch '^HTTP/') { $last = $null } elseif ($ln -imatch '^date:[ ]*(.*)$') { $last = $Matches[1] } } } catch { return $null }
    if ($last -isnot [string] -or $last -cnotmatch '^[A-Z][a-z]{2}, [0-3][0-9] [A-Z][a-z]{2} [0-9]{4} [0-2][0-9]:[0-5][0-9]:[0-5][0-9] GMT\z') { return $null }
    $style = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    $when = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($last.Substring(5), 'dd MMM yyyy HH:mm:ss \G\M\T', [Globalization.CultureInfo]::InvariantCulture, $style, [ref]$when)) { return $null }
    return $when
}

function Test-Clock([string]$Path) {
    # H8: this PC's clock more than $ClockSlack behind the Date of the install.json fetch is `clock`; a Date absent, ahead,
    # garbled or oversized is ignored
    if ($Rules[$Mode] -cnotcontains 'clock') { return }
    $server = Get-ServerDate $Path
    if ($null -eq $server) { return }
    if (($server - (Get-Date).ToUniversalTime()).TotalSeconds -gt $ClockSlack) { Stop-Refused 'clock' }
}

function Get-LineNumber([string]$Text) {
    # a line number is canonical decimal (no sign, no leading zeros) and at most 2^31
    if ($Text -cnotmatch '^(0|[1-9][0-9]{0,9})\z') { Stop-Refused 'args' }
    $n = [long]$Text
    if ($n -gt 2147483648) { Stop-Refused 'args' }
    return $n
}

function Get-Args([object[]]$List) {
    # H1: at most one mode switch, each number flag once, case-sensitive and whole, any order, no other token; the internal
    # -Elevated only with a mode that elevates. Returns the numbers by flag name, plus Mode and Elevated.
    $mode = 'check'
    $elevated = $false
    $seen = @{}
    $i = 0
    while ($i -lt $List.Count) {
        $name = $List[$i]
        if ($name -isnot [string]) { Stop-Refused 'args' }
        if ($name -cmatch '^-(Install|Update|Uninstall|Status)\z' -and $mode -ceq 'check') {
            $mode = $Matches[1].ToLowerInvariant()
            $i += 1
        } elseif ($name -ceq '-Elevated' -and -not $elevated) {
            $elevated = $true
            $i += 1
        } elseif ($name -cmatch '^-(Serial|MinSerial|GwSerial)\z' -and -not $seen.ContainsKey($name) -and $i + 1 -lt $List.Count -and $List[$i + 1] -is [string]) {
            $seen[$name] = Get-LineNumber $List[$i + 1]
            $i += 2
        } else { Stop-Refused 'args' }
    }
    if ($elevated -and @('install', 'update', 'uninstall') -cnotcontains $mode) { Stop-Refused 'args' }
    foreach ($flag in @('-Serial', '-MinSerial', '-GwSerial')) {
        if (($Grammar[$mode] -ccontains $flag) -ne $seen.ContainsKey($flag)) { Stop-Refused 'args' }
    }
    if ($seen['-Serial'] -lt $seen['-MinSerial']) { Stop-Refused 'args' }
    $seen['Mode'] = $mode
    $seen['Elevated'] = $elevated
    return $seen
}

function Get-Fingerprint([string]$Key) {
    # ssh-keygen's SHA256 fingerprint of a baked key line (already shape-checked): unpadded base64 of the key blob's hash
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Convert]::FromBase64String($Key.Split(' ')[1])) } finally { $sha.Dispose() }
    return 'SHA256:' + [Convert]::ToBase64String($hash).TrimEnd('=')
}

function Test-Sha($Value) {  # untyped: a [string] parameter would cast the one-element array @('a'*64) into a string and pass it
    return ($Value -is [string]) -and ($Value -cmatch '^[0-9a-f]{64}\z')
}

function Test-Int($Value) {
    return ($Value -is [int]) -or ($Value -is [long])
}

function Test-Count($Value) {
    # a whole number in manifest.py's range for a serial, 0 to 2^31
    return (Test-Int $Value) -and $Value -ge 0 -and $Value -le 2147483648
}

function Test-Signature([string]$Doc, [string]$Sig, [string]$Ns = $Namespace) {
    # ssh-keygen -Y verify through cmd /c with the baked key (its shape was checked before any network); Good must be said
    # for namespace and owner; returns the key fingerprint from that Good line
    $allowed = Join-Path $Work 'allowed_signers'
    [IO.File]::WriteAllText($allowed, ('owner namespaces="{0}" {1}' -f $Ns, $OwnerKey) + "`n", [Text.Encoding]::ASCII)
    $line = '/d /s /c ""{0}" -Y verify -f "{1}" -I owner -n {2} -s "{3}" < "{4}" 2>&1"'
    $got = Invoke-Proc $CmdExe ($line -f $SshKeygen, $allowed, $Ns, $Sig, $Doc) $true 60
    $good = 'Good "{0}" signature for owner with ' -f $Ns
    if ($got.Code -eq 127) { Stop-Refused 'ssh-keygen' }  # killed after 60 s, or cmd could not run it: same word as the .sh
    if ($got.Code -ne 0 -or -not $got.Out.StartsWith($good)) { Stop-Refused 'sig' }
    $first = ($got.Out.Trim() -split '\r?\n')[0]
    $m = [regex]::Match($first.Substring($good.Length), '^[A-Za-z0-9-]+ key (SHA256:[A-Za-z0-9+/]+)\z')
    if (-not $m.Success) { Stop-Refused 'sig' }
    return $m.Groups[1].Value
}

function Read-Json([string]$Path) {
    $doc = $null
    $opt = @{}
    # PowerShell 7 turns an ISO-8601 string into [datetime] unless told not to; Windows PowerShell 5.1 has no -DateKind and keeps the string
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $opt['DateKind'] = 'String' }
    try { $doc = [IO.File]::ReadAllText($Path) | ConvertFrom-Json @opt } catch { }
    return $doc
}

function Write-Serial($Doc) {
    # right after the signature verifies, before any check of the file; a field that is not in shape prints as ?
    $n = Get-Prop $Doc 'serial'
    $t = Get-Prop $Doc 'valid_until'
    if (-not (Test-Count $n)) { $n = '?' }
    if ($t -isnot [string] -or $t -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z') { $t = '?' }
    Write-Host ('serial {0} valid_until {1}' -f $n, $t)
}

function Read-Proof($Doc) {
    # the optional proof block (I12d, manifest.py's PROOF_KEYS): one or more distinct canary sha256s and a net_port from 1024 to
    # 65535, else `form`; the stage's --proof value (<port>:<canary>,...), or `none` when the key is absent
    if ($null -eq $Doc.PSObject.Properties['proof']) { return 'none' }
    $p = Get-Prop $Doc 'proof'
    if ($p -isnot [pscustomobject] -or (@($p.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object -CaseSensitive) -join ',') -cne 'canaries,net_port') { Stop-Refused 'form' }
    $c = Get-Prop $p 'canaries'
    $port = Get-Prop $p 'net_port'
    if ($c -isnot [array] -or $c.Count -lt 1 -or -not (Test-Int $port) -or $port -lt 1024 -or $port -gt 65535) { Stop-Refused 'form' }
    foreach ($one in $c) { if (-not (Test-Sha $one)) { Stop-Refused 'form' } }
    if (@($c | Select-Object -Unique).Count -ne $c.Count) { Stop-Refused 'form' }
    return ('{0}:{1}' -f $port, ($c -join ','))
}

function Read-Install($Doc) {
    # the verified file, read strictly: the kind first (a wrong kind is not a malformed file), then each key in its shape
    $kind = Get-Prop $Doc 'kind'
    if ($kind -isnot [string] -or $kind -cne 'install') { Stop-Refused 'kind' }  # -cne alone would turn $true into a string-equal
    $boot = Get-Prop (Get-Prop (Get-Prop $Doc 'bootstrap') 'ps1') 'sha256'
    $kit = Get-Prop $Doc 'kit'
    $out = [pscustomobject]@{
        Serial = Get-Prop $Doc 'serial'; Until = Get-Utc (Get-Prop $Doc 'valid_until'); Boot = $boot
        KitSerial = Get-Prop $kit 'serial'; KitSha = Get-Prop $kit 'kit_json_sha256'; Handoff = Get-Prop $Doc 'handoff'
        Proof = Read-Proof $Doc
    }
    if (-not (Test-Count $out.Serial) -or -not (Test-Count $out.KitSerial)) { Stop-Refused 'form' }
    if (-not (Test-Sha $boot) -or -not (Test-Sha $out.KitSha)) { Stop-Refused 'form' }
    if ($null -ne $Doc.PSObject.Properties['handoff'] -and $out.Handoff -isnot [pscustomobject]) { Stop-Refused 'form' }  # the key present as null, [] or a scalar is `form`, not an absent notice
    if ($null -ne $out.Handoff) {  # the rotation notice (H8): a fingerprint and the successor series' first serial
        if ((Get-Prop $out.Handoff 'fp') -isnot [string] -or (Get-Prop $out.Handoff 'fp') -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}\z' -or -not (Test-Count (Get-Prop $out.Handoff 'first_serial')) -or [long](Get-Prop $out.Handoff 'first_serial') -le [long]$out.Serial) {
            Stop-Refused 'form'
        }
    }
    return $out
}

function Test-Handoff($Install) {
    # H8: a verified release that hands over to a new key is refused `rotated` where $Rules says, else announced
    if ($null -eq $Install.Handoff) { return }
    if ($Rules[$Mode] -ccontains 'rotated') { Stop-Refused 'rotated' }
    if ($Rules[$Mode] -ccontains 'successor') { Write-Host ('successor {0} first-serial {1}' -f $Install.Handoff.fp, $Install.Handoff.first_serial) }
}

function Test-Serial($Install) {
    # after the expiry: older than the line's floor is a rollback; not the line's own number is a swapped or mis-tagged asset
    if ($Install.Serial -lt $MinNum) { Stop-Refused 'rollback' }
    if ($Install.Serial -ne $SerialNum) { Stop-Refused 'serial' }
}

function Read-Kit([string]$Path, $Install) {
    # kit.json after its hash matched the signed one: the five files exactly, and the Python ZIP
    $kit = Read-Json $Path
    $files = Get-Prop $kit 'files'
    if ($files -isnot [array]) { $files = @($files) }
    $zip = Get-Prop $kit 'python_zip'
    $names = @($files | ForEach-Object { Get-Prop $_ 'path' })
    $have = (@($names | Sort-Object) -join ' ')
    $want = (@($KitFiles | Sort-Object) -join ' ')
    $kitSerial = Get-Prop $kit 'serial'
    if (-not (Test-Int $kitSerial) -or $kitSerial -ne $Install.KitSerial -or $have -cne $want) { Stop-Refused 'form' }
    $version = Get-Prop $zip 'version'
    if ($version -isnot [string] -or $version -cnotmatch '^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}\z' -or -not (Test-Sha (Get-Prop $zip 'sha256'))) {
        Stop-Refused 'form'
    }
    foreach ($f in $files) { if (-not (Test-Sha (Get-Prop $f 'sha256'))) { Stop-Refused 'form' } }
    return [pscustomobject]@{ Files = $files; Version = $version; ZipSha = $zip.sha256 }
}

function Stop-Done([string]$Line, [string]$Sentence) {
    # H6: the two closing lines of a mode that finished (DONE <mode>, or STATUS <state>), then the normal end, exit 0
    Write-Host $Line
    Write-Host $Sentence
    $script:Done = @($Line, $Sentence)
    throw 'DONE'
}

function Test-Installed {
    # H11: the journal exists once an install has begun (AF27 writes it first); Test-Finished tells a finished one from a started one
    return Test-Path -LiteralPath ($InstallDir + '\uninstall.json')
}

function Test-Finished {
    # AF30: the journal's last write is `done` true (AF27); a journal without it is an install that started and did not finish
    $journal = Read-Json ([IO.Path]::Combine($InstallDir, 'uninstall.json'))
    $done = $null
    if ($null -ne $journal -and $null -ne $journal.PSObject.Properties['done']) { $done = $journal.PSObject.Properties['done'].Value }
    return ($done -is [bool] -and $done)
}

function Get-Outcome([string]$Text) {
    # H4 step 8, H6: two lines, `DONE <this mode>` or `REFUSED <word of $Words>`, then a printable sentence of at most 200; else $null
    $m = [regex]::Match($Text, '^(?:DONE ([a-z]{1,9})|REFUSED ([a-z0-9-]{1,24}))\r?\n([ -~]{1,200})\r?\n?\z')
    if (-not $m.Success) { return $null }
    if ($m.Groups[1].Success) {
        if ($m.Groups[1].Value -cne $Mode) { return $null }
        return [pscustomobject]@{ Word = $null; Sentence = $m.Groups[3].Value }
    }
    if (-not $Words.ContainsKey($m.Groups[2].Value)) { return $null }
    return [pscustomobject]@{ Word = $m.Groups[2].Value; Sentence = $null }
}

function Wait-Result([string]$Path, $Proc) {
    # H4 step 8: the text of `result` (at most 1 KiB), or $null when the loader exits without one; no clock (AF30): the loader
    # waits for a person, so the parent waits for the loader
    while ($true) {
        $exited = $Proc.HasExited  # read first: a result written before the exit is then there to be found
        if (Test-Path -LiteralPath $Path) {
            if ((Get-Item -LiteralPath $Path).Length -gt 1024) { return $null }
            $raw = [IO.File]::ReadAllBytes($Path)  # the decoder turns a high byte into `?`, so a byte outside LF, CR and 0x20-0x7E is refused first
            foreach ($b in $raw) { if ($b -ne 10 -and $b -ne 13 -and ($b -lt 32 -or $b -gt 126)) { return $null } }
            return [Text.Encoding]::ASCII.GetString($raw)
        }
        if ($exited) { return $null }
        Start-Sleep -Seconds 1
    }
}

function Invoke-Elevated([bool]$Fallback = $false) {
    # H4 steps 1, 2, 8: run the loader as an administrator and print what `result` says. Uninstall runs the installed copy, never
    # a fetch; the copy is judged by the elevated loader and the copy (AF05), and when no result comes the loader's exit code says
    # why: 5 nothing was installed, 4 the data folder is not administrators only, 6 (AF36) the copy is missing or is not the one the
    # journal names: only that code runs the loader once more with $RemoveLoader ($Fallback), a second elevation by design
    if (@('install', 'update', 'uninstall') -cnotcontains $Mode) { Stop-Refused 'install-failed' }
    if ([Environment]::GetFolderPath('ProgramFiles') -cne 'C:\Program Files') { Stop-Refused 'temp' }
    $guid = [guid]::NewGuid().ToString('N')
    if (Test-Path -LiteralPath ($StageRoot + '\' + $guid)) { Stop-Refused 'temp' }  # H4 step 4: a stage path that pre-existed
    if ($Fallback) {
        $text = $RemoveLoader -f $SerialNum, $MinNum, $guid, $bootSha
    } elseif ($Mode -ceq 'uninstall') {
        $text = $UninstallLoader -f $SerialNum, $MinNum, $guid
    } else {
        $text = $Loader -f $SerialNum, $MinNum, $GwNum, $guid, $bootSha, ($Mode.Substring(0, 1).ToUpperInvariant() + $Mode.Substring(1))
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $PowerShellExe
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -Command "' + $text + '"'
    $psi.UseShellExecute = $true
    $psi.Verb = 'runas'
    $proc = $null
    try { $proc = [System.Diagnostics.Process]::Start($psi) } catch { }  # a declined UAC prompt throws
    if ($null -eq $proc) { Stop-Refused 'elevate' }
    $out = $null
    $said = Wait-Result ($StageRoot + '\' + $guid + '\result') $proc
    if ($null -ne $said) { $out = Get-Outcome $said }
    if ($null -eq $out -and -not $Fallback -and $Mode -ceq 'uninstall' -and $proc.HasExited) {  # ExitCode throws on a running process
        if ($proc.ExitCode -eq 5) { Stop-Done 'DONE uninstall' 'Nothing was installed.' }
        if ($proc.ExitCode -eq 4) { Stop-Refused 'folder-owner' }
        if ($proc.ExitCode -eq 6) { Invoke-Elevated $true }
    }
    if ($null -eq $out) { Stop-Refused 'install-failed' }
    if ($out.Word) { Stop-Refused $out.Word }
    Stop-Done ('DONE ' + $Mode) $out.Sentence
}

function Test-Acl([string]$Path, [string]$Want) {
    # H4 step 4: protected, nothing inherited, exactly the ACEs of $Want (SDDL) in any order; else `temp`
    $sddl = (Get-Item -LiteralPath $Path -Force).GetAccessControl().GetSecurityDescriptorSddlForm('Access')
    $have = Get-Aces $sddl
    if ($null -eq $have -or $have -cne (Get-Aces $Want)) { Stop-Refused 'temp' }
}

function Get-Aces([string]$Sddl) {
    # the ACEs of a protected DACL, sorted and joined; $null when it is not protected or has anything but ACEs
    $m = [regex]::Match($Sddl, '^D:P(?:AI)?((?:\([^()]*\))+)\z')
    if (-not $m.Success) { return $null }
    $aces = [string[]]@([regex]::Matches($m.Groups[1].Value, '\([^()]*\)') | ForEach-Object { $_.Value })
    [Array]::Sort($aces, [StringComparer]::Ordinal)
    return ($aces -join '')
}

function Remove-StaleStages([string]$Keep, [bool]$All = $false) {
    # H4 step 8, AF30: the loaders remove their own stage, so this sweep only catches stage folders a killed or crashed loader left
    # behind, when older than $StageStale seconds, or of any age when $All (uninstall: it holds the only live stage); a link is skipped.
    $cut = (Get-Date).ToUniversalTime().AddSeconds(-$StageStale)
    try {
        foreach ($StageOld in [IO.Directory]::GetDirectories($StageRoot)) {
            if ([IO.Path]::GetFileName($StageOld) -cmatch '^[0-9a-f]{32}\z' -and $StageOld -cne $Keep -and ($All -or [IO.Directory]::GetCreationTimeUtc($StageOld) -lt $cut) -and -not [IO.File]::GetAttributes($StageOld).HasFlag([IO.FileAttributes]::ReparsePoint)) {
                Remove-Item -LiteralPath $StageOld -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}

function Get-Stage {
    # H4 step 6: an administrator, as <StageRoot>\<32 hex>\bootstrap.ps1, parent and stage with exactly the protected ACL; makes priv\
    $me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Stop-Refused 'elevate' }
    if ($Mode -ceq 'uninstall' -and $PSCommandPath -ceq [IO.Path]::Combine($InstallDir, 'boot', 'bootstrap.ps1')) {  # the installed copy runs from InstallDir\boot; its stage is the one the loader made, named in its environment
        $guid = [Environment]::GetEnvironmentVariable('MIRRORSTACK_STAGE')
        if ($guid -isnot [string] -or $guid -cnotmatch '^[0-9a-f]{32}\z') { Stop-Refused 'temp' }
        $StageDir = $StageRoot + '\' + $guid
    } else {  # install, update, and (AF36) the uninstall copy $RemoveLoader fetched: it runs from its own stage
        $StageDir = [IO.Path]::GetDirectoryName($PSCommandPath)
        if ([IO.Path]::GetFileName($PSCommandPath) -cne 'bootstrap.ps1' -or [IO.Path]::GetDirectoryName($StageDir) -cne $StageRoot -or [IO.Path]::GetFileName($StageDir) -cnotmatch '^[0-9a-f]{32}\z') { Stop-Refused 'temp' }
    }
    Test-Acl $StageRoot $StageSddl
    Test-Acl $StageDir $StageSddl
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($StageSddl)
    [void][IO.Directory]::CreateDirectory($StageDir + '\priv', $acl)
    Remove-StaleStages $StageDir ($Mode -ceq 'uninstall')
    return $StageDir
}

function Get-JournalSha {
    # H11: the bootstrap_sha256 the install journaled in uninstall.json; $null when the journal or that key is not readable
    $want = Get-Prop (Read-Json ([IO.Path]::Combine($InstallDir, 'uninstall.json'))) 'bootstrap_sha256'
    if (Test-Sha $want) { return $want }
    return $null
}

function Test-TreeJournaled([string]$Root, $Tree) {
    # H2, as install.tampered: no link, and every file under $Root is one the journal lists with its sha256 (a journaled file that is gone is fine)
    if (-not (Test-Path -LiteralPath $Root)) { return $true }
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Recurse -Force)) {
        if ($item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) { return $false }
        if ($item.PSIsContainer) { continue }
        $prop = $null
        if ($null -ne $Tree) { $prop = $Tree.PSObject.Properties[$item.FullName.Substring($Root.Length + 1)] }
        if ($null -eq $prop -or $prop.Value -cne (Get-Sha $item.FullName)) { return $false }
    }
    return $true
}

function Get-AclLines([string]$Text, [string]$Root) {
    # install.acl_lines: icacls' entries for $Root, sorted, `who:(flags)` only (the path and any localised summary line dropped)
    $first = [regex]::new([regex]::Escape($Root + ' ')).Replace($Text, '', 1)
    $lines = @(foreach ($raw in ($first -split '\r?\n')) { $hit = [regex]::Match($raw.Trim(), '^\S.*?:(?:\([A-Za-z0-9,]+\))+\z'); if ($hit.Success) { $hit.Value } })
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    return , $lines
}

function Get-FolderSddl([string]$Path) {
    # AF46: the folder's DACL as SDDL (SIDs, no language in it); one line so the pwsh harness can stub it
    return (Get-Item -LiteralPath $Path -Force).GetAccessControl().GetSecurityDescriptorSddlForm('Access')
}

function Test-Journaled($Journal) {
    # H2: the install folder is as the journal says (tree, then ACL); no folder, or a journal with none of the fields, has nothing to check.
    # AF46: a journal with `sddl` is compared on that whole string (-ceq, the live DACL, inherited ACEs and all: the protected-DACL reader
    # would turn an inherited `D:AI(` into $null); one that is no `D:` string, or a live reading that fails, is a mismatch. icacls only for acl without sddl.
    $tree = Get-Prop $Journal 'tree'
    $acl = Get-Prop $Journal 'acl'
    $sddl = Get-Prop $Journal 'sddl'
    if (-not (Test-Path -LiteralPath $ProgramDir) -or ($null -eq $tree -and $null -eq $acl -and $null -eq $sddl)) { return $true }
    if (-not (Test-TreeJournaled $ProgramDir $tree)) { return $false }
    if ($null -ne $sddl) {
        if ($sddl -isnot [string] -or $sddl -cnotmatch '^D:') { return $false }
        try { $live = Get-FolderSddl $ProgramDir } catch { return $false }
        return ($live -is [string] -and $live -ceq $sddl)
    }
    $got = Invoke-Proc $IcaclsExe ('"{0}"' -f $ProgramDir) $true 60
    $want = [string[]]@($acl)
    [Array]::Sort($want, [StringComparer]::Ordinal)
    return ($got.Code -eq 0 -and ((Get-AclLines $got.Out $ProgramDir) -join "`n") -ceq ($want -join "`n"))
}

function Invoke-FixedRemoval {
    # H2, H11: what the install made, by the constant names of this copy only (nothing is read from or run out of the installed
    # folder or the journal), each step on its own. A spike report stays (it may not have been delivered); power and VM-service
    # settings, and a CPython the install made (kept by name below, read by nobody), stay as they are.
    foreach ($task in @('actuator', 'tick', 'sensor')) {
        try { $null = Invoke-Proc $SchtasksExe ('/End /TN "\MirrorStack Fleet\{0}"' -f $task) $true 60 } catch { }  # AF46: a running instance first; the code is ignored
        try { $null = Invoke-Proc $SchtasksExe ('/Delete /TN "\MirrorStack Fleet\{0}" /F' -f $task) $true 60 } catch { }
    }
    $steps = @(
        { if (Get-VM -Name 'fleet-l1' -ErrorAction SilentlyContinue) {
            if ((Get-VM -Name 'fleet-l1').State -ne 'Off') { Stop-VM -Name 'fleet-l1' -TurnOff -Force }
            Get-VMNetworkAdapterAcl -VMName 'fleet-l1' -ErrorAction SilentlyContinue | Remove-VMNetworkAdapterAcl
            Get-VMHardDiskDrive -VMName 'fleet-l1' | Remove-VMHardDiskDrive
            Remove-VM -Name 'fleet-l1' -Force } },
        { Remove-NetFirewallRule -DisplayName 'MirrorStack Fleet: block inbound on vEthernet (fleet-nat)' -ErrorAction SilentlyContinue },
        { if (Get-NetAdapter -Name 'vEthernet (fleet-nat)' -ErrorAction SilentlyContinue) { Enable-NetAdapterBinding -Name 'vEthernet (fleet-nat)' -ComponentID ms_tcpip6 } },
        { Remove-NetNat -Name 'fleet-nat' -Confirm:$false -ErrorAction SilentlyContinue },
        { Remove-VMSwitch -Name 'fleet-nat' -Force -ErrorAction SilentlyContinue },
        { $vm = [IO.Path]::Combine($InstallDir, 'vm')
          if (Test-Path -LiteralPath $vm) {
            foreach ($f in @(Get-ChildItem -LiteralPath $vm -Recurse -File -Force)) {
                $f.IsReadOnly = $false
                $zeros = [byte[]]::new(1MB)
                $stream = [IO.File]::OpenWrite($f.FullName)
                try { for ($left = $f.Length; $left -gt 0; $left -= $zeros.Length) { $stream.Write($zeros, 0, [int][Math]::Min($left, $zeros.Length)) } } finally { $stream.Close() }
            } } },
        { if (Test-Path -LiteralPath $LinksDir) { [IO.Directory]::Delete($LinksDir, $true) } },
        { if (Test-Path -LiteralPath $ProgramDir) { [IO.Directory]::Delete($ProgramDir, $true) } }
    )
    $failed = 0
    foreach ($step in $steps) { try { & $step } catch { $failed++ } }
    # a step that failed leaves the journal and the data folder for the next run: it is a refusal, never "removed"
    if ($failed -gt 0) { Stop-Refused 'install-failed' }
    foreach ($entry in @(Get-ChildItem -LiteralPath $InstallDir -Force)) {
        # AF46: the Python the install made stays removable: its setup and note are kept by name, never read
        if (@('python-setup.exe', 'python.json') -ccontains $entry.Name) { continue }
        if ($entry.Name -cne 'spike') { Remove-Item -LiteralPath $entry.FullName -Recurse -Force -ErrorAction SilentlyContinue }
        else { foreach ($kept in @(Get-ChildItem -LiteralPath $entry.FullName -Force)) { if ($kept.Name -cne 'report.txt') { Remove-Item -LiteralPath $kept.FullName -Recurse -Force -ErrorAction SilentlyContinue } } }
    }
}

function Get-RemovalSentence([bool]$Fixed) {
    # H6, H11: one sentence that names what was left: the spike report (the fixed routine keeps it)
    $say = 'MirrorStack was removed from this computer.'
    if ($Fixed) { $say = 'MirrorStack was removed by the fixed routine; power and VM-service settings and any Python it installed stay.' }
    $report = [IO.Path]::Combine($InstallDir, 'spike', 'report.txt')
    if (Test-Path -LiteralPath $report) { $say += ' The spike report was kept: ' + $report }
    return $say
}

function Invoke-Removal {
    # H2, H4 step 6 (the elevated installed copy): the installed removal when Python is there and the install is as journaled, else the fixed routine
    $journal = Read-Json ([IO.Path]::Combine($InstallDir, 'uninstall.json'))
    $entry = [IO.Path]::Combine($ProgramDir, 'bin', 'fleet-carrier.py')
    $fixed = ($null -eq $journal) -or -not ((Test-Path -LiteralPath $PythonExe) -and (Test-Path -LiteralPath $entry) -and (Test-Journaled $journal))
    if ($fixed) {
        Invoke-FixedRemoval
    } else {
        $ran = Invoke-Proc $PythonExe ('-I -X utf8 "{0}" uninstall' -f $entry) $false 3600
        if ($ran.Code -ne 0) { Stop-Refused 'install-failed' }
    }
    Stop-Done 'DONE uninstall' (Get-RemovalSentence $fixed)
}

function Write-Result([string]$Line, [string]$Sentence) {
    # H4 step 7, the last act: the two lines to result.tmp (with the Users read ACE), renamed to `result`; stage.py's own stays.
    # A refusal before $Stage was set (the machine checks, a failed key check) finds the stage here; one whose path or ACL cannot be
    # verified writes nothing (the parent then says install-failed), never into a folder a standard user might write
    if ($null -eq $Stage -and $Elevated -and @('install', 'update', 'uninstall') -ccontains $Mode) { try { $script:Stage = Get-Stage } catch { return } }
    if ($null -eq $Stage -or (Test-Path -LiteralPath ($Stage + '\result'))) { return }
    try {
        $sec = New-Object Security.AccessControl.FileSecurity
        $sec.SetSecurityDescriptorSddlForm($ResultSddl)
        $out = [IO.File]::Create($Stage + '\result.tmp', 4096, [IO.FileOptions]::None, $sec)
        try { $bytes = [Text.Encoding]::ASCII.GetBytes($Line + "`n" + $Sentence + "`n"); $out.Write($bytes, 0, $bytes.Length) } finally { $out.Dispose() }
        [IO.File]::Move($Stage + '\result.tmp', $Stage + '\result')
    } catch { }
}

function Read-Invite {
    # H1: a no-echo prompt in the elevated window, never in the line; upper case, no spaces or hyphens; three wrong shapes is `invite`
    for ($try = 0; $try -lt 3; $try++) {
        $secure = Read-Host -AsSecureString 'Invite code (typing is hidden)'
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $text = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $code = ($text -replace '[ -]', '').ToUpperInvariant()
        if ($code -cmatch '^[23456789CFGHJMPQRVWX]{10}\z') { return $code }
    }
    Stop-Refused 'invite'
}

function Copy-Capped($In, $Out, [long]$Limit, [int]$Seconds) {
    # reads at most $Limit bytes of $In into $Out, so a longer stream is cut there; returns the count read. The whole read (not
    # only the headers, which HttpClient.Timeout covers) gets $Seconds, like curl's --max-time: a stalled read is `fetch`
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $buf = New-Object byte[] 65536
    [long]$total = 0
    while ($total -lt $Limit) {
        $task = $In.ReadAsync($buf, 0, [int][Math]::Min($buf.Length, $Limit - $total))
        $left = $Seconds * 1000 - $clock.ElapsedMilliseconds
        if ($left -le 0 -or -not $task.Wait([int]$left)) { Stop-Refused 'fetch' }
        $n = $task.Result
        if ($n -le 0) { break }
        $Out.Write($buf, 0, $n)
        $total += $n
    }
    return $total
}

function Get-Kit([string]$Url, [string]$To, [long]$Cap, [string]$Invite, [int]$Seconds) {
    # H3 steps 2-3: one kit-host file, https only, the invite in Authorization: FleetInvite <code> (never a URL or argv); 404 is invite-refused, 429
    # rate-limited; at most $Cap + 1 bytes are read, so a longer stream is `size`
    if ($Url -notmatch '^https://') { Stop-Refused 'fetch' }
    # the header is built from a code shaped like Read-Invite's, so a line break can never reach it (the validating Headers.Add is gone)
    if ($Invite -cnotmatch '^[23456789CFGHJMPQRVWX]{10}\z') { Stop-Refused 'invite' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($Seconds)
    $got = 0
    try {
        $client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('FleetInvite', $Invite)
        $resp = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $status = [int]$resp.StatusCode
        if ($status -eq 404) { Stop-Refused 'invite-refused' }
        if ($status -eq 429) { Stop-Refused 'rate-limited' }
        if ($status -ne 200) { Stop-Refused 'fetch' }
        $in = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $file = [IO.File]::Open($To, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        try { $got = Copy-Capped $in $file ($Cap + 1) $Seconds } finally { $file.Dispose() }
    } catch {
        if ($_.Exception.Message -cmatch '^REFUSED ') { throw }
        Stop-Refused 'fetch'
    } finally { $client.Dispose() }
    if ($got -gt $Cap) { Stop-Refused 'size' }
}

function Get-KitUrls([string]$Url) {
    # H3: bundle.url is https://<kit-host>/v1/kit/<this serial>/bundle.tar, not GitHub's host; the two records beside it replace
    # the last segment; anything else is `form`
    $m = [regex]::Match($Url, '^(https://([a-z0-9.-]{3,200})/v1/kit/' + $SerialNum + '/)([A-Za-z0-9._-]{1,64})\z')
    if (-not $m.Success -or $m.Groups[3].Value -cne 'bundle.tar' -or $m.Groups[2].Value -cmatch '(^|\.)(github\.com|githubusercontent\.com)\z') { Stop-Refused 'form' }
    $base = $m.Groups[1].Value
    return [pscustomobject]@{ Bundle = $Url; Gateway = $base + 'gateway.json'; GatewaySig = $base + 'gateway.json.sig' }
}

function Read-Bundle($Doc) {
    # install.json's bundle and lock_sha256 in their shapes, else `form`, before anything is fetched from kit-serve
    $b = Get-Prop $Doc 'bundle'
    $out = [pscustomobject]@{ Head = Get-Prop $b 'head'; Tree = Get-Prop $b 'tree'; Url = Get-Prop $b 'url'; Sha = Get-Prop $b 'sha256'; Size = Get-Prop $b 'size'; Lock = Get-Prop $Doc 'lock_sha256' }
    foreach ($id in @($out.Head, $out.Tree)) { if ($id -isnot [string] -or $id -cnotmatch '^[0-9a-f]{40}\z') { Stop-Refused 'form' } }
    if (-not (Test-Sha $out.Sha) -or -not (Test-Sha $out.Lock) -or $out.Url -isnot [string]) { Stop-Refused 'form' }
    if (-not (Test-Int $out.Size) -or $out.Size -lt 1 -or $out.Size -gt $BundleMax) { Stop-Refused 'form' }
    return $out
}

function Test-Gateway([string]$Json, [string]$Sig) {
    # H3 step 2: signed in the pin namespace (else gateway-pin); no whole serial or boolean r9_closed is `form`; serial 0, no
    # address or a serial below -GwSerial is gateway-not-live
    $fp = ''
    try { $fp = Test-Signature $Json $Sig $PinNamespace } catch { if ($_.Exception.Message -cne 'REFUSED sig') { throw } }
    if ($fp -cne $fingerprint) { Stop-Refused 'gateway-pin' }
    $gw = Read-Json $Json
    $serial = Get-Prop $gw 'serial'
    if (-not (Test-Int $serial) -or (Get-Prop $gw 'r9_closed') -isnot [bool]) { Stop-Refused 'form' }
    if ($serial -lt 1 -or $serial -lt $GwNum -or $null -eq (Get-Prop $gw 'address')) { Stop-Refused 'gateway-not-live' }
}

function Get-Python($Kit) {
    # the kit's embedded Python: python.org's ZIP, hashed against kit.json, expanded in $Work; returns python.exe's path
    $zipTo = Join-Path $Work 'python.zip'
    Get-Url ($PythonUrl -f $Kit.Version) $zipTo 33554432 300
    if ((Get-Sha $zipTo) -cne $Kit.ZipSha) { Stop-Refused 'zip-hash' }
    $pyDir = Join-Path $Work 'python'
    Expand-Archive -LiteralPath $zipTo -DestinationPath $pyDir
    return (Join-Path $pyDir 'python.exe')
}

function Invoke-Install($Json, $Install, [string]$KitJson) {
    # H3 steps 1-6 after the chain: verifier and Python, pin, invite, gateway.json, bundle, closure, lock, then stage.py; every
    # file lands in the stage and nothing from the bundle runs before the lock matches
    $kit = Read-Kit $KitJson $Install
    $bundle = Read-Bundle $Json
    $urls = Get-KitUrls $bundle.Url
    $verifier = Join-Path $KitDir 'verify-archive.py'
    Get-Url ($Tag + '/verify-archive.py') $verifier 4194304
    if ((Get-Sha $verifier) -cne @($kit.Files | Where-Object { $_.path -ceq 'verify-archive.py' })[0].sha256) { Stop-Refused 'file-hash' }
    $py = Get-Python $kit
    $pin = Join-Path $Work 'deploy-pin.json'
    Get-Url ($Tag + '/deploy-pin.json') $pin 4096
    Get-Url ($Tag + '/deploy-pin.json.sig') ($pin + '.sig') 4096
    $invite = Read-Invite
    [IO.File]::WriteAllText($Stage + '\priv\inv.txt', $invite, [Text.Encoding]::ASCII)
    # the design's paths: gateway.json, its signature and the extracted tree sit in the stage itself, the invite in priv\; whatever
    # the stage holds of them is removed on every way out (stage.py has read the invite by then), `result` and this copy stay
    $gw = Join-Path $Stage 'gateway.json'
    $x = Join-Path $Stage 'x'
    try {
        Get-Kit $urls.Gateway $gw 65536 $invite 120
        Get-Kit $urls.GatewaySig ($gw + '.sig') 4096 $invite 120
        Test-Gateway $gw ($gw + '.sig')
        $tar = Join-Path $Work 'bundle.tar'
        Get-Kit $urls.Bundle $tar $bundle.Size $invite 1800
        if ((Get-Item -LiteralPath $tar).Length -ne $bundle.Size -or (Get-Sha $tar) -cne $bundle.Sha) { Stop-Refused 'bundle-hash' }
        [void][IO.Directory]::CreateDirectory($x)
        $pub = Join-Path $x 'owner-pin.pub'
        [IO.File]::WriteAllText($pub, $OwnerKey + "`n", [Text.Encoding]::ASCII)
        $ran = Invoke-Proc $py ('-I -X utf8 "{0}" --closure "{1}" "{2}" "{3}" "{4}" "{5}"' -f $verifier, $tar, $pub, $pin, ($pin + '.sig'), $x) $false 900
        if ($ran.Code -ne 0) { Stop-Refused 'closure' }
        $root = Join-Path $x ('mirrorstack-fleet-' + $bundle.Head)
        $stamp = $null
        if (Test-Path -LiteralPath (Join-Path $root 'ARCHIVE-VERIFIED')) { $stamp = Read-Json (Join-Path $root 'ARCHIVE-VERIFIED') }
        if ((Get-Prop $stamp 'head') -cne $bundle.Head -or (Get-Prop $stamp 'tree') -cne $bundle.Tree) { Stop-Refused 'pin-mismatch' }
        $lock = Join-Path $root 'fleet\carrier\carrier.lock.json'
        if (-not (Test-Path -LiteralPath $lock) -or (Get-Sha $lock) -cne $bundle.Lock) { Stop-Refused 'carrier-lock' }
        $go = '-I -X utf8 "{0}" --head {1} --owner-pin "{2}" --gw-serial {3} --gw-json "{4}" --gw-sig "{5}" --invite-file "{6}" --bootstrap-file "{7}" --mode {8} --proof {9}'
        $ran = Invoke-Proc $py ($go -f (Join-Path $root 'fleet\install\stage.py'), $bundle.Head, $pub, $GwNum, $gw, ($gw + '.sig'), ($Stage + '\priv\inv.txt'), $PSCommandPath, $Mode, $Install.Proof) $false 0
        if ($ran.Code -ne 0) { Stop-Refused 'install-failed' }
    } finally {
        Remove-Item -LiteralPath ($Stage + '\priv\inv.txt') -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $gw, ($gw + '.sig') -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $x -Recurse -Force -ErrorAction SilentlyContinue
    }
    Stop-Done ('DONE ' + $Mode) $(if ($Mode -ceq 'update') { 'This computer was updated.' } else { 'This computer is installed.' })
}

function Read-StatusFile {
    # H11: status.json, at most 4096 bytes, JSON, display only; $null when there is none, Valid false when it cannot be read
    if (-not (Test-Path -LiteralPath $StatusFile)) { return $null }
    $item = Get-Item -LiteralPath $StatusFile -Force
    $doc = $null
    if (-not $item.PSIsContainer -and $item.Length -le 4096 -and -not $item.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        # the same flat shape bootstrap.sh holds (STATUS_JSON): short keys, and string, whole-number, boolean or null values only
        $flat = ''
        try { $flat = [regex]::Replace([IO.File]::ReadAllText($StatusFile), '[ \t\r\n]', '') } catch { }
        if ($flat -cmatch $StatusShape) { $doc = Read-Json $StatusFile }
    }
    if ($doc -isnot [pscustomobject]) { return [pscustomobject]@{ Valid = $false; Head = $null; Paused = $false; Revoked = $false } }
    $head = Get-Prop $doc 'installed_head'
    if ($head -isnot [string] -or $head -cnotmatch '^[0-9a-f]{40}\z') { $head = $null }
    return [pscustomobject]@{ Valid = $true; Head = $head; Paused = ((Get-Prop $doc 'paused') -is [bool] -and (Get-Prop $doc 'paused')); Revoked = ((Get-Prop $doc 'revoked') -is [bool] -and (Get-Prop $doc 'revoked')) }
}

function Get-LatestHead {
    # the signed source_head of the release the line names, or $null: a failed fetch or chain is `latest: unknown`, never a refusal
    $Work = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'mirrorstack-fleet-' + [guid]::NewGuid().ToString('N'))
    if ($Work -cmatch '["%^&!<>|]') { Stop-Refused 'temp' }
    try {
        if ((Get-Date).ToUniversalTime() -ge (Get-Utc $Expires)) { return $null }
        [void][IO.Directory]::CreateDirectory($Work)
        $tag = '{0}/install-{1}' -f $Release, $SerialNum
        $doc = Join-Path $Work 'install.json'
        Get-Url ($tag + '/install.json') $doc 8192
        Get-Url ($tag + '/install.json.sig') (Join-Path $Work 'install.json.sig') 4096
        if ((Test-Signature $doc (Join-Path $Work 'install.json.sig')) -cne $fingerprint) { return $null }
        $json = Read-Json $doc
        $install = Read-Install $json
        if ((Get-Date).ToUniversalTime() -ge $install.Until) { return $null }
        Test-Serial $install
        if ($bootSha -cne $install.Boot) { return $null }
        Test-Handoff $install
        $head = Get-Prop $json 'source_head'
        if ($head -is [string] -and $head -cmatch '^[0-9a-f]{40}\z') { return $head }
        return $null
    } catch {
        return $null
    } finally {
        if (Test-Path -LiteralPath $Work) { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-Status {
    # H2: unelevated and display only; refusals are args os arch tools key temp, and a failed chain is `latest: unknown`
    $file = Read-StatusFile
    if ($null -eq $file) { Stop-Done 'STATUS not-installed' 'Nothing is installed on this computer.' }
    Write-Host ('installed ' + $(if ($file.Head) { $file.Head } else { '?' }))
    $latest = Get-LatestHead
    if ($latest) { Write-Host ('latest ' + $latest) } else { Write-Host 'latest: unknown' }
    $state = 'unknown'
    $say = 'The state of this computer could not be read. Tell the owner.'
    if ($file.Valid -and $file.Revoked) { $state = 'revoked'; $say = 'Removed by MirrorStack. You can uninstall it with the uninstall line.' }
    elseif ($file.Valid -and $file.Paused) { $state = 'paused'; $say = 'The software is installed and paused.' }
    elseif ($file.Valid -and $file.Head -and $latest -and $file.Head -ceq $latest) { $state = 'installed-current'; $say = 'This computer has the latest release.' }
    elseif ($file.Valid -and $file.Head -and $latest) { $state = 'installed-behind'; $say = 'A newer release is out. Ask the owner for the update line.' }
    Stop-Done ('STATUS ' + $state) $say
}

function Send-Code([string]$Report, [int]$Status) {
    $text = ''
    if (Test-Path -LiteralPath $Report) { $text = [IO.File]::ReadAllText($Report, [Text.Encoding]::UTF8) }
    $m = [regex]::Match($text, $CodePattern)
    if (-not $m.Success) { Stop-Refused 'check-failed' }
    $code = $m.Groups[1].Value
    Write-Host ''
    Write-Host ('Your code: ' + $code)
    try { Set-Clipboard -Value $code; Write-Host 'The code is copied. Paste it where the owner asked.' }
    catch { Write-Host 'Copy the code by hand and send it to the owner.' }
    return $Status
}

$ExitCode = 1
try {
    $parsed = Get-Args @($args)
    $Mode = $parsed['Mode']
    $SerialNum = $parsed['-Serial']
    $MinNum = $parsed['-MinSerial']
    $GwNum = $parsed['-GwSerial']
    $Elevated = $parsed['Elevated']
    Test-Machine
    if (-not $PSCommandPath) { Stop-Refused 'boot-hash' }
    $bootSha = Get-Sha $PSCommandPath
    Write-Host ('bootstrap sha256 ' + $bootSha)
    if ($OwnerKey -cnotmatch '^ssh-ed25519 [A-Za-z0-9+/]{68}\z') { Stop-Refused 'key' }
    $fingerprint = Get-Fingerprint $OwnerKey
    Write-Host ('key ' + $fingerprint)
    if ($Elevated -and @('install', 'update', 'uninstall') -ccontains $Mode) { $Stage = Get-Stage }  # H4 step 6, before anything is fetched
    if ($Mode -ceq 'uninstall') {  # H2: no network, no signature, no expiry: an expired or withdrawn line still removes the software
        Write-Host ('serial {0} min-serial {1}' -f $SerialNum, $MinNum)
        if (-not $Elevated) { Invoke-Elevated }  # AF05: the unelevated half reads nothing from the data folder
        if (-not (Test-Installed)) { Stop-Done 'DONE uninstall' 'Nothing was installed.' }
        if ($PSCommandPath -cne [IO.Path]::Combine($InstallDir, 'boot', 'bootstrap.ps1')) {  # AF36: Get-Stage vouched for a stage copy, the loader pinned its hash
            Invoke-FixedRemoval  # no journal compare, never fleet-carrier.py, nothing read from the data folder
            Stop-Done 'DONE uninstall' (Get-RemovalSentence $true)
        }
        if ($bootSha -cne (Get-JournalSha)) { Stop-Refused 'install-failed' }  # H4 step 6: the copy that runs is the one the journal names
        Invoke-Removal
    }
    if ($Mode -ceq 'status') { Invoke-Status }
    if ($Elevated -and @('install', 'update') -ccontains $Mode) {  # H2: a local read, before the clock and the network (elevated only, AF05)
        if ((Test-Installed) -and $Mode -ceq 'install') {
            if (-not (Test-Finished)) { Stop-Refused 'install-failed' }  # AF30: an install that began and did not finish is not `installed`
            Stop-Refused 'installed'
        }
        if (-not (Test-Installed) -and $Mode -ceq 'update') { Stop-Refused 'not-installed' }
    }
    if ((Get-Date).ToUniversalTime() -ge (Get-Utc $Expires)) { Stop-Refused 'expired' }
    $Work = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'mirrorstack-fleet-' + [guid]::NewGuid().ToString('N'))
    if ($Stage) { $Work = $Stage + '\w' }  # the elevated copy keeps its files inside the protected stage
    if ($Work -cmatch '["%^&!<>|]') { Stop-Refused 'temp' }
    $KitDir = Join-Path $Work 'kit'
    [void][IO.Directory]::CreateDirectory($KitDir)
    $Tag = '{0}/install-{1}' -f $Release, $SerialNum

    $doc = Join-Path $Work 'install.json'
    Get-Url ($Tag + '/install.json') $doc 8192 120 ($doc + '.hdr')
    Test-Clock ($doc + '.hdr')
    Get-Url ($Tag + '/install.json.sig') (Join-Path $Work 'install.json.sig') 4096
    if ((Test-Signature $doc (Join-Path $Work 'install.json.sig')) -cne $fingerprint) { Stop-Refused 'sig' }
    $json = Read-Json $doc
    Write-Serial $json
    $install = Read-Install $json
    if ((Get-Date).ToUniversalTime() -ge $install.Until) { Stop-Refused 'expired' }
    Test-Serial $install
    if ($bootSha -cne $install.Boot) { Stop-Refused 'boot-hash' }

    Test-Handoff $install
    $kitJson = Join-Path $Work 'kit.json'
    Get-Url ($Tag + '/kit.json') $kitJson 65536
    if ((Get-Sha $kitJson) -cne $install.KitSha) { Stop-Refused 'kit-hash' }
    if (@('install', 'update') -ccontains $Mode) {  # H2's unelevated half ends here: the kit must be serial 5 or newer
        if ($install.KitSerial -lt $MinKitSerial) { Stop-Refused 'kit-old' }
        if ($Stage) { Invoke-Install $json $install $kitJson }
        Invoke-Elevated
    }
    $kit = Read-Kit $kitJson $install
    foreach ($f in $kit.Files) {
        $to = Join-Path $KitDir $f.path
        Get-Url ($Tag + '/' + $f.path) $to 4194304
        if ((Get-Sha $to) -cne $f.sha256) { Stop-Refused 'file-hash' }
    }
    $py = Get-Python $kit
    Write-Host 'Every file matches the signed release. Running the check (about a minute; nothing is changed).'
    $ran = Invoke-Proc $py ('-I -X utf8 "{0}" check' -f (Join-Path $KitDir 'carrier-check.py')) $false 900
    $ExitCode = Send-Code (Join-Path $KitDir 'carrier-check-report.txt') $ran.Code
} catch {
    if ($_.Exception.Message -ceq 'DONE') {
        $ExitCode = 0
        Write-Result $Done[0] $Done[1]
    } else {
        $code = 'unexpected'
        if ($_.Exception.Message -cmatch '^REFUSED ([a-z0-9-]+)\z') { $code = $Matches[1] }
        if (-not $Words.ContainsKey($code)) { $code = 'unexpected' }
        Write-Host ('REFUSED ' + $code)
        Write-Host $Words[$code]
        Write-Result ('REFUSED ' + $code) $Words[$code]
    }
} finally {
    if ($Work -and (Test-Path -LiteralPath $Work)) { Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue }
}
if ($Elevated) { try { [void](Read-Host 'Press Enter to close this window') } catch { } }  # H4 step 7: the elevated window waits
exit $ExitCode
