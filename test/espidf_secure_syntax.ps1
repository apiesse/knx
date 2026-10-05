param(
    [Parameter(Mandatory = $true)] [string] $CompileDatabase,
    [string] $OriginalWorkspace = 'C:/git/knxRoomUnit',
    [string] $WorktreeRoot = ''
)

# Reuse a configured ESP-IDF build's real SDK flags without writing objects,
# generated configuration, or any source/build files in the original checkout.
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($WorktreeRoot)) {
    $WorktreeRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../..'))
}
$knxOriginal = [IO.Path]::GetFullPath($OriginalWorkspace).Replace('\', '/').TrimEnd('/')
$knxWorktree = [IO.Path]::GetFullPath($WorktreeRoot).Replace('\', '/').TrimEnd('/')
$knxRepo = "$knxWorktree/libs/fw/OpenKNX-knx"
$knxDb = Get-Content -Raw -LiteralPath $CompileDatabase | ConvertFrom-Json
$knxPaths = @(& git -C $knxRepo -c core.safecrlf=false diff --name-only -- src 2>$null)
$knxPaths += @(& git -C $knxRepo ls-files --others --exclude-standard src)
# Keep critical units explicit so this remains useful after the feature is
# committed and git diff/untracked no longer reports the secure source files.
$knxPaths += @('src/espidf_platform.cpp',
    'src/knx/bau07B0.cpp', 'src/knx/bau091A.cpp',
    'src/knx/bau27B0.cpp', 'src/knx/bau57B0.cpp',
    'src/knx/bau2920.cpp', 'src/knx/bau_systemB.cpp',
    'src/knx/bau_systemB_coupler.cpp', 'src/knx/bau_systemB_device.cpp',
    'src/knx/cemi_frame.cpp', 'src/knx/cemi_server.cpp', 'src/knx/data_property.cpp',
    'src/knx/ip_data_link_layer.cpp', 'src/knx/ip_parameter_object.cpp',
    'src/knx/ip_tunnel_server.cpp', 'src/knx/knx_ip_description_response.cpp',
    'src/knx/knx_ip_search_response.cpp', 'src/knx/knx_ip_search_response_extended.cpp',
    'src/knx/knx_ip_tunnel_connection.cpp', 'src/knx/network_layer_coupler.cpp',
    'src/knx/platform.cpp', 'src/knx/router_object.cpp', 'src/knx/memory.cpp',
    'src/knx/secure_application_layer.cpp', 'src/knx/security_interface_object.cpp',
    'src/knx/ip_secure.cpp', 'src/knx/secure_proxy.cpp')
$knxUnits = @($knxPaths | Where-Object { $_ -match '\.cpp$' } | Select-Object -Unique |
    ForEach-Object { "libs/fw/OpenKNX-knx/$_" })
$knxUnits += @('libs/fw/OpenKNX-knx/src/knx/aes.c',
    'firmware/knxRoomUnit/components/knx/knx_adapter.cpp',
    'firmware/knxRoomUnit/main/main.c')
$knxCppTemplate = $knxDb | Where-Object {
    $_.file.Replace('\', '/') -eq "$knxOriginal/libs/fw/OpenKNX-knx/src/knx/ip_data_link_layer.cpp"
} | Select-Object -First 1
$knxCTemplate = $knxDb | Where-Object {
    $_.file.Replace('\', '/') -eq "$knxOriginal/firmware/knxRoomUnit/main/main.c"
} | Select-Object -First 1
if (!$knxCppTemplate -or !$knxCTemplate) {
    throw 'The compile database must contain OpenKNX ip_data_link_layer.cpp and firmware main.c.'
}
if ($knxCppTemplate.command -notmatch '(?:^| )-I(?<sdkroot>[^ ]+)/components/esp_hw_support/include(?: |$)') {
    throw 'Cannot locate ESP-IDF SDK include root in the compile database.'
}
$knxBootloaderInclude = "-I$($Matches.sdkroot)/components/bootloader_support/include"
$knxSecureProfile = "$knxWorktree/firmware/knxRoomUnit/main/knx_secure_profile.generated.h"
if (!(Test-Path -LiteralPath $knxSecureProfile)) {
    throw 'Generate the RoomUnit Secure capacity profile before running syntax checks.'
}

$knxErrors = 0
foreach ($knxUnit in $knxUnits) {
    $knxEntry = $knxDb | Where-Object {
        $_.file.Replace('\', '/') -eq "$knxOriginal/$knxUnit"
    } | Select-Object -First 1
    if (!$knxEntry) {
        if ($knxUnit.EndsWith('.cpp')) { $knxEntry = $knxCppTemplate }
        else { $knxEntry = $knxCTemplate }
    }
    if ($knxEntry.command -notmatch '^(?:"(?<exe>[^"]+)"|(?<exe>\S+)) (?<args>.*)$') {
        throw "Unsupported compiler command for $knxUnit"
    }
    $knxExe = $Matches.exe
    $knxArgs = $Matches.args
    # Other configured compile databases may carry dependency-output flags.
    # Remove those as well: a syntax check must not overwrite the original
    # build's .d files even when GCC is invoked with -MD/-MF.
    $knxArgs = [regex]::Replace($knxArgs, ' (?:-MD|-MMD|-MP)(?= |$)', '')
    $knxArgs = [regex]::Replace($knxArgs, ' -(?:MF|MT|MQ|MJ) (?:"[^"]+"|\S+)', '')
    $knxArgs = $knxArgs.Replace("$knxOriginal/libs/", "$knxWorktree/libs/").
        Replace("$knxOriginal/firmware/knxRoomUnit/components/", "$knxWorktree/firmware/knxRoomUnit/components/").
        Replace("$knxOriginal/firmware/knxRoomUnit/main", "$knxWorktree/firmware/knxRoomUnit/main")
    # Generated config/build include paths intentionally remain in the original
    # build: the worktree has not been configured with this SDK/board yet.
    $knxExtra = " -DUSE_DATASECURE -DCONFIG_KNX_DATA_SECURE=1 $knxBootloaderInclude -include `"$knxSecureProfile`""
    if ($knxUnit -match '/bau27B0\.cpp$') {
        $knxArgs = $knxArgs.Replace('-DMASK_VERSION=0x07B0', '-DMASK_VERSION=0x27B0')
    }
    elseif ($knxUnit -match '/bau2920\.cpp$') {
        $knxArgs = $knxArgs.Replace('-DMASK_VERSION=0x07B0', '-DMASK_VERSION=0x2920')
    }
    elseif ($knxUnit -match '/bau57B0\.cpp$') {
        $knxArgs = $knxArgs.Replace('-DMASK_VERSION=0x07B0', '-DMASK_VERSION=0x57B0')
        $knxExtra += ' -DUSE_IPSECURE -DKNX_TUNNELING=1 -DKNX_SERVICE_FAMILY_CORE=2'
    }
    elseif ($knxUnit -match '/(ip_|knx_ip_|network_layer_coupler|bau091A|bau_systemB_coupler|secure_proxy)') {
        $knxArgs = $knxArgs.Replace('-DMASK_VERSION=0x07B0', '-DMASK_VERSION=0x091A')
        # USE_IP is derived from MASK_VERSION by config.h; defining it again
        # triggers the SDK's -Werror=macro-redefined.
        $knxExtra += ' -DUSE_IPSECURE -DKNX_TUNNELING=1 -DKNX_SERVICE_FAMILY_CORE=2'
    }
    $knxTail = ' -o (?:"[^"]+"|\S+) -c (?:"[^"]+"|\S+)\s*$'
    if ($knxArgs -notmatch $knxTail) { throw "Cannot safely remove object-output options for $knxUnit" }
    $knxArgs = [regex]::Replace($knxArgs, $knxTail, " -fsyntax-only$knxExtra `"$knxWorktree/$knxUnit`"")
    $knxProc = New-Object System.Diagnostics.Process
    $knxProc.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $knxProc.StartInfo.FileName = $knxExe
    $knxProc.StartInfo.Arguments = $knxArgs
    $knxProc.StartInfo.UseShellExecute = $false
    $knxProc.StartInfo.CreateNoWindow = $true
    $knxProc.StartInfo.RedirectStandardOutput = $true
    $knxProc.StartInfo.RedirectStandardError = $true
    [void]$knxProc.Start()
    $knxOutTask = $knxProc.StandardOutput.ReadToEndAsync()
    $knxErrTask = $knxProc.StandardError.ReadToEndAsync()
    $knxProc.WaitForExit()
    Write-Output "$knxUnit`: exit $($knxProc.ExitCode)"
    if ($knxProc.ExitCode -ne 0) {
        ++$knxErrors
        Write-Output $knxOutTask.Result
        Write-Output $knxErrTask.Result
    }
    $knxProc.Dispose()
}
Write-Output "Checked $($knxUnits.Count) units. Syntax errors: $knxErrors"
exit $knxErrors
