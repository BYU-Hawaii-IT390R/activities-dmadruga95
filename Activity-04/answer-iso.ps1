<#
.SYNOPSIS
Builds a minimal ISO (answer.iso) containing Autounattend.xml for hands-free installations.

.DESCRIPTION
Uses oscdimg.exe to create answer.iso from Autounattend.xml.
#>

$xmlPath = '.\Autounattend.xml'
$isoPath = 'C:\ISO Folder\answer.iso'

# Verify Autounattend.xml exists
if (-not (Test-Path $xmlPath)) {
    Write-Error "Autounattend.xml not found at $xmlPath."
    exit 1
}

# Run oscdimg to create ISO
oscdimg -n -m -o -u2 -lANSWER $xmlPath $isoPath

if (Test-Path $isoPath) {
    Write-Host "answer.iso created successfully at $isoPath"
} else {
    Write-Error "Failed to create answer.iso"
}
