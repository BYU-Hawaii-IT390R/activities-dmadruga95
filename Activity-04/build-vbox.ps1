# PowerShell script to create a Windows 10 VM using VirtualBox

# Paths
$vmName     = "AutomatedWin10"
$isoFolder  = "C:\ISO Folder"
$winISO     = "$isoFolder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerISO  = "$isoFolder\answer.iso"
$vdiPath    = "$isoFolder\AutomatedWin10.vdi"

# VBoxManage location (adjust if VirtualBox is installed somewhere else)
$vboxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# Create VM
& "$vboxManage" createvm --name $vmName --register
& "$vboxManage" modifyvm $vmName --memory 4096 --cpus 2 --ostype "Windows10_64"

# Create virtual hard disk
& "$vboxManage" createmedium disk --filename $vdiPath --size 40000

# Add storage controllers
& "$vboxManage" storagectl $vmName --name "SATA Controller" --add sata --controller IntelAhci
& "$vboxManage" storageattach $vmName --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $vdiPath

& "$vboxManage" storagectl $vmName --name "IDE Controller" --add ide
& "$vboxManage" storageattach $vmName --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium $winISO
& "$vboxManage" storageattach $vmName --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium $answerISO

# Enable network
& "$vboxManage" modifyvm $vmName --nic1 nat

# Start VM
& "$vboxManage" startvm $vmName
