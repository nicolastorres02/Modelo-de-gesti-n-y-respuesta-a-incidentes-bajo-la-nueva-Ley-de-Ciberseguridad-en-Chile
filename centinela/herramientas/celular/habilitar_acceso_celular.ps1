# Permite abrir el panel de Centinela desde un celular conectado al mismo Wi-Fi.
# VMware (red NAT VMnet8) reenvia el puerto 5000 de Windows hacia la VM, y el
# Firewall de Windows lo admite solo desde la red local. Requiere administrador.
param(
    [string]$Vm = "192.168.58.132",
    [int]$Puerto = 5000,
    [switch]$Quitar
)
$ErrorActionPreference = "Stop"
$conf = "C:\ProgramData\VMware\vmnetnat.conf"
$regla = "Centinela - panel desde celular (TCP $Puerto)"
$linea = "$Puerto = ${Vm}:$Puerto"

if (-not (Test-Path $conf)) { Write-Host "No se encontro $conf (VMware Workstation instalado?)" -ForegroundColor Red; exit 1 }
$lineas = [System.Collections.Generic.List[string]](Get-Content $conf)
$lineas.RemoveAll([Predicate[string]] { param($l) $l -match "^\s*$Puerto\s*=" }) | Out-Null

if ($Quitar) {
    Set-Content -Path $conf -Value $lineas -Encoding Ascii
    Remove-NetFirewallRule -DisplayName $regla -ErrorAction SilentlyContinue
    Restart-Service "VMware NAT Service"
    Write-Host "Acceso desde el celular desactivado." -ForegroundColor Green
    exit 0
}

Copy-Item $conf "$conf.respaldo-centinela" -Force
$i = $lineas.IndexOf("[incomingtcp]")
if ($i -lt 0) { $lineas.Add("[incomingtcp]"); $i = $lineas.Count - 1 }
$lineas.Insert($i + 1, $linea)
Set-Content -Path $conf -Value $lineas -Encoding Ascii
Write-Host "[1/3] VMware reenviara el puerto $Puerto de Windows hacia $Vm."
Restart-Service "VMware NAT Service"
Write-Host "[2/3] Servicio NAT de VMware reiniciado."

Remove-NetFirewallRule -DisplayName $regla -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $regla -Direction Inbound -Protocol TCP -LocalPort $Puerto `
    -RemoteAddress LocalSubnet -Action Allow -Profile Any | Out-Null
Write-Host "[3/3] Firewall de Windows: puerto $Puerto abierto solo para la red local."

$wifi = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.InterfaceAlias -notmatch "VMware|Loopback|vEthernet" -and $_.IPAddress -notlike "169.254*" } |
    Select-Object -First 1 -ExpandProperty IPAddress
Write-Host ""
Write-Host "Listo. IP de este PC en el Wi-Fi: $wifi" -ForegroundColor Green
Write-Host ""
Write-Host "Falta UN paso en victima-02 (para que el certificado incluya esa IP):"
Write-Host "   cd centinela"
Write-Host "   sudo bash instalar.sh --ip-extra $wifi"
Write-Host ""
Write-Host "Luego, en el iPhone (Safari):  https://${wifi}:$Puerto/certificado"
