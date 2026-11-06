# Crea el acceso directo "Centinela" en el escritorio de Windows.
#  1. Descarga el certificado de la autoridad local desde el panel y lo instala (usuario actual).
#  2. Crea un acceso directo que abre el panel como aplicación (ventana propia, sin barra del navegador).
param(
    [string]$Servidor = "192.168.58.132",
    [int]$Puerto = 5000
)
$ErrorActionPreference = "Stop"
$url = "https://${Servidor}:${Puerto}/"
$carpeta = Join-Path $env:LOCALAPPDATA "Centinela"
New-Item -ItemType Directory -Force -Path $carpeta | Out-Null

Write-Host ""
Write-Host "=== Centinela: instalacion del acceso directo ===" -ForegroundColor Cyan
Write-Host "Panel: $url"
Write-Host ""

# --- 1. Certificado ---------------------------------------------------------------------
Write-Host "[1/3] Descargando el certificado de la autoridad de Centinela..."
$crt = Join-Path $carpeta "centinela-ca.crt"
# -k solo para esta descarga: aun no confiamos en la autoridad (se verifica la huella abajo)
& curl.exe -k -s -f --connect-timeout 8 -o $crt "${url}certificado"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $crt)) {
    Write-Host ""
    Write-Host "No se pudo conectar con $url" -ForegroundColor Red
    Write-Host "Compruebe que la maquina de Centinela este encendida y que este equipo"
    Write-Host "este en la misma red. Tambien puede indicar otra IP:"
    Write-Host "   instalar_centinela.bat 192.168.58.132"
    exit 1
}
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($crt)
if ($cert.Subject -notmatch "Centinela") {
    Write-Host "El certificado recibido no es de Centinela ($($cert.Subject)). Se cancela." -ForegroundColor Red
    exit 1
}
Write-Host "      Emisor : $($cert.Subject)"
Write-Host "      Huella : $($cert.Thumbprint)"
Write-Host "      Vence  : $($cert.NotAfter.ToString('dd-MM-yyyy'))"

$almacen = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$almacen.Open("ReadWrite")
$ya = $almacen.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if ($ya) {
    Write-Host "[2/3] El certificado ya estaba instalado."
} else {
    Write-Host "[2/3] Instalando el certificado. Windows pedira confirmacion: compare la huella y pulse SI."
    try { $almacen.Add($cert) } catch {
        Write-Host "No se instalo el certificado (se cancelo la confirmacion)." -ForegroundColor Red
        exit 1
    }
}
$almacen.Close()

# --- 2. Acceso directo ------------------------------------------------------------------
Write-Host "[3/3] Creando el acceso directo en el escritorio..."
$ico = Join-Path $carpeta "centinela.ico"
Copy-Item -Force (Join-Path $PSScriptRoot "centinela.ico") $ico

$navegadores = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
$nav = $navegadores | Where-Object { Test-Path $_ } | Select-Object -First 1

$shell = New-Object -ComObject WScript.Shell
$destinos = @([Environment]::GetFolderPath("Desktop"),
              (Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs"))
foreach ($d in $destinos) {
    $lnk = $shell.CreateShortcut((Join-Path $d "Centinela.lnk"))
    if ($nav) {
        $lnk.TargetPath = $nav
        $lnk.Arguments = "--app=$url"
    } else {
        $lnk.TargetPath = $url          # sin Edge/Chrome: abre el navegador predeterminado
    }
    $lnk.IconLocation = "$ico,0"
    $lnk.Description = "Centinela - Notificacion de incidentes (Ley 21.663)"
    $lnk.Save()
}

Write-Host ""
Write-Host "Listo. En el escritorio y en el menu Inicio quedo el icono 'Centinela'." -ForegroundColor Green
if (-not $nav) { Write-Host "(No se encontro Edge ni Chrome: se abrira en el navegador predeterminado.)" }
Write-Host ""
$r = Read-Host "Abrir Centinela ahora? (S/N)"
if ($r -match "^[sS]") {
    if ($nav) { Start-Process $nav "--app=$url" } else { Start-Process $url }
}
