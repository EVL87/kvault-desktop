$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$assetsDir = Join-Path $PSScriptRoot '..\assets'
if (-not (Test-Path $assetsDir)) {
    New-Item -ItemType Directory -Path $assetsDir | Out-Null
}

function New-KVaultBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([System.Drawing.Color]::Transparent)

    $pad = [int]([Math]::Max(1, [Math]::Round($size * 0.06)))
    $rectSize = $size - ($pad * 2)

    # Fondo cuadrado técnico oscuro (#14181F) con borde metálico azul acero (#3B73B9)
    $bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 20, 24, 31))
    $innerBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 28, 35, 45))
    $borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 59, 115, 185), [Math]::Max(1.5, $size * 0.055))
    $accentPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 62, 166, 98), [Math]::Max(1.0, $size * 0.035))

    $g.FillRectangle($bgBrush, $pad, $pad, $rectSize, $rectSize)

    $innerPad = [int]([Math]::Round($size * 0.16))
    $innerSize = $size - ($innerPad * 2)
    $g.FillRectangle($innerBrush, $innerPad, $innerPad, $innerSize, $innerSize)
    $g.DrawRectangle($borderPen, $pad, $pad, $rectSize, $rectSize)

    # Dibujar arco de candado / escudo en la parte superior central y ojo de cerradura
    $cx = $size / 2.0
    $cy = $size / 2.0

    # Shackle (arco superior del candado)
    $shackleW = $size * 0.30
    $shackleH = $size * 0.26
    $shackleX = $cx - ($shackleW / 2.0)
    $shackleY = $size * 0.20
    $shacklePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 138, 184, 240), [Math]::Max(1.5, $size * 0.065))
    $g.DrawArc($shacklePen, $shackleX, $shackleY, $shackleW, $shackleH, 180, 180)
    $g.DrawLine($shacklePen, $shackleX, $shackleY + ($shackleH / 2.0), $shackleX, $size * 0.44)
    $g.DrawLine($shacklePen, $shackleX + $shackleW, $shackleY + ($shackleH / 2.0), $shackleX + $shackleW, $size * 0.44)

    # Cuerpo del candado (#3B73B9)
    $bodyW = $size * 0.48
    $bodyH = $size * 0.38
    $bodyX = $cx - ($bodyW / 2.0)
    $bodyY = $size * 0.42
    $bodyBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 59, 115, 185))
    $bodyBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 138, 184, 240), [Math]::Max(1.0, $size * 0.025))
    $g.FillRectangle($bodyBrush, $bodyX, $bodyY, $bodyW, $bodyH)
    $g.DrawRectangle($bodyBorder, $bodyX, $bodyY, $bodyW, $bodyH)

    # Ojo de cerradura central (#14181F + punto verde #7CE09D)
    $khR = $size * 0.065
    $khBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 17, 20, 25))
    $g.FillEllipse($khBrush, ($cx - $khR), ($bodyY + $bodyH * 0.24), ($khR * 2), ($khR * 2))
    $slotW = [Math]::Max(2.0, $size * 0.055)
    $slotH = $bodyH * 0.36
    $g.FillRectangle($khBrush, ($cx - $slotW / 2.0), ($bodyY + $bodyH * 0.38), $slotW, $slotH)

    # Indicador LED de estado AEAD en esquina superior derecha
    $ledR = [Math]::Max(2.0, $size * 0.045)
    $ledBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 62, 166, 98))
    $g.FillEllipse($ledBrush, ($size - $pad - $ledR * 3.2), ($pad + $ledR * 1.2), ($ledR * 2), ($ledR * 2))

    $g.Dispose()
    return $bmp
}

# 1. Guardar PNG de 256x256
$pngPath = Join-Path $assetsDir 'icon.png'
$bmp256 = New-KVaultBitmap 256
$bmp256.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)

# 2. Construir archivo .ICO multi-resolución (256, 64, 48, 32, 16) con frames PNG embebidos (estándar Windows Vista/10/11)
$sizes = @(256, 64, 48, 32, 16)
$pngFrames = New-Object System.Collections.Generic.List[byte[]]

foreach ($s in $sizes) {
    $b = New-KVaultBitmap $s
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngFrames.Add($ms.ToArray())
    $ms.Dispose()
    $b.Dispose()
}
$bmp256.Dispose()

$icoPath = Join-Path $assetsDir 'icon.ico'
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)

# ICONDIR Header (6 bytes)
$bw.Write([uint16]0) # Reserved
$bw.Write([uint16]1) # Type: 1 = ICO
$bw.Write([uint16]$sizes.Count) # Count

$offset = 6 + (16 * $sizes.Count)
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $data = $pngFrames[$i]
    $dimByte = if ($s -ge 256) { [byte]0 } else { [byte]$s }

    $bw.Write([byte]$dimByte)   # Width
    $bw.Write([byte]$dimByte)   # Height
    $bw.Write([byte]0)          # ColorCount
    $bw.Write([byte]0)          # Reserved
    $bw.Write([uint16]1)        # Planes
    $bw.Write([uint16]32)       # BitCount
    $bw.Write([uint32]$data.Length) # BytesInRes
    $bw.Write([uint32]$offset)  # ImageOffset

    $offset += $data.Length
}

for ($i = 0; $i -lt $sizes.Count; $i++) {
    $bw.Write($pngFrames[$i])
}

$bw.Flush()
$bw.Dispose()
$fs.Dispose()

Write-Output "OK|$icoPath|$pngPath"
