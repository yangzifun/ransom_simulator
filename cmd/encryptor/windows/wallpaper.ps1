param(
    [Parameter(Mandatory=$true)][string]$OutPath,
    [string]$Uuid = 'UNKNOWN',
    [string]$Ver = '3.6',
    [string]$Remove = 'false'
)

Add-Type -AssemblyName System.Drawing

# 是否删除源文件：决定壁纸是否显示“源文件已被删除”提示
$srcDeleted = ($Remove -eq 'true')
$verText = 'SIM ' + $Ver

$W = 1920
$H = 1080
$bmp = [System.Drawing.Bitmap]::new($W, $H)
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$g.Clear([System.Drawing.Color]::White)

$black = [System.Drawing.Brushes]::Black
$red   = [System.Drawing.Brushes]::Red
$white = [System.Drawing.Brushes]::White
$gray  = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(105,105,105))
$dark  = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(35,35,35))

$fBrand  = [System.Drawing.Font]::new('Arial', 54, [System.Drawing.FontStyle]::Bold)
$fLogo   = [System.Drawing.Font]::new('Arial', 72, [System.Drawing.FontStyle]::Bold)
$fHead   = [System.Drawing.Font]::new('Arial', 44, [System.Drawing.FontStyle]::Bold)
$fMedCjk = [System.Drawing.Font]::new('Microsoft YaHei UI', 20, [System.Drawing.FontStyle]::Bold)
$fMedEn  = [System.Drawing.Font]::new('Arial', 21, [System.Drawing.FontStyle]::Bold)
$fBody   = [System.Drawing.Font]::new('Microsoft YaHei UI', 15)
$fBodyEn = [System.Drawing.Font]::new('Arial', 15)

function Draw-Center {
    param($Text, $Font, $Brush, [single]$Y)
    $fmt = [System.Drawing.StringFormat]::new()
    $fmt.Alignment = [System.Drawing.StringAlignment]::Center
    $rect = [System.Drawing.RectangleF]::new(0, $Y, $W, 90)
    $g.DrawString($Text, $Font, $Brush, $rect, $fmt)
}

function Draw-Seg {
    param($Text, $Font, $Fg, [bool]$Highlight, [single]$X, [single]$Y)
    $sz = $g.MeasureString($Text, $Font)
    $pad = 14
    if ($Highlight) {
        $g.FillRectangle($red, [single]($X), [single]($Y - 10), [single]($sz.Width + $pad), [single]($sz.Height + 4))
        $g.DrawString($Text, $Font, $Fg, [single]($X + $pad/2), [single]$Y)
    } else {
        $g.DrawString($Text, $Font, $Fg, [single]$X, [single]$Y)
    }
    return [single]($X + $sz.Width + $pad + 8)
}

function Draw-BandCenter {
    param($Text, $Font, $Brush, [single]$Y)
    $sz = $g.MeasureString($Text, $Font)
    $x = [single](($W - $sz.Width) / 2)
    $g.FillRectangle($red, [single]($x - 16), [single]($Y - 4), [single]($sz.Width + 32), [single]($sz.Height + 4))
    $g.DrawString($Text, $Font, $Brush, $x, [single]$Y)
}

$g.FillEllipse($red, 190, 46, 118, 118)
$g.DrawString('R', $fLogo, $white, 228, 50)
$bx = 340
$sz = $g.MeasureString('RANSOM', $fBrand)
$g.DrawString('RANSOM', $fBrand, $black, [single]$bx, [single]72)
$bx = $bx + $sz.Width + 8
$sz2 = $g.MeasureString($verText, $fBrand)
$g.FillRectangle($red, [single]$bx, 62, [single]($sz2.Width + 22), [single]($sz2.Height + 2))
$g.DrawString($verText, $fBrand, $white, [single]($bx + 11), [single]72)

$hy = 300
$segs = @(@('ALL YOUR',$false), @('IMPORTANT FILES',$true), @('ARE',$false), @('STOLEN AND ENCRYPTED',$true), @('!',$false))
$fHeadSize = 44.0
$fHead = [System.Drawing.Font]::new('Arial', [single]$fHeadSize, [System.Drawing.FontStyle]::Bold)
$total = 0
foreach ($s in $segs) { $total = $total + $g.MeasureString($s[0], $fHead).Width + 22 }
while ($total -gt ($W - 120) -and $fHeadSize -gt 20) {
    $fHeadSize = $fHeadSize - 2
    $fHead = [System.Drawing.Font]::new('Arial', [single]$fHeadSize, [System.Drawing.FontStyle]::Bold)
    $total = 0
    foreach ($s in $segs) { $total = $total + $g.MeasureString($s[0], $fHead).Width + 22 }
}
$cx = [single](($W - $total) / 2)
foreach ($s in $segs) {
    if ($s[1]) { $fg = $white } else { $fg = $black }
    $cx = Draw-Seg -Text $s[0] -Font $fHead -Fg $fg -Highlight $s[1] -X $cx -Y $hy
}

Draw-Center '您的文件已被加密（本页为安全培训模拟演练）' $fMedCjk $dark 460
Draw-Center 'for more information see' $fBodyEn $gray 505
Draw-Center '!!!_如何解密你的文件_!!!.txt' $fMedEn $red 540
Draw-Center 'that is located in every encrypted folder.' $fBodyEn $gray 580
Draw-Center '获取恢复工具与解密私钥 / get the recovery tool and private key:' $fMedCjk $dark 650
Draw-Center 'https://encrypt.yangzifun.org/' $fMedEn $black 692
Draw-Center ('您的唯一个人ID (UUID): ' + $Uuid) $fBodyEn $dark 734

if ($srcDeleted) {
    Draw-BandCenter '原始文件已被删除 / SOURCE FILES DELETED' $fMedEn $white 778
}

Draw-Center '我们的系统获取了您网络中的文件，并对其进行了加密处理。' $fBody $gray 815
Draw-Center '在真实攻击中，若没有攻击者持有的私钥，这些文件将无法恢复。' $fBody $gray 848
if ($srcDeleted) {
    Draw-Center '您的源文件已被删除，仅保留加密后的文件；请通过上方链接获取私钥及恢复程序。' $fBody $red 881
} else {
    Draw-Center '本程序不会删除任何源文件；可随时通过上方链接获取私钥及恢复程序。' $fBody $gray 881
}

$t = '这是一次受控的安全培训模拟演练 —— 本项目遵循 MIT 许可证，仅用于防御研究'
$sz = $g.MeasureString($t, $fBody)
$x = [single](($W - $sz.Width) / 2)
$g.FillRectangle($red, [single]($x - 18), 960, [single]($sz.Width + 36), [single]($sz.Height + 2))
$g.DrawString($t, $fBody, $white, $x, 962)

$dir = Split-Path -Parent $OutPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
Write-Output 'WALLPAPER_OK'