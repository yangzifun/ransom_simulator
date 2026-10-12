// ransom_simulator_linux_wallpaper.go
// 纯 Go 实现的勒索提示壁纸生成（仅使用标准库，无外部依赖）
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
)

const (
	wallpaperWidth  = 1920
	wallpaperHeight = 1080
)

// font5x7 内置 5x7 点阵字体（大写字母、数字与常用符号）
var font5x7 = map[rune][7]string{
	' ': {".....", ".....", ".....", ".....", ".....", ".....", "....."},
	'!': {"..X..", "..X..", "..X..", "..X..", "..X..", ".....", "..X.."},
	'-': {".....", ".....", ".....", "XXXXX", ".....", ".....", "....."},
	'.': {".....", ".....", ".....", ".....", ".....", ".XX..", ".XX.."},
	'/': {"....X", "....X", "...X.", "..X..", ".X...", "X....", "X...."},
	':': {".....", ".XX..", ".XX..", ".....", ".XX..", ".XX..", "....."},
	'?': {".XXX.", "X...X", "....X", "...X.", "..X..", ".....", "..X.."},
	'0': {".XXX.", "X...X", "X..XX", "X.X.X", "XX..X", "X...X", ".XXX."},
	'1': {"..X..", ".XX..", "..X..", "..X..", "..X..", "..X..", ".XXX."},
	'2': {".XXX.", "X...X", "....X", "...X.", "..X..", ".X...", "XXXXX"},
	'3': {"XXXXX", "...X.", "..X..", "...X.", "....X", "X...X", ".XXX."},
	'4': {"...X.", "..XX.", ".X.X.", "X..X.", "XXXXX", "...X.", "...X."},
	'5': {"XXXXX", "X....", "XXXX.", "....X", "....X", "X...X", ".XXX."},
	'6': {"..XX.", ".X...", "X....", "XXXX.", "X...X", "X...X", ".XXX."},
	'7': {"XXXXX", "....X", "...X.", "..X..", ".X...", ".X...", ".X..."},
	'8': {".XXX.", "X...X", "X...X", ".XXX.", "X...X", "X...X", ".XXX."},
	'9': {".XXX.", "X...X", "X...X", ".XXXX", "....X", "...X.", ".XX.."},
	'A': {".XXX.", "X...X", "X...X", "XXXXX", "X...X", "X...X", "X...X"},
	'B': {"XXXX.", "X...X", "X...X", "XXXX.", "X...X", "X...X", "XXXX."},
	'C': {".XXX.", "X...X", "X....", "X....", "X....", "X...X", ".XXX."},
	'D': {"XXXX.", "X...X", "X...X", "X...X", "X...X", "X...X", "XXXX."},
	'E': {"XXXXX", "X....", "X....", "XXXX.", "X....", "X....", "XXXXX"},
	'F': {"XXXXX", "X....", "X....", "XXXX.", "X....", "X....", "X...."},
	'G': {".XXX.", "X...X", "X....", "X.XXX", "X...X", "X...X", ".XXXX"},
	'H': {"X...X", "X...X", "X...X", "XXXXX", "X...X", "X...X", "X...X"},
	'I': {"XXXXX", "..X..", "..X..", "..X..", "..X..", "..X..", "XXXXX"},
	'J': {"..XXX", "...X.", "...X.", "...X.", "...X.", "X..X.", ".XX.."},
	'K': {"X...X", "X..X.", "X.X..", "XX...", "X.X..", "X..X.", "X...X"},
	'L': {"X....", "X....", "X....", "X....", "X....", "X....", "XXXXX"},
	'M': {"X...X", "XX.XX", "X.X.X", "X.X.X", "X...X", "X...X", "X...X"},
	'N': {"X...X", "XX..X", "X.X.X", "X..XX", "X...X", "X...X", "X...X"},
	'O': {".XXX.", "X...X", "X...X", "X...X", "X...X", "X...X", ".XXX."},
	'P': {"XXXX.", "X...X", "X...X", "XXXX.", "X....", "X....", "X...."},
	'Q': {".XXX.", "X...X", "X...X", "X...X", "X.X.X", "X..X.", ".XX.X"},
	'R': {"XXXX.", "X...X", "X...X", "XXXX.", "X.X..", "X..X.", "X...X"},
	'S': {".XXXX", "X....", "X....", ".XXX.", "....X", "....X", "XXXX."},
	'T': {"XXXXX", "..X..", "..X..", "..X..", "..X..", "..X..", "..X.."},
	'U': {"X...X", "X...X", "X...X", "X...X", "X...X", "X...X", ".XXX."},
	'V': {"X...X", "X...X", "X...X", "X...X", "X...X", ".X.X.", "..X.."},
	'W': {"X...X", "X...X", "X...X", "X.X.X", "X.X.X", "XX.XX", "X...X"},
	'X': {"X...X", "X...X", ".X.X.", "..X..", ".X.X.", "X...X", "X...X"},
	'Y': {"X...X", "X...X", ".X.X.", "..X..", "..X..", "..X..", "..X.."},
	'Z': {"XXXXX", "....X", "...X.", "..X..", ".X...", "X....", "XXXXX"},
}

// fillRect 在画布上填充矩形（带边界裁剪）
func fillRect(img *image.RGBA, x, y, w, h int, col color.RGBA) {
	for i := x; i < x+w; i++ {
		if i < 0 || i >= wallpaperWidth {
			continue
		}
		for j := y; j < y+h; j++ {
			if j < 0 || j >= wallpaperHeight {
				continue
			}
			img.SetRGBA(i, j, col)
		}
	}
}

// drawTextAt 以点阵字体在 (x,y) 处绘制文本，返回绘制结束后的 x 坐标
func drawTextAt(img *image.RGBA, text string, x, y, scale int, col color.RGBA) int {
	cx := x
	for _, ch := range text {
		glyph, ok := font5x7[ch]
		if !ok {
			glyph = font5x7['?']
		}
		for row := 0; row < 7; row++ {
			for col5 := 0; col5 < 5; col5++ {
				if glyph[row][col5] == 'X' {
					fillRect(img, cx+col5*scale, y+row*scale, scale, scale, col)
				}
			}
		}
		cx += 6 * scale
	}
	return cx
}

// textPixelWidth 计算文本按指定缩放后的像素宽度
func textPixelWidth(text string, scale int) int {
	n := len([]rune(text))
	if n == 0 {
		return 0
	}
	return n*6*scale - scale
}

// drawCentered 居中绘制文本
func drawCentered(img *image.RGBA, text string, y, scale int, col color.RGBA) {
	x := (wallpaperWidth - textPixelWidth(text, scale)) / 2
	drawTextAt(img, text, x, y, scale, col)
}

// drawBandCentered 居中绘制带底色色块的文本（模仿勒索壁纸的高亮标题）
func drawBandCentered(img *image.RGBA, text string, y, scale, pad int, fg, bg color.RGBA) {
	w := textPixelWidth(text, scale)
	x := (wallpaperWidth - w) / 2
	fillRect(img, x-pad, y-pad/2, w+2*pad, 7*scale+pad, bg)
	drawTextAt(img, text, x, y, scale, fg)
}

// generateRansomWallpaper 生成勒索提示壁纸 PNG（纯标准库实现，无外部依赖）
func generateRansomWallpaper(path, uuid string) error {
	img := image.NewRGBA(image.Rect(0, 0, wallpaperWidth, wallpaperHeight))

	bg := color.RGBA{0x0F, 0x0F, 0x0F, 0xFF}
	red := color.RGBA{0xE0, 0x1E, 0x1E, 0xFF}
	white := color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	gray := color.RGBA{0xB0, 0xB0, 0xB0, 0xFF}

	fillRect(img, 0, 0, wallpaperWidth, wallpaperHeight, bg)

	drawCentered(img, "RANSOM SIM 3.6", 70, 5, red)
	drawBandCentered(img, "ALL YOUR FILES ARE ENCRYPTED !", 230, 6, 26, white, red)
	drawCentered(img, "YOUR IMPORTANT FILES HAVE BEEN ENCRYPTED", 400, 3, white)
	drawCentered(img, "THIS IS A CONTROLLED SECURITY TRAINING SIMULATION", 470, 2, gray)
	drawCentered(img, "FOR RECOVERY SEE THE NOTE FILE IN EVERY ENCRYPTED FOLDER", 515, 2, gray)
	drawCentered(img, "GET THE RECOVERY TOOL AND PRIVATE KEY:", 610, 2, white)
	drawCentered(img, "HTTPS://ENCRYPT.YANGZIFUN.ORG", 660, 3, white)
	drawCentered(img, "YOUR PERSONAL ID: "+strings.ToUpper(uuid), 740, 2, red)
	drawCentered(img, "THIS PROGRAM DOES NOT DELETE ANY SOURCE FILE", 900, 2, gray)
	drawBandCentered(img, "CONTROLLED SIMULATION - MIT LICENSE - DEFENSE RESEARCH ONLY", 960, 2, 16, white, red)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建壁纸文件失败: %w", err)
	}
	defer f.Close()

	if err := png.Encode(f, img); err != nil {
		return fmt.Errorf("编码壁纸 PNG 失败: %w", err)
	}
	return nil
}
