#include "MinePicker.h"

#include <windowsx.h>
#include <algorithm>
#include <cstdint>
#include <mutex>
#include <new>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kWindowClassName[] = L"MinePickerWindowClass";

constexpr int kMinRows = 9;
constexpr int kMaxRows = 24;
constexpr int kMinColumns = 9;
constexpr int kMaxColumns = 30;
constexpr int kMaxMinePercent = 93;

constexpr int kCellSize = 26;
constexpr int kToolbarHeight = 72;
constexpr int kMargin = 10;
constexpr int kButtonWidth = 64;
constexpr int kButtonHeight = 30;
constexpr int kButtonGap = 6;
constexpr int kButtonY = 34;
constexpr int kButtonCount = 4;

constexpr int kIdRandom = 1001;
constexpr int kIdConfirm = 1002;
constexpr int kIdCancel = 1003;
constexpr int kIdClear = 1004;

constexpr wchar_t kWindowTitle[] = L"\u5730\u96f7\u4f4d\u7f6e\u9009\u62e9\u5668";
constexpr wchar_t kRandomText[] = L"\u968f\u673a\u8865\u5168";
constexpr wchar_t kClearText[] = L"\u4e00\u952e\u6e05\u9664";
constexpr wchar_t kConfirmText[] = L"\u786e\u8ba4";
constexpr wchar_t kCancelText[] = L"\u53d6\u6d88";
constexpr wchar_t kSelectedPrefix[] = L"\u5df2\u9009\u62e9 ";
constexpr wchar_t kMineSuffix[] = L" \u4e2a\u96f7";

HINSTANCE g_instance = nullptr;
std::once_flag g_registerOnce;
ATOM g_windowClassAtom = 0;

struct PickerState {
    int rows = 0;
    int columns = 0;
    int mineCount = 0;
    int selectedCount = 0;

    bool confirmed = false;
    bool done = false;

    HWND window = nullptr;
    HWND randomButton = nullptr;
    HWND clearButton = nullptr;
    HWND confirmButton = nullptr;
    HWND cancelButton = nullptr;

    std::vector<std::uint8_t> selected;
};

LRESULT CALLBACK PickerWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

int ToInt(LONG value) noexcept {
    return static_cast<int>(value);
}

int MaxInt(int a, int b) noexcept {
    return a > b ? a : b;
}

HMENU ControlId(int id) noexcept {
    return reinterpret_cast<HMENU>(static_cast<INT_PTR>(id));
}

PickerState* GetState(HWND hwnd) noexcept {
    return reinterpret_cast<PickerState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void RegisterPickerWindowClass() {
    std::call_once(g_registerOnce, []() {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = 0;
        wc.lpfnWndProc = PickerWindowProc;
        wc.hInstance = g_instance;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
        wc.hIconSm = wc.hIcon;
        wc.hbrBackground = nullptr;
        wc.lpszClassName = kWindowClassName;

        g_windowClassAtom = RegisterClassExW(&wc);
    });
}

RECT GetStatusRect(const PickerState& state) noexcept {
    RECT client{};
    GetClientRect(state.window, &client);

    return RECT{
        kMargin,
        4,
        ToInt(client.right) - kMargin,
        30
    };
}

RECT GetCellRect(int row, int column) noexcept {
    return RECT{
        column * kCellSize,
        kToolbarHeight + row * kCellSize,
        (column + 1) * kCellSize,
        kToolbarHeight + (row + 1) * kCellSize
    };
}

void LayoutControls(PickerState& state) {
    RECT client{};
    GetClientRect(state.window, &client);

    const int clientWidth = ToInt(client.right - client.left);
    const int totalWidth = kButtonWidth * kButtonCount + kButtonGap * (kButtonCount - 1);
    const int startX = MaxInt(0, (clientWidth - totalWidth) / 2);

    MoveWindow(state.randomButton, startX, kButtonY, kButtonWidth, kButtonHeight, TRUE);
    MoveWindow(
        state.clearButton,
        startX + kButtonWidth + kButtonGap,
        kButtonY,
        kButtonWidth,
        kButtonHeight,
        TRUE);
    MoveWindow(
        state.confirmButton,
        startX + (kButtonWidth + kButtonGap) * 2,
        kButtonY,
        kButtonWidth,
        kButtonHeight,
        TRUE);
    MoveWindow(
        state.cancelButton,
        startX + (kButtonWidth + kButtonGap) * 3,
        kButtonY,
        kButtonWidth,
        kButtonHeight,
        TRUE);
}

void UpdateConfirmButton(PickerState& state) {
    const BOOL shouldEnable = state.selectedCount == state.mineCount ? TRUE : FALSE;

    if (IsWindowEnabled(state.confirmButton) != shouldEnable) {
        EnableWindow(state.confirmButton, shouldEnable);
    }
}

void DrawStatus(HDC dc, const PickerState& state) {
    RECT rect = GetStatusRect(state);

    FillRect(
        dc,
        &rect,
        reinterpret_cast<HBRUSH>(static_cast<INT_PTR>(COLOR_WINDOW + 1)));

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
    SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));

    const std::wstring text =
        std::wstring(kSelectedPrefix) +
        std::to_wstring(state.selectedCount) +
        L" / " +
        std::to_wstring(state.mineCount) +
        kMineSuffix;

    DrawTextW(
        dc,
        text.c_str(),
        -1,
        &rect,
        DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

void DrawCell(HDC dc, const PickerState& state, int row, int column) {
    if (row < 0 || row >= state.rows || column < 0 || column >= state.columns) return;

    const int index = row * state.columns + column;
    const bool isMine = state.selected[static_cast<std::size_t>(index)] != 0U;

    RECT cell = GetCellRect(row, column);

    HBRUSH cellBrush = CreateSolidBrush(
        isMine ? RGB(220, 72, 72) : RGB(242, 242, 242));

    if (cellBrush != nullptr) {
        FillRect(dc, &cell, cellBrush);
        DeleteObject(cellBrush);
    }

    HBRUSH borderBrush = CreateSolidBrush(RGB(125, 125, 125));

    if (borderBrush != nullptr) {
        FrameRect(dc, &cell, borderBrush);
        DeleteObject(borderBrush);
    }

    if (isMine) {
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(255, 255, 255));
        SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));

        DrawTextW(
            dc,
            L"X",
            -1,
            &cell,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
    }
}

void PaintSingleCellNow(PickerState& state, int row, int column) {
    if (state.window == nullptr || !IsWindow(state.window)) return;

    HDC dc = GetDC(state.window);
    if (dc == nullptr) return;

    const RECT cell = GetCellRect(row, column);
    const int saved = SaveDC(dc);

    IntersectClipRect(dc, cell.left, cell.top, cell.right, cell.bottom);
    DrawCell(dc, state, row, column);

    if (saved != 0) RestoreDC(dc, saved);

    ReleaseDC(state.window, dc);
}

void PaintStatusNow(PickerState& state) {
    if (state.window == nullptr || !IsWindow(state.window)) return;

    HDC dc = GetDC(state.window);
    if (dc == nullptr) return;

    const RECT rect = GetStatusRect(state);
    const int saved = SaveDC(dc);

    IntersectClipRect(dc, rect.left, rect.top, rect.right, rect.bottom);
    DrawStatus(dc, state);

    if (saved != 0) RestoreDC(dc, saved);

    ReleaseDC(state.window, dc);
}

void PaintChangedCellsNow(PickerState& state, const std::vector<int>& changedIndices) {
    if (changedIndices.empty()) return;
    if (state.window == nullptr || !IsWindow(state.window)) return;

    HDC dc = GetDC(state.window);
    if (dc == nullptr) return;

    for (int index : changedIndices) {
        const int row = index / state.columns;
        const int column = index % state.columns;
        DrawCell(dc, state, row, column);
    }

    ReleaseDC(state.window, dc);
}

void RefreshAfterCellChange(PickerState& state, int row, int column) {
    UpdateConfirmButton(state);
    PaintSingleCellNow(state, row, column);
    PaintStatusNow(state);
}

void AddRandomMines(PickerState& state) {
    const int remaining = state.mineCount - state.selectedCount;
    if (remaining <= 0) return;

    std::vector<int> available;
    available.reserve(state.selected.size() - static_cast<std::size_t>(state.selectedCount));

    for (int index = 0; index < static_cast<int>(state.selected.size()); ++index) {
        if (state.selected[static_cast<std::size_t>(index)] == 0U) {
            available.push_back(index);
        }
    }

    std::random_device rd;
    std::mt19937 generator(rd());

    std::shuffle(available.begin(), available.end(), generator);

    std::vector<int> changedIndices;
    changedIndices.reserve(static_cast<std::size_t>(remaining));

    for (int i = 0; i < remaining; ++i) {
        const int index = available[static_cast<std::size_t>(i)];

        state.selected[static_cast<std::size_t>(index)] = 1U;
        changedIndices.push_back(index);
    }

    state.selectedCount += remaining;

    UpdateConfirmButton(state);
    PaintChangedCellsNow(state, changedIndices);
    PaintStatusNow(state);
}

void ClearSelectedMines(PickerState& state) {
    if (state.selectedCount <= 0) return;

    std::vector<int> changedIndices;
    changedIndices.reserve(static_cast<std::size_t>(state.selectedCount));

    for (int index = 0; index < static_cast<int>(state.selected.size()); ++index) {
        std::uint8_t& value = state.selected[static_cast<std::size_t>(index)];

        if (value != 0U) {
            value = 0U;
            changedIndices.push_back(index);
        }
    }

    state.selectedCount = 0;

    UpdateConfirmButton(state);
    PaintChangedCellsNow(state, changedIndices);
    PaintStatusNow(state);
}

void HandleGridClick(PickerState& state, int mouseX, int mouseY) {
    if (mouseX < 0 || mouseY < kToolbarHeight) return;

    const int gridY = mouseY - kToolbarHeight;
    const int column = mouseX / kCellSize;
    const int row = gridY / kCellSize;

    if (row < 0 || row >= state.rows || column < 0 || column >= state.columns) return;

    const int index = row * state.columns + column;
    std::uint8_t& value = state.selected[static_cast<std::size_t>(index)];

    if (value != 0U) {
        value = 0U;
        --state.selectedCount;
    } else {
        if (state.selectedCount >= state.mineCount) {
            MessageBeep(MB_ICONWARNING);
            return;
        }

        value = 1U;
        ++state.selectedCount;
    }

    RefreshAfterCellChange(state, row, column);
}

void PaintPicker(PickerState& state) {
    PAINTSTRUCT paint{};
    HDC dc = BeginPaint(state.window, &paint);

    if (dc == nullptr) return;

    FillRect(
        dc,
        &paint.rcPaint,
        reinterpret_cast<HBRUSH>(static_cast<INT_PTR>(COLOR_WINDOW + 1)));

    const RECT statusRect = GetStatusRect(state);
    RECT intersection{};

    if (IntersectRect(&intersection, &paint.rcPaint, &statusRect)) {
        DrawStatus(dc, state);
    }

    const RECT boardRect{
        0,
        kToolbarHeight,
        state.columns * kCellSize,
        kToolbarHeight + state.rows * kCellSize
    };

    if (IntersectRect(&intersection, &paint.rcPaint, &boardRect)) {
        int firstColumn = paint.rcPaint.left / kCellSize;
        int lastColumn = (paint.rcPaint.right - 1) / kCellSize;

        int firstRow = (paint.rcPaint.top - kToolbarHeight) / kCellSize;
        int lastRow = (paint.rcPaint.bottom - 1 - kToolbarHeight) / kCellSize;

        firstColumn = std::max(0, firstColumn);
        firstRow = std::max(0, firstRow);

        lastColumn = std::min(state.columns - 1, lastColumn);
        lastRow = std::min(state.rows - 1, lastRow);

        if (firstColumn <= lastColumn && firstRow <= lastRow) {
            for (int row = firstRow; row <= lastRow; ++row) {
                for (int column = firstColumn; column <= lastColumn; ++column) {
                    RECT cell = GetCellRect(row, column);

                    if (RectVisible(dc, &cell)) {
                        DrawCell(dc, state, row, column);
                    }
                }
            }
        }
    }

    EndPaint(state.window, &paint);
}

LRESULT CALLBACK PickerWindowProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam) {

    PickerState* state = GetState(hwnd);

    if (message == WM_NCCREATE) {
        CREATESTRUCTW* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = static_cast<PickerState*>(create->lpCreateParams);

        if (state == nullptr) return FALSE;

        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        state->window = hwnd;
    }

    switch (message) {
        case WM_CREATE: {
            if (state == nullptr) return -1;

            state->randomButton = CreateWindowExW(
                0,
                L"BUTTON",
                kRandomText,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd,
                ControlId(kIdRandom),
                g_instance,
                nullptr);

            state->clearButton = CreateWindowExW(
                0,
                L"BUTTON",
                kClearText,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd,
                ControlId(kIdClear),
                g_instance,
                nullptr);

            state->confirmButton = CreateWindowExW(
                0,
                L"BUTTON",
                kConfirmText,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                0, 0, 0, 0,
                hwnd,
                ControlId(kIdConfirm),
                g_instance,
                nullptr);

            state->cancelButton = CreateWindowExW(
                0,
                L"BUTTON",
                kCancelText,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 0, 0,
                hwnd,
                ControlId(kIdCancel),
                g_instance,
                nullptr);

            if (state->randomButton == nullptr ||
                state->clearButton == nullptr ||
                state->confirmButton == nullptr ||
                state->cancelButton == nullptr) {
                return -1;
            }

            HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

            SendMessageW(state->randomButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SendMessageW(state->clearButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SendMessageW(state->confirmButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SendMessageW(state->cancelButton, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);

            LayoutControls(*state);
            UpdateConfirmButton(*state);

            return 0;
        }

        case WM_COMMAND:
            if (state == nullptr) break;

            switch (static_cast<int>(LOWORD(wParam))) {
                case kIdRandom:
                    AddRandomMines(*state);
                    return 0;

                case kIdClear:
                    ClearSelectedMines(*state);
                    return 0;

                case kIdConfirm:
                    if (state->selectedCount == state->mineCount) {
                        state->confirmed = true;
                        DestroyWindow(hwnd);
                    }
                    return 0;

                case kIdCancel:
                    DestroyWindow(hwnd);
                    return 0;

                default:
                    break;
            }
            break;

        case WM_LBUTTONDOWN:
            if (state != nullptr) {
                HandleGridClick(*state, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            }
            return 0;

        case WM_PAINT:
            if (state != nullptr) {
                PaintPicker(*state);
                return 0;
            }
            break;

        case WM_ERASEBKGND:
            return 1;

        case WM_KEYDOWN:
            if (state != nullptr && wParam == VK_ESCAPE) {
                DestroyWindow(hwnd);
                return 0;
            }
            break;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_NCDESTROY:
            if (state != nullptr) {
                state->done = true;
                state->window = nullptr;
            }

            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return DefWindowProcW(hwnd, message, wParam, lParam);

        default:
            break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

bool ValidateArguments(int rows, int columns, int mineCount, int* outIndices) noexcept {
    if (rows < kMinRows || rows > kMaxRows) return false;
    if (columns < kMinColumns || columns > kMaxColumns) return false;
    if (mineCount < 0) return false;

    const long long totalCells =
        static_cast<long long>(rows) * static_cast<long long>(columns);

    if (static_cast<long long>(mineCount) * 100LL >
        totalCells * static_cast<long long>(kMaxMinePercent)) {
        return false;
    }

    if (mineCount > 0 && outIndices == nullptr) return false;

    return true;
}

HWND CreatePickerWindow(PickerState& state) {
    RECT workArea{};

    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0)) {
        workArea.left = 0;
        workArea.top = 0;
        workArea.right = GetSystemMetrics(SM_CXSCREEN);
        workArea.bottom = GetSystemMetrics(SM_CYSCREEN);
    }

    const int workWidth = ToInt(workArea.right - workArea.left);
    const int workHeight = ToInt(workArea.bottom - workArea.top);

    const int toolbarWidth =
        kButtonWidth * kButtonCount + kButtonGap * (kButtonCount - 1);

    const int boardWidth = state.columns * kCellSize;
    const int clientWidth = MaxInt(boardWidth, toolbarWidth + kMargin * 2);
    const int clientHeight = kToolbarHeight + state.rows * kCellSize;

    const DWORD style =
        WS_OVERLAPPED |
        WS_CAPTION |
        WS_SYSMENU |
        WS_MINIMIZEBOX |
        WS_CLIPCHILDREN;

    RECT windowRect{0, 0, clientWidth, clientHeight};

    AdjustWindowRectEx(&windowRect, style, FALSE, 0);

    const int windowWidth = ToInt(windowRect.right - windowRect.left);
    const int windowHeight = ToInt(windowRect.bottom - windowRect.top);

    const int x =
        ToInt(workArea.left) +
        MaxInt(0, (workWidth - windowWidth) / 2);

    const int y =
        ToInt(workArea.top) +
        MaxInt(0, (workHeight - windowHeight) / 2);

    return CreateWindowExW(
        0,
        kWindowClassName,
        kWindowTitle,
        style,
        x,
        y,
        windowWidth,
        windowHeight,
        nullptr,
        nullptr,
        g_instance,
        &state);
}

BOOL RunPickerBlocking(int rows, int columns, int mineCount, int* outIndices) {
    RegisterPickerWindowClass();

    if (g_windowClassAtom == 0) {
        WNDCLASSEXW existing{};
        existing.cbSize = sizeof(existing);

        if (!GetClassInfoExW(g_instance, kWindowClassName, &existing)) {
            return FALSE;
        }
    }

    PickerState state;

    state.rows = rows;
    state.columns = columns;
    state.mineCount = mineCount;

    state.selected.assign(
        static_cast<std::size_t>(rows) * static_cast<std::size_t>(columns),
        0U);

    HWND window = CreatePickerWindow(state);
    if (window == nullptr) return FALSE;

    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);

    bool receivedQuit = false;
    int quitCode = 0;
    MSG message{};

    while (!state.done) {
        const BOOL result = GetMessageW(&message, nullptr, 0, 0);

        if (result == -1) {
            if (IsWindow(window)) DestroyWindow(window);
            return FALSE;
        }

        if (result == 0) {
            receivedQuit = true;
            quitCode = static_cast<int>(message.wParam);

            if (IsWindow(window)) DestroyWindow(window);
            break;
        }

        if (IsWindow(window) && IsDialogMessageW(window, &message)) continue;

        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (receivedQuit) PostQuitMessage(quitCode);
    if (!state.confirmed) return FALSE;

    int outputPosition = 0;

    for (int index = 0; index < static_cast<int>(state.selected.size()); ++index) {
        if (state.selected[static_cast<std::size_t>(index)] != 0U) {
            outIndices[outputPosition++] = index;
        }
    }

    return TRUE;
}

}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = module;
        DisableThreadLibraryCalls(module);
    }

    return TRUE;
}

extern "C" MINEPICKER_API BOOL WINAPI SelectMinePositions(
    int rows,
    int columns,
    int mineCount,
    int* outIndices) {

    if (!ValidateArguments(rows, columns, mineCount, outIndices)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    try {
        return RunPickerBlocking(rows, columns, mineCount, outIndices);
    } catch (const std::bad_alloc&) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    } catch (...) {
        SetLastError(ERROR_UNHANDLED_EXCEPTION);
        return FALSE;
    }
}