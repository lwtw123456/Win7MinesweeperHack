#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>

namespace {

constexpr wchar_t kClickMessageName[] =
    L"Win7MinesweeperHack.InternalClick.v2";
constexpr wchar_t kReadyPropertyName[] =
    L"Win7MinesweeperHack.WndProcHookReady.v2";
constexpr wchar_t kOldWndProcPropertyName[] =
    L"Win7MinesweeperHack.OldWndProc.v2";
constexpr wchar_t kLastSequencePropertyName[] =
    L"Win7MinesweeperHack.LastSequence.v2";
constexpr wchar_t kLastResultPropertyName[] =
    L"Win7MinesweeperHack.LastResult.v2";

constexpr std::uintptr_t kClickContextRva = 0x000AAA38;
constexpr std::uintptr_t kClickFunctionRva = 0x00031854;

enum class ClickResult : ULONG_PTR {
    None = 0,
    Success = 1,
    Busy = 2,
    InvalidCellPointer = 3,
    GameNotRunning = 4,
    InvalidGamePointer = 5,
    InternalException = 6,
};

HMODULE g_module = nullptr;
UINT g_click_message = 0;
volatile LONG g_busy = 0;

bool IsReadableAddress(const void* address, SIZE_T size) noexcept {
    if (address == nullptr || size == 0) {
        return false;
    }

    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(address, &info, sizeof(info)) == 0) {
        return false;
    }

    if (info.State != MEM_COMMIT) {
        return false;
    }

    if ((info.Protect & PAGE_GUARD) != 0 ||
        (info.Protect & 0xFF) == PAGE_NOACCESS) {
        return false;
    }

    const auto start = reinterpret_cast<std::uintptr_t>(address);
    const auto region_start =
        reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    const auto region_end = region_start + info.RegionSize;

    return start >= region_start &&
           start + size >= start &&
           start + size <= region_end;
}

void PublishResult(
    HWND hwnd,
    ULONG_PTR sequence,
    ClickResult result
) noexcept {
    SetPropW(
        hwnd,
        kLastResultPropertyName,
        reinterpret_cast<HANDLE>(
            static_cast<ULONG_PTR>(result)
        )
    );

    MemoryBarrier();

    SetPropW(
        hwnd,
        kLastSequencePropertyName,
        reinterpret_cast<HANDLE>(sequence)
    );
}

ClickResult ExecuteClick(void* cell_pointer) noexcept {
#if !defined(_M_X64)
    (void)cell_pointer;
    return ClickResult::InternalException;
#else
    __try {
        if (!IsReadableAddress(
                cell_pointer,
                sizeof(std::uintptr_t))) {
            return ClickResult::InvalidCellPointer;
        }

        const auto module_base =
            reinterpret_cast<std::uintptr_t>(
                GetModuleHandleW(nullptr)
            );

        if (module_base == 0) {
            return ClickResult::InvalidGamePointer;
        }

        const auto context_address =
            module_base + kClickContextRva;

        if (!IsReadableAddress(
                reinterpret_cast<void*>(context_address),
                sizeof(std::uintptr_t))) {
            return ClickResult::InvalidGamePointer;
        }

        const auto game_root =
            *reinterpret_cast<std::uintptr_t*>(
                context_address
            );

        if (game_root == 0 ||
            !IsReadableAddress(
                reinterpret_cast<void*>(game_root + 0x29),
                sizeof(std::uint8_t)) ||
            !IsReadableAddress(
                reinterpret_cast<void*>(game_root + 0x38),
                sizeof(std::int32_t))) {
            return ClickResult::InvalidGamePointer;
        }

        const auto engine_state =
            *reinterpret_cast<std::int32_t*>(
                game_root + 0x38
            );

        if (engine_state != 1) {
            return ClickResult::GameNotRunning;
        }

        // 保留仓库原 CALL shellcode 在调用前执行的状态准备。
        *reinterpret_cast<std::uint8_t*>(
            game_root + 0x29
        ) = 0;

        using ClickFunction =
            void(__fastcall*)(void*, void*);

        const auto click_function =
            reinterpret_cast<ClickFunction>(
                module_base + kClickFunctionRva
            );

        click_function(
            reinterpret_cast<void*>(context_address),
            cell_pointer
        );

        return ClickResult::Success;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return ClickResult::InternalException;
    }
#endif
}

LRESULT CALLBACK HookWndProc(
    HWND hwnd,
    UINT message,
    WPARAM w_param,
    LPARAM l_param
) {
    const auto old_wndproc =
        reinterpret_cast<WNDPROC>(
            GetPropW(hwnd, kOldWndProcPropertyName)
        );

    if (message == g_click_message) {
        const auto sequence =
            static_cast<ULONG_PTR>(w_param);

        if (InterlockedCompareExchange(
                &g_busy,
                1,
                0) != 0) {
            PublishResult(
                hwnd,
                sequence,
                ClickResult::Busy
            );
            return 0;
        }

        const auto cell_pointer =
            reinterpret_cast<void*>(
                static_cast<std::uintptr_t>(l_param)
            );

        const auto result =
            ExecuteClick(cell_pointer);

        PublishResult(hwnd, sequence, result);
        InterlockedExchange(&g_busy, 0);
        return 0;
    }

    if (message == WM_NCDESTROY && old_wndproc != nullptr) {
        RemovePropW(hwnd, kReadyPropertyName);
        RemovePropW(hwnd, kLastSequencePropertyName);
        RemovePropW(hwnd, kLastResultPropertyName);

        SetWindowLongPtrW(
            hwnd,
            GWLP_WNDPROC,
            reinterpret_cast<LONG_PTR>(old_wndproc)
        );
        RemovePropW(hwnd, kOldWndProcPropertyName);

        return CallWindowProcW(
            old_wndproc,
            hwnd,
            message,
            w_param,
            l_param
        );
    }

    if (old_wndproc != nullptr) {
        return CallWindowProcW(
            old_wndproc,
            hwnd,
            message,
            w_param,
            l_param
        );
    }

    return DefWindowProcW(
        hwnd,
        message,
        w_param,
        l_param
    );
}

BOOL CALLBACK EnumWindowsCallback(
    HWND hwnd,
    LPARAM
) {
    DWORD process_id = 0;
    GetWindowThreadProcessId(
        hwnd,
        &process_id
    );

    if (process_id != GetCurrentProcessId()) {
        return TRUE;
    }

    if (!IsWindow(hwnd) ||
        !IsWindowVisible(hwnd) ||
        GetAncestor(hwnd, GA_ROOT) != hwnd) {
        return TRUE;
    }

    if (GetPropW(hwnd, kReadyPropertyName) != nullptr) {
        return TRUE;
    }

    const auto current =
        reinterpret_cast<WNDPROC>(
            GetWindowLongPtrW(
                hwnd,
                GWLP_WNDPROC
            )
        );

    if (current == nullptr ||
        current == HookWndProc) {
        return TRUE;
    }

    if (!SetPropW(
            hwnd,
            kOldWndProcPropertyName,
            reinterpret_cast<HANDLE>(current))) {
        return TRUE;
    }

    SetLastError(ERROR_SUCCESS);
    const LONG_PTR replaced =
        SetWindowLongPtrW(
            hwnd,
            GWLP_WNDPROC,
            reinterpret_cast<LONG_PTR>(
                HookWndProc
            )
        );
    const DWORD error = GetLastError();

    if (replaced == 0 &&
        error != ERROR_SUCCESS) {
        RemovePropW(
            hwnd,
            kOldWndProcPropertyName
        );
        return TRUE;
    }

    SetPropW(
        hwnd,
        kReadyPropertyName,
        reinterpret_cast<HANDLE>(1)
    );

    return TRUE;
}

DWORD WINAPI HookMonitorThread(LPVOID) {
    g_click_message =
        RegisterWindowMessageW(
            kClickMessageName
        );

    if (g_click_message == 0) {
        return GetLastError();
    }

    // 持续发现同进程中新建的顶层窗口。这样窗口重建后，
    // 不需要再次执行 Python 远程 CALL。
    while (true) {
        EnumWindows(
            EnumWindowsCallback,
            0
        );
        Sleep(500);
    }
}

} // namespace

BOOL WINAPI DllMain(
    HINSTANCE instance,
    DWORD reason,
    LPVOID
) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = instance;
        DisableThreadLibraryCalls(instance);

        HANDLE thread = CreateThread(
            nullptr,
            0,
            HookMonitorThread,
            nullptr,
            0,
            nullptr
        );

        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
