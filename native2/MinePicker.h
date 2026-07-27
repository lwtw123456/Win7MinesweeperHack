#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#ifdef MINEPICKER_BUILD
#define MINEPICKER_API __declspec(dllexport)
#else
#define MINEPICKER_API __declspec(dllimport)
#endif

// Blocking call.
// rows: number of grid rows, valid range [9, 24].
// columns: number of grid columns, valid range [9, 30].
// mineCount: exact number of mines to select. It must be >= 0 and must not
//            exceed 93% of rows * columns.
// outIndices: writable array containing at least mineCount int elements.
//             It may be nullptr only when mineCount == 0.
//
// The picker window is created at a fixed size that shows the full board.
// It has no horizontal/vertical scroll bars and cannot be resized.
//
// Returns TRUE only after the user presses Confirm. In that case, outIndices
// receives the selected cell indices in ascending row-major order.
// Returns FALSE on Cancel, window close, or invalid arguments. In those cases,
// outIndices is not modified.
extern "C" MINEPICKER_API BOOL WINAPI SelectMinePositions(
    int rows,
    int columns,
    int mineCount,
    int* outIndices);
