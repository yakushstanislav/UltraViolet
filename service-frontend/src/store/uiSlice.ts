import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

type UiState = {
  /**
   * Count of in-flight blocking operations (session restore, login, logout,
   * etc.) that should show the top progress bar. Per-route data fetches
   * use local skeletons instead.
   */
  blockingTaskCount: number;
};

const initialState: UiState = {
  blockingTaskCount: 0,
};

export const uiSlice = createSlice({
  name: 'ui',
  initialState,
  reducers: {
    startBlocking(state) {
      state.blockingTaskCount += 1;
    },
    finishBlocking(state) {
      if (state.blockingTaskCount <= 0) {
        console.warn(
          'uiSlice: finishBlocking called with no in-flight blocking task'
        );
        state.blockingTaskCount = 0;

        return;
      }

      state.blockingTaskCount -= 1;
    },
    setBlocking(state, action: PayloadAction<boolean>) {
      state.blockingTaskCount = action.payload ? 1 : 0;
    },
  },
});

export const { startBlocking, finishBlocking, setBlocking } = uiSlice.actions;
