import { configureStore } from "@reduxjs/toolkit";
import * as Slice from "./Slices/index"

export const store = configureStore({
    reducer:{
        loggedInUser: Slice.loggedInUserSlice.reducer
    }
})