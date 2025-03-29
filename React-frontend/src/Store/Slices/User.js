import { createSlice } from "@reduxjs/toolkit";
import { getAuthCookies } from '../../api/auth';


const userDetailsCookie = getAuthCookies()



const initialState = {
  loggedInUser: {
    // isLoggedIn: false,
    name: userDetailsCookie.name || "",
    username: userDetailsCookie.username || "",
    email: userDetailsCookie.email || "",
    role: userDetailsCookie.role || "",
    refreshToken: userDetailsCookie.refreshToken || "",
    accessToken: userDetailsCookie.accessToken || "",
  },
};

export const loggedInUserSlice = createSlice({
  name: "loggedInUser",
  initialState,
  reducers: {
    setLogedInUserData: (state, action) => {
    //   console.log(action.payload);
      state.loggedInUser = action.payload;
    },
  },
  reset: (state) => {
    state = {
      name: "",
      username: "",
      email: "",
    //   role: "",
      refreshToken: "",
      accessToken: "",
    };
  },
});
