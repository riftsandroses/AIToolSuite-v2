import axios from "axios";
import * as Cookie from "../utils/cookie";

export const getAuthCookies = () => {
  const name = Cookie.get("name");
  const username = Cookie.get("username");
  const email = Cookie.get("email");
//   const role = Cookie.get("role");
  const accessToken = Cookie.get("accessToken");
  const refreshToken = Cookie.get("refreshToken");

  return {
    name,
    username,
    email,
    // role,
    refreshToken,
    accessToken,
  };
};
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

export const signInUser = async ({ email, password }) => {
//   try {
    const res = await axios.post(
      `${API_BASE_URL}/api/v1/login/`,
      {
        email: email,
        password: password,
      },
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );
    // console.log(res.data)
    return res.data;

//   } catch (error) {
//     console.error(error.response.data.error)
//     return Error(error.response.data.error)
//     // throw new Error(error.error)
//     // console.log(error.response.data);
//   }
};

export const setAuthCookies = ({
  name,
  username,
  email,
//   role,
  refreshToken,
  accessToken,
  expiry,
}) => {
  if (name) {
    Cookie.set("name", `${name}`, expiry);
  }

  if (username) {
    Cookie.set("username", `${username}`, expiry);
  }

  if (email) {
    Cookie.set("email", `${email}`, expiry);
  }

//   if (role) {
//     Cookie.set("role", `${role}`, expiry);
//   }

  if (refreshToken) {
    Cookie.set("refreshToken", `${refreshToken}`, expiry);
  }

  if (accessToken) {
    Cookie.set("accessToken", `${accessToken}`, expiry);
  }
};

export const deleteAuthCookies = () => {
  Cookie.erase("name");
  Cookie.erase("username");
  Cookie.erase("email");
//   Cookie.erase("role");
  Cookie.erase("refreshToken");
  Cookie.erase("accessToken");
};
