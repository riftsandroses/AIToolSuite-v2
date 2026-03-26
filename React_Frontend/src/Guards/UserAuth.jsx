import { useEffect } from "react";
import { useSelector } from "react-redux";
import { Navigate } from "react-router";
import { getAuthCookies, startTokenRefreshInterval, stopTokenRefresh } from "../api/auth";

const UserAuth = ({ children }) => {
    const userData = useSelector((state) => state.loggedInUser.loggedInUser);
    const { username, email, accessToken } = userData;

    useEffect(() => {
        const { accessToken: tokenFromCookie } = getAuthCookies();
        if (!tokenFromCookie) return;

        // Schedule once on mount using the cookie token directly.
        // auth.js handles rescheduling internally after each refresh —
        // we must NOT re-run this effect on token changes or it will
        // spawn duplicate timers and spam the refresh endpoint.
        startTokenRefreshInterval(tokenFromCookie);

        return () => stopTokenRefresh();
    }, []); // empty dep array — run once on mount only

    if (!username || !email || !accessToken) {
        return <Navigate to="/login" />;
    }

    return children;
};

export default UserAuth;