import { useSelector } from "react-redux";
// import { Navigate } from 'react-router-dom';
import { Navigate } from "react-router";

export const UserAuth = ({ children }) => {
    const userData = useSelector((state) => state.loggedInUser.loggedInUser)
    const { username, email, accessToken } = userData

    console.log(userData)

    if (
        !username ||
        !email ||
        !accessToken
    ) {
        return <Navigate to="/login" />
    }

    return children;
}