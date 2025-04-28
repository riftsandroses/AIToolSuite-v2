// import { useSelector } from "react-redux";
// import { Navigate } from 'react-router-dom';

// export const UserAuth = ({ children }) => {
//     const userData = useSelector((state) => state.loggedInUser.loggedInUser)
//     const { username, email, accessToken } = userData

//     if (
//         !username ||
//         !email ||
//         !accessToken
//     ) {
//         return <Navigate to="/" />
//     }

//     return children;
// }