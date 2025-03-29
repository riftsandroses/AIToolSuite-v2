import React, { useState } from 'react'
import classes from "./login.module.css"
import { useDispatch } from 'react-redux'
import { setAuthCookies, signInUser } from '../../api/auth'
import { loggedInUserSlice } from '../../Store/Slices'
import { useNavigate } from 'react-router'
import Input from "../../Components/Input/Input";
import Snackbar from '../../Components/Snackbar/Snackbar';



const Login = () => {
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const [isSignup, setIsSignup] = useState(false)
    const [userCreds, setUserCreds] = useState({
        email: "",
        password: "",
    })
    const [errorMsg, setErrorMsg] = useState("")

    const [openSnackbar, setOpenSnackbar] = useState(false)
    const [snackbarDetails, setSnackbarDetails] = useState({
        type: "",
        message: ""
    })

    const handleSubmit = async () => {
        // setError
        console.log("Outside")
        // console.log(userCreds)

        if (userCreds.email !== "" && userCreds.password !== "") {
            console.log(userCreds)

            try {
                const userLoginData = await signInUser({
                    email: userCreds.email,
                    password: userCreds.password,
                })

                setAuthCookies({
                    name: userLoginData.name || "",
                    username: userLoginData.username || "",
                    email: userLoginData.email || "",
                    refreshToken: userLoginData.refresh,
                    accessToken: userLoginData.access,
                    expiry: 0,
                });

                dispatch(
                    loggedInUserSlice.actions.setLogedInUserData({
                        name: userLoginData.name || "",
                        username: userLoginData.username || "",
                        email: userLoginData.email || "",
                        refreshToken: userLoginData.refresh,
                        accessToken: userLoginData.access,
                    })
                )

                navigate("/")
            } catch (error) {
                setErrorMsg(error.response.data.error)
                console.log(error.response.data.error)
            }
        } else {
            setSnackbarDetails({
                type: "error",
                message: "Enter Email & Password"
            })
            setOpenSnackbar(true)
        }
    }

    const handleChange = (keyName, keyValue) => {
        setUserCreds({
            ...userCreds,
            [keyName]: keyValue
        })
    }

    return (
        <div className={classes.outerContainer}>
            <Snackbar openSnackbar={openSnackbar} setOpenSnackbar={setOpenSnackbar} type={snackbarDetails.type} message={snackbarDetails.message} />
            <div className={`${classes.container} ${isSignup ? classes.active : ""} `}>
                <div className={`${classes.formContainer} ${classes.signUp}`}>
                    <form className={classes.form}>
                        <h1 className={`${classes.containerHeading} mb-7`}>Create Account</h1>
                        <div className="flex flex-col justify-center items-center w-full mt-4">
                            <div className='flex flex-col w-full mb-1'>
                                <Input
                                    label={"email"}
                                    placeholder={"Name"}
                                    value={userCreds.email}
                                    // handleChange={handleChange}
                                    handleChange={() => { }}
                                />

                            </div>
                            <div className='flex flex-col w-full my-1'>
                                <Input
                                    label={"email"}
                                    placeholder={"Email"}
                                    value={""}
                                    handleChange={() => { }}
                                />
                                <div className='flex flex-col w-full mt-2'>
                                    <Input
                                        type='password'
                                        label={"password"}
                                        placeholder={"Password"}
                                        value={""}
                                        handleChange={() => { }}
                                    />

                                </div>
                            </div>
                            {/* <input type="text" placeholder="Name" className={classes.inputField} />
                            <input type="email" placeholder="Email" className={classes.inputField} />
                            <input type="password" placeholder="Password" className={classes.inputField} /> */}
                        </div>
                        <button className={`${classes.primaryBtn} ${classes.button}`}>Sign Up</button>
                    </form>
                </div>
                <div className={`${classes.formContainer} ${classes.signIn}`}>
                    <form className={classes.form}>
                        <h1 className={`${classes.containerHeading} mb-8`}>Sign In</h1>
                        <div className='flex flex-col justify-center items-center w-full mt-4'>
                            {errorMsg && <p className='text-red-600 text-sm mb-2'>{errorMsg}</p>}
                            <div className='flex flex-col w-full mb-1'>
                                <Input
                                    label={"email"}
                                    placeholder={"Email"}
                                    value={userCreds.email}
                                    handleChange={handleChange}
                                />

                            </div>
                            <div className='flex flex-col w-full mt-1'>
                                <Input
                                    type='password'
                                    label={"password"}
                                    placeholder={"Password"}
                                    value={userCreds.password}
                                    handleChange={handleChange}
                                />
                            </div>
                        </div>

                        {/* <a href="#" className={classes.subText} >Forget Your Password?</a> */}
                        <div
                            className={`${classes.primaryBtn} ${classes.button}`}
                            onClick={handleSubmit}>
                            Sign In
                        </div>

                    </form>
                </div>
                <div className={classes.toggleContainer}>
                    <div className={classes.toggle}>
                        <div className={`${classes.togglePanel} ${classes.toggleLeft}`}>
                            <h1 className='text-3xl font-bold'>Welcome Back!</h1>
                            <p className={classes.toggleInfo}>Enter your personal details to use all of site features</p>
                            <button className={`${classes.secondaryBtn} ${classes.button}`} onClick={() => setIsSignup(false)}>
                                Sign In
                            </button>
                        </div>
                        <div className={`${classes.togglePanel} ${classes.toggleRight}`}>
                            <h1 className='text-3xl font-bold'>Hello, Friend!</h1>
                            <p className={classes.toggleInfo}>Register with your details to use all of site features</p>
                            <button className={`${classes.secondaryBtn} ${classes.button}`} onClick={() => setIsSignup(true)}>
                                Sign Up
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

    )
}

export default Login