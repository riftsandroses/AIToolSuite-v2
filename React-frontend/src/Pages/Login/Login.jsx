import React, { useState } from 'react'
import classes from "./login.module.css"

const Login = () => {
    const [isSignup, setIsSignup] = useState(false)
    return (
        <div className={classes.outerContainer}>
            <div className={`${classes.container} ${isSignup ? classes.active : ""} `}>
                <div className={`${classes.formContainer} ${classes.signUp}`}>
                    <form className={classes.form}>
                        <h1 className={`${classes.containerHeading} mb-7`}>Create Account</h1>
                        {/* <div className="social-icons">
                            <a href="#" className="icon">
                                <i className="fa-brands fa-google-plus-g" />
                            </a>
                            <a href="#" className="icon">
                                <i className="fa-brands fa-facebook-f" />
                            </a>
                            <a href="#" className="icon">
                                <i className="fa-brands fa-github" />
                            </a>
                            <a href="#" className="icon">
                                <i className="fa-brands fa-linkedin-in" />
                            </a>
                        </div> */}
                        {/* <span>or use your email for registeration</span> */}
                        <div className="mt-4">
                            <input type="text" placeholder="Name" className={classes.inputField}/>
                            <input type="email" placeholder="Email" className={classes.inputField}/>
                            <input type="password" placeholder="Password" className={classes.inputField}/>
                        </div>
                        <button className={`${classes.primaryBtn} ${classes.button}`}>Sign Up</button>
                    </form>
                </div>
                <div className={`${classes.formContainer} ${classes.signIn}`}>
                    <form className={classes.form}>
                        <h1 className={`${classes.containerHeading} mb-8`}>Sign In</h1>
                        <div className='mt-4'>
                            <input type="email" placeholder="Email"  className={classes.inputField}/>
                            <input type="password" placeholder="Password"  className={classes.inputField}/>
                        </div>

                        <a href="#" className={classes.subText} >Forget Your Password?</a>
                        <button className={`${classes.primaryBtn} ${classes.button}`}>Sign In</button>
                        {/* <hr/>
                        <div className="social-icons">
                            <a href="#" className="icon">
                                <i className="fa-brands fa-google-plus-g" />
                            </a>
                            <a href="#" className="icon">
                                <i className="fa-brands fa-facebook-f" />
                            </a>
                            <a href="#" className="icon">
                                <i className="fa-brands fa-github" />
                            </a>
                            <a href="#" className="icon">
                                <i className="fa-brands fa-linkedin-in" />
                            </a>
                        </div>  */}
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