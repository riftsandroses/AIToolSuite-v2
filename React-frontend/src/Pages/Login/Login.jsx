import React, { useState } from 'react'
import "./login.css"

const Login = () => {
    const [isSignup, setIsSignup] = useState(false)
    return (
        <div className="outer-container">
            <div className={`container ${isSignup ? "active" : ""} `} id="container">
                <div className="form-container sign-up">
                    <form>
                        <h1 className='text-4xl font-bold mb-7'>Create Account</h1>
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
                            <input type="text" placeholder="Name" />
                            <input type="email" placeholder="Email" />
                            <input type="password" placeholder="Password" />
                        </div>
                        <button className='primaryBtn button'>Sign Up</button>
                    </form>
                </div>
                <div className="form-container sign-in">
                    <form>
                        <h1 className='text-4xl font-bold mb-8'>Sign In</h1>
                        <div className='mt-4'>
                            <input type="email" placeholder="Email" />
                            <input type="password" placeholder="Password" />
                        </div>

                        <a href="#" className='my-4 text-[#333] text-xs' >Forget Your Password?</a>
                        <button className='primaryBtn button'>Sign In</button>
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
                <div className="toggle-container">
                    <div className="toggle">
                        <div className="toggle-panel toggle-left">
                            <h1>Welcome Back!</h1>
                            <p className='toggleInfo'>Enter your personal details to use all of site features</p>
                            <button className="secondaryBtn button" onClick={() => setIsSignup(false)}>
                                Sign In
                            </button>
                        </div>
                        <div className="toggle-panel toggle-right">
                            <h1>Hello, Friend!</h1>
                            <p className='toggleInfo'>Register with your personal details to use all of site features</p>
                            <button className="secondaryBtn button" onClick={() => setIsSignup(true)}>
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