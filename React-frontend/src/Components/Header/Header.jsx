import React from 'react'
import { menu } from "./navOptions";
import logo from "../../Assets/logo.webp"
import SlideTabs from './SlideTabs';
import classes from "./header.module.css"

const Header = () => {
    return (
        <div>
            {/* bg-[#18181A] */}
            <header className={classes.headerContainer}>
                <nav className={classes.navContainer}>
                    <div className={classes.logoContainer}>
                        <img src={logo} alt="KPMG" className="size-8" />
                        <h3 className="text-lg font-semibold text-white">KPMG</h3>
                    </div>

                    <div className={classes.slideTabContainer}>
                        <SlideTabs menuItems={menu} />
                    </div>


                    <div className={classes.actionBtnContainer}>
                        <button
                            aria-label="sign-in"
                            className={classes.signinBtn}
                        >
                            Sign In
                        </button>
                    </div>
                </nav>
            </header>
        </div>
    )
}

export default Header