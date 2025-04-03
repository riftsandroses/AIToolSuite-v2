import React, { useState, useEffect } from 'react'
import { menu } from "./navOptions";
import logo from "../../Assets/logo.webp"
import SlideTabs from './SlideTabs';
import classes from "./header.module.css"
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import { useSelector } from "react-redux"


const Header = () => {
    const [headerBgChange, setHeaderBgChange] = useState(false)

    const accessToken = useSelector((state) => state.loggedInUser.loggedInUser.accessToken)


    useEffect(() => {
        const handleScroll = () => {
            if (window.scrollY > 40) {
                setHeaderBgChange(true);
            } else {
                setHeaderBgChange(false)
            }
        };
        window.addEventListener("scroll", handleScroll);

        return () => {
            window.removeEventListener("scroll", handleScroll)
        }
    }, [])


    return (
        <div>
            {/* bg-[#18181A] */}
            <header className={`${classes.headerContainer} ${headerBgChange && classes.headerContainerBg}`}>
                <nav className={classes.navContainer}>
                    <div className={classes.logoContainer}>
                        <img src={logo} alt="KPMG" className="size-8" />
                        <h3 className="text-lg font-semibold text-white">STELLAR</h3>
                    </div>

                    <div className={classes.slideTabContainer}>
                        <SlideTabs menuItems={menu} />
                    </div>


                    <div className={classes.actionBtnContainer}>

                        {accessToken ?
                            <AccountCircleIcon
                                className={classes.signedIn} />
                            :
                            <button
                                aria-label="sign-in"
                                className={classes.signinBtn}
                            >
                                Sign In
                            </button>
                        }
                    </div>
                </nav>
            </header>
        </div>
    )
}

export default Header