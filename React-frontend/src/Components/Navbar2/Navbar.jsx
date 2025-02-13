
import Logo from "./logo.webp";
import "./style.css"
import { SlideTabsExample } from "../Navbar1/Navbar"


const Navbar = () => {
    return (
        <div>
            {/* bg-[#18181A] */}
            <header className="h-[4.5rem] text-[15px] fixed inset-0 flex items-center   bg-[#172130] ">
                <nav className=" px-3.5 flex justify-between items-center w-full max-w-7xl mx-auto">
                    <div className="flex items-center gap-x-3 z-[999] relative">
                        <img src={Logo} alt="" className="size-8" />
                        <h3 className="text-lg font-semibold text-white">Framer</h3>
                    </div>

                    <ul className="gap-x-1 flex items-center">
                        <SlideTabsExample/>
                        {/* {Menus.map((menu) => ( */}
                            {/* <DesktopMenu  /> */}
                        {/* ))} */}
                    </ul>


                    <div className="flex items-center gap-x-5">
                        <button
                            aria-label="sign-in"
                            className="bg-white z-[999] relative px-6 py-2  shadow rounded-xl flex items-center"
                        >
                            Sign In
                        </button>
                    </div>
                </nav>
            </header>
        </div>
    )
}

export default Navbar