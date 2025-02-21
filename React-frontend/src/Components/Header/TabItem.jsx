import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { motion } from "framer-motion";
import classes from "./header.module.css"


const TabItem = ({ menu }) => {
    const [isHover, toggleHover] = useState(false);
    const toggleHoverMenu = () => {
        toggleHover(!isHover);
    };

    const subMenuAnimate = {
        enter: {
            opacity: 1,
            rotateX: 0,
            transition: {
                duration: 0.5,
            },
            display: "block",
        },
        exit: {
            opacity: 0,
            rotateX: -15,
            transition: {
                duration: 0.5,
            },
            transitionEnd: {
                display: "none",
            },
        },
    };

    const hasSubMenu = menu?.subMenu?.length;


    return (
        <motion.li
            className="group/link"
            onHoverStart={() => {
                toggleHoverMenu();
            }}
            onHoverEnd={toggleHoverMenu}
            key={menu.name}
        >
            <span className={classes.tabName}>
                {menu.tabName}
                {hasSubMenu && (
                    <ChevronDown className="mt-[0.6px] group-hover/link:rotate-180 duration-200" />
                )}
            </span>
            {hasSubMenu && (
                <motion.div
                    className={classes.subMenuContainer}
                    initial="exit"
                    animate={isHover ? "enter" : "exit"}
                    variants={subMenuAnimate}
                >
                    <div className="flex flex-row">
                        {menu.subMenu.map((subMenu, i) => {
                            return (
                                <>
                                    <div className="flex flex-col w-[14rem] " key={i}>
                                        <p className={classes.subMenuHeading}>
                                            {subMenu.heading}
                                        </p>
                                        {subMenu.options.map((subMenuItem, index) => {
                                            return (
                                                <div className={`${classes.subMenuItem} group/menubox`} key={index}>
                                                    <div className="bg-white/5 w-fit p-2 mr-2 rounded-md group-hover/menubox:bg-white group-hover/menubox:text-gray-900 duration-300">
                                                        {subMenuItem.icon && <subMenuItem.icon />}
                                                    </div>
                                                    <div>
                                                        <h6 className="font-semibold">{subMenuItem.name}</h6>
                                                        <p className="text-sm text-gray-400">{subMenuItem.desc}</p>
                                                    </div>
                                                </div>
                                            )
                                        })}
                                    </div>
                                </>
                            )
                        })}
                    </div>
                </motion.div>
            )}
        </motion.li>
    );
}

export default TabItem
