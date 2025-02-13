
import React, { useRef, useState } from "react";
import { motion } from "framer-motion";
import NewNav from "../Navbar2/DesktopMenu"
import "../Navbar2/style.css"
import { Menus } from "../Navbar2/utils";

export const SlideTabsExample = () => {
  return (
    // <div className="bg-neutral-100 py-20 mt-[20rem]">
    <>
      <SlideTabs />
    </>
    // </div>
  );
};

const SlideTabs = () => {
  const [position, setPosition] = useState({
    left: 0,
    width: 0,
    opacity: 0,
  });

  return (
    <ul
      onMouseLeave={() => {
        setPosition((pv) => ({
          ...pv,
          opacity: 0,
        }));
      }}
      className={`${`relative mx-auto flex w-fit rounded-full border-2 border-black p-1`} ${"innerSubMenu"}`}
    >
      {Menus.map((menu) => (
        <>
          <Tab setPosition={setPosition}>
            <NewNav menu={menu} key={menu.name}/>
          </Tab>
        </>
      ))}

      {/* <Tab setPosition={setPosition}>
        <NewNav />
      </Tab>
      <Tab setPosition={setPosition}>
        <NewNav />
      </Tab>
      <Tab setPosition={setPosition}>
        <NewNav />
      </Tab>
      <Tab setPosition={setPosition}>
        <NewNav />
      </Tab>
      <Tab setPosition={setPosition}>Blog</Tab> */}

      <Cursor position={position} />
    </ul>
  );
};

const Tab = ({ children, setPosition }) => {
  const ref = useRef(null);

  return (
    <li
      ref={ref}
      onMouseEnter={() => {
        if (!ref?.current) return;

        const { width } = ref.current.getBoundingClientRect();

        setPosition({
          left: ref.current.offsetLeft,
          width,
          opacity: 1,
        });
      }}
      className="relative z-10 block cursor-pointer px-3 py-1.5 text-xs uppercase text-white mix-blend-difference  md:text-base"
    >
      {children}
    </li>
  );
};

const Cursor = ({ position }) => {
  return (
    <motion.li
      animate={{
        ...position,
      }}
      className="absolute z-0 rounded-full bg-[#16202e] h-9 "
    />
  );
};