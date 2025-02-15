import React, { useRef, useState } from "react";
import { motion } from "framer-motion";
import classes from "./header.module.css"
import TabItem from "./TabItem";

const SlideTabs = ({menuItems}) => {
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
      className={`${`relative mx-auto flex w-fit rounded-full border-2 border-black p-1`} ${classes.innerSubMenu}`}
    >
      {menuItems.map((menu) => (
        <>
          <Tab setPosition={setPosition} key={menu.name}>
            <TabItem menu={menu} />
          </Tab>
        </>
      ))}

      <Cursor position={position} />
    </ul>
  );
};

export default SlideTabs

const Tab = ({ children, setPosition }) => {
    const ref = useRef(null);
  
    return (
      <div
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
      </div>
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