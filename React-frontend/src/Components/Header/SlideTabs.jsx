import React, { useRef, useState } from "react";
import { motion } from "framer-motion";
import classes from "./header.module.css"
import TabItem from "./TabItem";

const SlideTabs = ({menuItems, newMenu}) => {
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
      className={classes.TabContainer}
    >
      {newMenu.map((menu, index) => (
        <>
          <Tab setPosition={setPosition} key={index}>
            <TabItem menu={menu}/>
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
        className={classes.tabItem}
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
        className={classes.tabSelector}
      />
    );
  };