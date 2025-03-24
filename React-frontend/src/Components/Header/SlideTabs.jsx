import React, { useRef, useState } from "react";
import { motion } from "framer-motion";
import classes from "./header.module.css"
import TabItem from "./TabItem";

const SlideTabs = ({ menuItems }) => {
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
      {menuItems.map((menu, index) => (
        <>
          <Tab setPosition={setPosition} index={index}>
            <TabItem menu={menu} index={index}/>
          </Tab>
        </>
      ))}

      <Cursor position={position} />
    </ul>
  );
};

export default SlideTabs

const Tab = ({ children, setPosition, index }) => {
  const ref = useRef(null);

  return (
    <div
      key={index}
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